package spa

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang-spa-auth/server/gmsm/sm2"
	"golang-spa-auth/server/gmsm/sm3"
	"golang-spa-auth/server/gmsm/sm4" // 使用服务端的SM4实现
)

// KnockRequest 表示UDP敲门请求
type KnockRequest struct {
	Nonce     string `json:"nonce"`      // 随机字符串
	ClientKey string `json:"client_key"` // 客户端密钥
	ClientIP  string `json:"client_ip"`  // 客户端IP
	Timestamp int64  `json:"timestamp"`  // 请求时间戳
}

// KnockResponse 表示敲门响应
type KnockResponse struct {
	Port      int   `json:"port"`       // 分配的TCP端口
	ExpiresIn int64 `json:"expires_in"` // 有效期（秒）
	Timestamp int64 `json:"timestamp"`  // 响应时间戳
}

// TokenResponse 表示JWT令牌响应
type TokenResponse struct {
	Token     string `json:"token"`      // JWT令牌
	ExpiresAt int64  `json:"expires_at"` // 过期时间戳
}

// SM4静态密钥，与服务端保持一致
var (
	SM4Key = []byte("1234567890abcdef") // 16字节SM4密钥
	SM4IV  = []byte("0000000000000000") // 16字节IV向量
)

// 初始化SM4加密环境
func init() {
	// 设置SM4的IV
	err := sm4.SetIV(SM4IV)
	if err != nil {
		fmt.Printf("SM4初始化错误: %v\n", err)
	}
}

// EncryptedSPARequest 表示加密后的敲门请求
type EncryptedSPARequest struct {
	EncryptedData string `json:"encrypted_data"` // Base64编码的加密数据
	PublicKeyPEM  string `json:"public_key_pem"` // PEM格式的SM2公钥
	Signature     []byte `json:"signature"`      // SM2签名
}

// EncryptedSPAResponse 表示加密后的敲门响应
type EncryptedSPAResponse struct {
	EncryptedData string `json:"encrypted_data"` // Base64编码的加密数据
}

// 添加生成随机字符串的辅助函数
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		// 这里使用时间作为随机源，在生产环境中应该使用更安全的随机源
		source := mrand.NewSource(time.Now().UnixNano() + int64(i))
		r := mrand.New(source)
		result[i] = charset[r.Intn(len(charset))]
	}
	return string(result)
}

// 更新SendKnockRequest函数，实现真正的UDP敲门并使用SM4加密
// 添加从文件加载SM2私钥进行签名的功能
func SendKnockRequest(serverIP string, udpPort int, clientKey string, privateKeyPath string) (*KnockResponse, error) {
	// 创建UDP连接
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, udpPort))
	if err != nil {
		return nil, fmt.Errorf("解析UDP地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("UDP连接失败: %v", err)
	}
	defer conn.Close()

	// 获取客户端真实IP
	clientIP := getOutboundIP().String()

	// 创建时间戳
	timestamp := time.Now().Unix()

	// 生成随机Nonce（防重放攻击）
	nonce := generateRandomString(16)

	// 构建敲门请求
	req := KnockRequest{
		Nonce:     nonce,
		ClientKey: clientKey,
		ClientIP:  clientIP,
		Timestamp: timestamp,
	}

	// 使用SM4加密请求数据
	encryptedData, err := encryptSPARequest(req)
	if err != nil {
		return nil, fmt.Errorf("加密请求失败: %v", err)
	}

	// 使用SM3进行摘要计算
	h := sm3.New()
	h.Write([]byte(encryptedData))
	sum := h.Sum(nil)
	fmt.Printf("SM3摘要: %x\n", sum)

	// 根据是否提供私钥文件路径决定使用方式
	var priv *sm2.PrivateKey
	var pub *sm2.PublicKey

	if privateKeyPath == "" {
		// 如果未提供私钥文件，则生成临时密钥对
		fmt.Println("未提供私钥文件，使用临时生成的SM2密钥对...")
		priv, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成SM2密钥对失败: %v", err)
		}
		pub = &priv.PublicKey
	} else {
		// 从文件加载私钥
		fmt.Printf("正在从文件加载SM2私钥: %s\n", privateKeyPath)
		priv, err = LoadPrivateKeyFromPEM(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("加载SM2私钥失败: %v", err)
		}
		pub = &priv.PublicKey
	}

	// 将消息和摘要组合起来
	msg := append([]byte(encryptedData), sum...)

	// 使用私钥签名
	signature, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("SM2签名失败: %v", err)
	}
	fmt.Printf("SM2签名完成，长度: %d 字节\n", len(signature))

	// 将公钥转换为PEM格式
	pubKeyPEM, err := PublicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("转换公钥为PEM格式失败: %v", err)
	}

	// 构建加密请求对象
	encReq := EncryptedSPARequest{
		EncryptedData: encryptedData,
		PublicKeyPEM:  pubKeyPEM,
		Signature:     signature,
	}

	// 序列化加密请求
	reqData, err := json.Marshal(encReq)
	if err != nil {
		return nil, fmt.Errorf("序列化加密请求失败: %v", err)
	}

	fmt.Printf("发送加密UDP敲门数据包，长度: %d 字节\n", len(reqData))

	// 发送UDP数据包
	_, err = conn.Write(reqData)
	if err != nil {
		return nil, fmt.Errorf("发送UDP敲门数据包失败: %v", err)
	}

	// 设置接收超时时间
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 接收响应
	buffer := make([]byte, 2048) // 增大缓冲区以容纳加密响应
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("接收UDP响应失败: %v", err)
	}

	// 解析响应
	responseData := buffer[:n]

	// 检查是否为错误响应
	var errorResp map[string]interface{}
	if err := json.Unmarshal(responseData, &errorResp); err == nil {
		if errorMsg, ok := errorResp["error"]; ok {
			return nil, fmt.Errorf("服务器返回错误: %v", errorMsg)
		}
	}

	// 尝试解析为加密响应
	var encResp EncryptedSPAResponse
	if err := json.Unmarshal(responseData, &encResp); err != nil {
		// 如果不是加密响应，尝试解析为普通响应（兼容旧版本）
		var response KnockResponse
		if err := json.Unmarshal(responseData, &response); err != nil {
			return nil, fmt.Errorf("解析响应失败: %v, 响应数据: %s", err, string(responseData))
		}
		return &response, nil
	}

	// 解密响应
	resp, err := decryptSPAResponse(encResp.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("解密响应失败: %v", err)
	}

	fmt.Printf("成功解密响应，分配的端口: %d\n", resp.Port)
	return resp, nil
}

// 连接到TCP端口获取令牌
func ConnectToTcpPort(serverIP string, portStr string, clientKey string) (*TokenResponse, error) {
	// port, err := strconv.Atoi(portStr)
	// if err != nil {
	// 	return nil, fmt.Errorf("无效的端口号: %v", err)
	// }

	// 不要连接到分配的端口，而是连接到服务端的主HTTP端口, 用于测试
	url := fmt.Sprintf("http://%s:8080/api/auth/connect?port=%s", serverIP, portStr)
	// url := fmt.Sprintf("http://%s:%d/api/auth/connect", serverIP, port)

	// 构建请求体
	reqBody := fmt.Sprintf(`{"client_key": "%s"}`, clientKey)

	// 创建HTTP请求
	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// 执行HTTP请求
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 执行请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("服务器返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var response TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &response, nil
}

// loggingRoundTripper 用于记录HTTP传输细节
type loggingRoundTripper struct {
	rt http.RoundTripper
}

func (l *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("HTTP请求: %s %s", req.Method, req.URL.String())
	log.Printf("请求头: %v", req.Header)

	resp, err := l.rt.RoundTrip(req)
	if err != nil {
		log.Printf("传输层错误: %v", err)
		return nil, err
	}

	log.Printf("HTTP响应: %d %s", resp.StatusCode, resp.Status)
	log.Printf("响应头: %v", resp.Header)

	return resp, nil
}

// 获取出站IP地址
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// 加密SPA请求
func encryptSPARequest(req KnockRequest) (string, error) {
	// 序列化请求为JSON
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %v", err)
	}

	// 使用SM4 ECB模式加密
	encrypted, err := sm4.Sm4Ecb(SM4Key, data, true)
	if err != nil {
		return "", fmt.Errorf("SM4加密失败: %v", err)
	}

	// Base64编码加密后的数据
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// 解密SPA响应
func decryptSPAResponse(encryptedBase64 string) (*KnockResponse, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	// 使用SM4 ECB模式解密
	decrypted, err := sm4.Sm4Ecb(SM4Key, encrypted, false)
	if err != nil {
		return nil, fmt.Errorf("SM4解密失败: %v", err)
	}

	// 去除填充
	decrypted = bytes.TrimRight(decrypted, string([]byte{0}))

	// 解析JSON
	var resp KnockResponse
	err = json.Unmarshal(decrypted, &resp)
	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &resp, nil
}

// LoadPrivateKeyFromPEM 从PEM文件加载SM2私钥
func LoadPrivateKeyFromPEM(filePath string) (*sm2.PrivateKey, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %v", err)
	}

	// 解析PEM块
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "SM2 PRIVATE KEY" {
		return nil, fmt.Errorf("无效的SM2私钥PEM文件")
	}

	// 解析私钥
	return ParseSM2PrivateKey(block.Bytes)
}

// PublicKeyToPEM 将SM2公钥转换为PEM格式字符串
func PublicKeyToPEM(pub *sm2.PublicKey) (string, error) {
	// 将公钥序列化
	pubKeyBytes, err := MarshalSM2PublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("序列化公钥失败: %v", err)
	}

	// 创建PEM块
	block := &pem.Block{
		Type:  "SM2 PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// 编码为PEM格式
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("PEM编码失败: %v", err)
	}

	return buf.String(), nil
}

// MarshalSM2PublicKey 将SM2公钥序列化为ASN.1 DER编码
func MarshalSM2PublicKey(key *sm2.PublicKey) ([]byte, error) {
	type sm2PublicKey struct {
		X, Y *big.Int
	}

	pubKey := sm2PublicKey{
		X: key.X,
		Y: key.Y,
	}

	return asn1.Marshal(pubKey)
}

// ParseSM2PrivateKey 从ASN.1 DER编码解析SM2私钥
func ParseSM2PrivateKey(derBytes []byte) (*sm2.PrivateKey, error) {
	type sm2PrivateKey struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier
		PublicKey     asn1.BitString
	}

	var privKey sm2PrivateKey
	_, err := asn1.Unmarshal(derBytes, &privKey)
	if err != nil {
		return nil, fmt.Errorf("ASN.1解析失败: %v", err)
	}

	// 创建SM2私钥
	curve := sm2.P256Sm2()
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(privKey.PrivateKey)

	// 从存储的公钥解析X和Y坐标
	pub, err := ParseSM2PublicKey(privKey.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %v", err)
	}
	priv.PublicKey.X = pub.X
	priv.PublicKey.Y = pub.Y

	return priv, nil
}

// ParseSM2PublicKey 从ASN.1 DER编码解析SM2公钥
func ParseSM2PublicKey(derBytes []byte) (*sm2.PublicKey, error) {
	type sm2PublicKey struct {
		X, Y *big.Int
	}

	var pubKey sm2PublicKey
	_, err := asn1.Unmarshal(derBytes, &pubKey)
	if err != nil {
		return nil, fmt.Errorf("ASN.1解析失败: %v", err)
	}

	// 创建SM2公钥
	curve := sm2.P256Sm2()
	pub := new(sm2.PublicKey)
	pub.Curve = curve
	pub.X = pubKey.X
	pub.Y = pubKey.Y

	return pub, nil
}
