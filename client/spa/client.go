package spa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// KnockRequest 表示UDP敲门请求
type KnockRequest struct {
	Nonce     string `json:"nonce"`      // 随机字符串
	ClientKey string `json:"client_key"` // 客户端密钥
	ClientIP  string `json:"client_ip"`  // 客户端IP
	Timestamp int64  `json:"timestamp"`  // 请求时间戳
	Signature string `json:"signature"`  // 请求签名
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

// 添加生成随机字符串的辅助函数
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		// 这里使用时间作为随机源，在生产环境中应该使用更安全的随机源
		source := rand.NewSource(time.Now().UnixNano() + int64(i))
		r := rand.New(source)
		result[i] = charset[r.Intn(len(charset))]
	}
	return string(result)
}

// 修改发送UDP敲门请求函数
func SendKnockRequest(serverIP string, udpPort int, clientKey string) (*KnockResponse, error) {
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

	// 生成随机Nonce
	nonce := generateRandomString(16)

	// 生成签名
	data := fmt.Sprintf("%s|%s|%d", clientKey, clientIP, timestamp)
	h := hmac.New(sha256.New, []byte("server_secret_key"))
	h.Write([]byte(data))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 构建敲门请求
	req := KnockRequest{
		Nonce:     nonce, // 添加随机生成的Nonce
		ClientKey: clientKey,
		ClientIP:  clientIP,
		Timestamp: timestamp,
		Signature: signature,
	}

	// 序列化请求
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	// 发送UDP数据包
	_, err = conn.Write(reqData)
	if err != nil {
		return nil, fmt.Errorf("发送UDP敲门数据包失败: %v", err)
	}

	// 设置接收超时时间
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 接收响应
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("接收UDP响应失败: %v", err)
	}

	// 解析响应
	var response KnockResponse
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &response, nil
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
