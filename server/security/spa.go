// 主要用于SPA包的生成和验证
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang-spa-auth/server/gmsm/sm2"
	"golang-spa-auth/server/gmsm/sm3"
)

// 初始化随机种子
func init() {
	mrand.Seed(time.Now().UnixNano())
}

// SpaConfig 存储SPA敲门服务的配置
type SpaConfig struct {
	Secret            string        // 用于验证敲门包的密钥
	UDPPort           int           // UDP敲门端口
	TCPPortRangeStart int           // TCP端口范围起始
	TCPPortRangeEnd   int           // TCP端口范围结束
	AllowedClients    []string      // 允许的客户端密钥列表
	PortValidity      time.Duration // 分配的端口有效期
	PublicKeysDir     string        // 公钥目录路径
}

// SPA包的内容，应该尽量复杂，包含随机数Nonce, 时间戳, 身份标识, 环境上下文, 签名, 加密密文
// 身份标识包含如设备MAC哈希、用户名哈希等, 使用SM3加密算法进行加密
// 环境上下文	设备信息（如地理位置IP属地、设备类型）地理位置可通过IP反查API获取，加密存储
// 签名	使用SM2算法进行签名
// 加密密文	使用SM4算法进行加密，密钥为随机生成的16位字符串，使用AES-128-CBC加密模式
// type KnockRequest struct {
// 	Nonce      string `json:"nonce"`       // 随机字符串
// 	Timestamp  int64  `json:"timestamp"`   // 时间戳
// 	Username   string `json:"username"`    // 用户名或身份标识
// 	DeviceInfo string `json:"device_info"` // 设备信息, 需要SM3哈希
// 	// Location     string `json:"location"`      // 地理位置, 暂时用不到
// 	Signature string `json:"signature"` // 签名, SM2算法签名
// 	// Encrypted    string `json:"encrypted"`     // 加密密文，包括需要
// 	// EncryptedKey string `json:"encrypted_key"` // 加密密钥
// }

type KnockRequest struct {
	Nonce             string `json:"nonce"`              // 随机字符串
	ClientKey         string `json:"client_key"`         // 客户端密钥
	ClientIP          string `json:"client_ip"`          // 客户端IP
	Timestamp         int64  `json:"timestamp"`          // 请求时间戳
	Signature         string `json:"signature"`          // 请求签名（可选）
	SPAVersion        string `json:"spa_version"`        // SPA版本号
	Username          string `json:"username"`           // 用户名
	DeviceFingerprint string `json:"device_fingerprint"` // 设备指纹
	TargetPort        int    `json:"target_port"`        // 目的端口号
}

// EncryptedSPARequest 表示加密后的敲门请求
type EncryptedSPARequest struct {
	EncryptedData string `json:"encrypted_data"` // Base64编码的加密数据
	KeyID         string `json:"key_id"`         // 用于在服务端查找公钥的标识符（通常为客户端ID或密钥）
	Signature     []byte `json:"signature"`      // SM2签名
}

// KnockResponse 表示对敲门请求的响应
type KnockResponse struct {
	Port      int   `json:"port"`       // 分配的TCP端口
	ExpiresIn int64 `json:"expires_in"` // 有效期（秒）
	Timestamp int64 `json:"timestamp"`  // 响应时间戳
}

// PortAllocation 表示一个已分配的端口
type PortAllocation struct {
	Port       int       // 分配的端口
	ClientKey  string    // 客户端密钥
	ClientIP   string    // 客户端IP
	AssignedAt time.Time // 分配时间
	ExpiresAt  time.Time // 过期时间
}

// SpaServer 实现单包授权服务, 运行在服务端(或称零信任网关)
type SpaServer struct {
	config           SpaConfig
	allocations      sync.Map // 存储端口分配 key=端口, value=PortAllocation
	usedNonces       sync.Map // 存储最近使用的Nonce key=Nonce, value=过期时间
	clientPublicKeys sync.Map // 存储客户端公钥 key=客户端ID, value=*sm2.PublicKey
	mutex            sync.Mutex
	udpConn          *net.UDPConn // 用于UDP监听
}

// 修改NewSpaServer函数，启动UDP监听服务
func NewSpaServer(config SpaConfig) *SpaServer {
	// 设置默认过期时间
	if config.PortValidity == 0 {
		config.PortValidity = 30 * time.Second
	}

	server := &SpaServer{
		config: config,
	}

	// 加载SM2公钥
	server.loadPublicKeys()

	// 启动过期端口清理任务
	go server.cleanExpiredPorts()
	go server.cleanExpiredNonces()

	// 启动UDP监听服务
	go server.startUDPServer()

	return server
}

// 添加UDP服务器启动函数
func (s *SpaServer) startUDPServer() {
	// 解析UDP地址
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.config.UDPPort))
	if err != nil {
		log.Printf("解析UDP地址失败: %v", err)
		return
	}

	// 监听UDP端口
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("UDP监听失败: %v", err)
		return
	}

	s.udpConn = conn
	defer conn.Close()

	log.Printf("UDP敲门服务已启动，监听端口: %d", s.config.UDPPort)

	// 循环读取UDP数据包
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("读取UDP数据包失败: %v", err)
			continue
		}

		// 处理接收到的敲门请求
		go s.handleKnockRequest(buffer[:n], addr)
	}
}

// 添加处理UDP敲门请求的函数
func (s *SpaServer) handleKnockRequest(data []byte, addr *net.UDPAddr) {
	log.Printf("接收到来自 %s 的敲门请求", addr.String())
	log.Printf("接收的原始数据包: %x", data)              // 打印原始数据包（十六进制）
	log.Printf("接收的原始数据包(字符串): %s", string(data)) // 打印原始数据包（字符串形式）

	// 将接收到的数据解析为加密请求
	var encReq EncryptedSPARequest
	if err := json.Unmarshal(data, &encReq); err != nil {
		log.Printf("解析加密请求失败: %v，尝试解析为未加密请求", err)

		// 如果不是加密请求格式，尝试解析为普通请求（兼容旧版本）
		var req KnockRequest
		if err := json.Unmarshal(data, &req); err != nil {
			log.Printf("解析请求失败: %v", err)
			sendUDPErrorResponse(s.udpConn, addr, "解析请求失败: "+err.Error())
			return
		}

		log.Printf("成功解析未加密请求: %+v", req) // 打印解析后的未加密请求

		// 设置客户端IP (使用实际UDP请求的源IP地址)
		req.ClientIP = addr.IP.String()

		// 验证敲门请求
		if err := s.ValidateKnockRequest(req); err != nil {
			log.Printf("敲门请求验证失败: %v", err)
			sendUDPErrorResponse(s.udpConn, addr, "敲门请求被拒绝: "+err.Error())
			return
		}

		// 分配端口
		resp, err := s.AllocatePort(req)
		if err != nil {
			log.Printf("无法分配端口: %v", err)
			sendUDPErrorResponse(s.udpConn, addr, "无法分配端口: "+err.Error())
			return
		}

		// 发送响应
		respData, err := json.Marshal(resp)
		if err != nil {
			log.Printf("响应JSON编码失败: %v", err)
			return
		}

		log.Printf("发送未加密响应: %+v", resp)

		// 通过UDP发送响应
		_, err = s.udpConn.WriteToUDP(respData, addr)
		if err != nil {
			log.Printf("发送UDP响应失败: %v", err)
			return
		}

		log.Printf("已为 %s 分配端口 %d, 有效期 %d 秒",
			addr.String(), resp.Port, resp.ExpiresIn)
		return
	}

	log.Printf("检测到加密请求, 加密数据: %s", encReq.EncryptedData)

	// 验证SM2签名
	if encReq.Signature != nil && len(encReq.KeyID) > 0 {
		log.Println("检测到SM2签名，进行验证...")

		// 从内存映射中查找公钥
		pubKey, exists := s.clientPublicKeys.Load(encReq.KeyID)
		if !exists {
			log.Printf("未找到对应的SM2公钥")
			sendUDPErrorResponse(s.udpConn, addr, "未找到对应的SM2公钥")
			return
		}

		pub := pubKey.(*sm2.PublicKey)

		// 使用SM3计算摘要
		h := sm3.New()
		h.Write([]byte(encReq.EncryptedData))
		sum := h.Sum(nil)

		// 构造完整消息（与客户端签名的消息相同：加密数据+摘要）
		msg := append([]byte(encReq.EncryptedData), sum...)

		// 使用请求中的公钥验证签名
		isValid := pub.Verify(msg, encReq.Signature)

		if !isValid {
			log.Printf("SM2签名验证失败")
			sendUDPErrorResponse(s.udpConn, addr, "SM2签名验证失败")
			return
		}

		log.Printf("SM2签名验证成功")
	}

	// 解密请求
	req, err := DecryptSPARequest(encReq.EncryptedData)
	if err != nil {
		log.Printf("解密请求失败: %v", err)
		sendUDPErrorResponse(s.udpConn, addr, "解密请求失败: "+err.Error())
		return
	}

	// 打印详细的请求信息，特别是新增字段
	log.Printf("成功解密SPA请求:")
	log.Printf("  基本信息: Nonce=%s, ClientKey=%s, Timestamp=%d",
		req.Nonce, req.ClientKey, req.Timestamp)
	log.Printf("  来源信息: ClientIP=%s", req.ClientIP)
	log.Printf("  新增信息: SPA版本=%s, 用户名=%s, 目标端口=%d",
		req.SPAVersion, req.Username, req.TargetPort)
	log.Printf("  设备指纹: %s", req.DeviceFingerprint)

	// 设置客户端IP (使用实际UDP请求的源IP地址)
	req.ClientIP = addr.IP.String()

	// 验证敲门请求
	if err := s.ValidateKnockRequest(*req); err != nil {
		log.Printf("敲门请求验证失败: %v", err)
		sendUDPErrorResponse(s.udpConn, addr, "敲门请求被拒绝: "+err.Error())
		return
	}

	// 分配端口
	resp, err := s.AllocatePort(*req)
	if err != nil {
		log.Printf("无法分配端口: %v", err)
		sendUDPErrorResponse(s.udpConn, addr, "无法分配端口: "+err.Error())
		return
	}

	log.Printf("已分配端口，准备加密响应: %+v", resp)

	// 加密响应
	encryptedResp, err := EncryptSPAResponse(resp)
	if err != nil {
		log.Printf("加密响应失败: %v", err)
		sendUDPErrorResponse(s.udpConn, addr, "加密响应失败: "+err.Error())
		return
	}

	// 构造加密响应对象
	encResp := EncryptedSPAResponse{
		EncryptedData: encryptedResp,
	}

	log.Printf("响应已加密: %s", encryptedResp)

	// 序列化加密响应
	respData, err := json.Marshal(encResp)
	if err != nil {
		log.Printf("响应JSON编码失败: %v", err)
		return
	}

	log.Printf("发送加密响应数据包: %s", string(respData))

	// 通过UDP发送加密响应
	_, err = s.udpConn.WriteToUDP(respData, addr)
	if err != nil {
		log.Printf("发送UDP加密响应失败: %v", err)
		return
	}

	log.Printf("已为 %s 分配加密端口 %d, 有效期 %d 秒",
		addr.String(), resp.Port, resp.ExpiresIn)
}

// 添加发送UDP错误响应的辅助函数
func sendUDPErrorResponse(conn *net.UDPConn, addr *net.UDPAddr, errMsg string) {
	resp := map[string]interface{}{
		"error":     errMsg,
		"timestamp": time.Now().Unix(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("错误响应JSON编码失败: %v", err)
		return
	}

	_, err = conn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("发送UDP错误响应失败: %v", err)
	}
}

// 下面是用于验证的相关函数
// ===================================================================================

// 检查并记录Nonce，如果Nonce已存在返回false，否则存储并返回true
func (s *SpaServer) checkAndStoreNonce(nonce string, expiry time.Time) bool {
	// 如果Nonce已存在，则返回false
	if _, exists := s.usedNonces.Load(nonce); exists {
		return false
	}
	s.usedNonces.Store(nonce, expiry)
	return true
}

// 清理过期的Nonce
func (s *SpaServer) cleanExpiredNonces() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.usedNonces.Range(func(key, value interface{}) bool {
			expiry := value.(time.Time)
			if now.After(expiry) {
				s.usedNonces.Delete(key)
			}
			return true
		})
	}
}

// 验证敲门请求
// ====================================================================================
// ValidateKnockRequest 验证敲门请求，这一部分需要进行大量填充
func (s *SpaServer) ValidateKnockRequest(req KnockRequest) error {
	// 基本字段验证
	if req.Nonce == "" {
		log.Println("Nonce不能为空")
		return errors.New("Nonce不能为空")
	}

	// 验证客户端密钥是否在白名单中
	clientAuthorized := false
	for _, allowedKey := range s.config.AllowedClients {
		if req.ClientKey == allowedKey {
			clientAuthorized = true
			break
		}
	}

	if !clientAuthorized {
		log.Println("未授权的客户端密钥")
		return errors.New("未授权的客户端密钥")
	}

	// 验证时间戳不超过5分钟
	now := time.Now()
	if now.Unix()-req.Timestamp > 300 {
		log.Println("请求已过期")
		return errors.New("请求已过期")
	}

	// 验证Nonce唯一性，防止重放攻击
	if req.Nonce != "" {
		nonceExpiry := time.Unix(req.Timestamp, 0).Add(5 * time.Minute)
		if !s.checkAndStoreNonce(req.Nonce, nonceExpiry) {
			log.Println("Nonce已被使用，可能是重放攻击")
			return errors.New("Nonce已被使用，可能是重放攻击")
		}
	}

	// // 如果请求包含签名，验证签名
	// if req.Signature != "" {
	// 	expectedSignature := generateSignature(req, s.config.Secret)
	// 	if req.Signature != expectedSignature {
	// 		return errors.New("请求签名无效")
	// 	}
	// }

	return nil
}

// AllocatePort 分配一个可用端口
func (s *SpaServer) AllocatePort(req KnockRequest) (KnockResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 在端口范围内寻找可用端口
	for port := s.config.TCPPortRangeStart; port <= s.config.TCPPortRangeEnd; port++ {
		if _, allocated := s.allocations.Load(port); !allocated {
			if isPortAvailable(port) {
				now := time.Now()
				allocation := PortAllocation{
					Port:       port,
					ClientKey:  req.ClientKey,
					ClientIP:   req.ClientIP,
					AssignedAt: now,
					ExpiresAt:  now.Add(s.config.PortValidity),
				}

				s.allocations.Store(port, allocation)

				return KnockResponse{
					Port:      port,
					ExpiresIn: int64(s.config.PortValidity.Seconds()),
					Timestamp: now.Unix(),
				}, nil
			}
		}
	}

	return KnockResponse{}, errors.New("没有可用的端口")
}

// ValidatePortAllocation 验证端口分配是否有效
func (s *SpaServer) ValidatePortAllocation(port int, clientKey string) (bool, error) {
	allocation, exists := s.allocations.Load(port)
	if !exists {
		return false, errors.New("端口无效")
	}

	portAlloc := allocation.(PortAllocation)

	// 验证客户端密钥
	if portAlloc.ClientKey != clientKey {
		return false, errors.New("客户端密钥不匹配")
	}

	// 检查是否过期
	if time.Now().After(portAlloc.ExpiresAt) {
		s.allocations.Delete(port)
		return false, errors.New("端口分配已过期")
	}

	return true, nil
}

// ExtendPortAllocation 延长端口分配的有效期
func (s *SpaServer) ExtendPortAllocation(port int) bool {
	allocation, exists := s.allocations.Load(port)
	if !exists {
		return false
	}

	portAlloc := allocation.(PortAllocation)
	portAlloc.ExpiresAt = time.Now().Add(s.config.PortValidity)
	s.allocations.Store(portAlloc.Port, portAlloc)

	return true
}

// ReleasePort 释放分配的端口
func (s *SpaServer) ReleasePort(port int) {
	s.allocations.Delete(port)
}

// cleanExpiredPorts 定期清理过期的端口分配
func (s *SpaServer) cleanExpiredPorts() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		s.allocations.Range(func(key, value interface{}) bool {
			port := key.(int)
			allocation := value.(PortAllocation)

			if now.After(allocation.ExpiresAt) {
				s.allocations.Delete(port)
				fmt.Printf("已清理过期端口: %d, 客户端: %s\n", port, allocation.ClientKey)
			}

			return true
		})
	}
}

// 检查端口是否可用
func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// 生成签名
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[mrand.Intn(len(charset))]
	}
	return string(result)
}

// 修改generateSignature为公开
func GenerateSignature(req KnockRequest, secret string) string {
	data := fmt.Sprintf("%s|%s|%d", req.ClientKey, req.ClientIP, req.Timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GetConnectionCount 返回当前活跃连接数
func (s *SpaServer) GetConnectionCount() int {
	count := 0
	s.allocations.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// GetActiveConnections 返回当前所有活跃连接的信息
func (s *SpaServer) GetActiveConnections() []PortAllocation {
	connections := []PortAllocation{}

	s.allocations.Range(func(_, value interface{}) bool {
		allocation := value.(PortAllocation)
		connections = append(connections, allocation)
		return true
	})

	return connections
}

// loadPublicKeys 从公钥目录加载SM2公钥
func (s *SpaServer) loadPublicKeys() {
	if s.config.PublicKeysDir == "" {
		log.Println("未配置公钥目录，跳过公钥加载")
		return
	}

	log.Printf("从目录加载SM2公钥: %s", s.config.PublicKeysDir)
	absPath, err := filepath.Abs(s.config.PublicKeysDir)
	if err != nil {
		log.Printf("获取公钥目录绝对路径失败: %v", err)
	} else {
		log.Printf("公钥目录绝对路径: %s", absPath)
	}

	// 检查目录是否存在
	if _, err := os.Stat(s.config.PublicKeysDir); os.IsNotExist(err) {
		log.Printf("公钥目录不存在: %s", s.config.PublicKeysDir)
		return
	}

	// 读取目录中的所有文件
	files, err := os.ReadDir(s.config.PublicKeysDir)
	if err != nil {
		log.Printf("读取公钥目录失败: %v", err)
		return
	}

	log.Printf("公钥目录中共有 %d 个文件/目录", len(files))

	// 遍历目录中的所有文件
	for _, file := range files {
		if file.IsDir() {
			log.Printf("跳过子目录: %s", file.Name())
			continue
		}

		// 只处理PEM文件
		if !strings.HasSuffix(file.Name(), ".pem") {
			log.Printf("跳过非PEM文件: %s", file.Name())
			continue
		}

		// 从文件名中提取客户端ID（去除.pem扩展名）
		clientID := strings.TrimSuffix(file.Name(), ".pem")
		log.Printf("处理公钥文件: %s, 客户端ID: %s", file.Name(), clientID)

		// 加载公钥文件
		pubKeyPath := filepath.Join(s.config.PublicKeysDir, file.Name())
		pubKey, err := sm2.LoadPublicKeyFromPEM(pubKeyPath)
		if err != nil {
			log.Printf("加载SM2公钥文件失败 %s: %v", pubKeyPath, err)
			continue
		}

		// 将公钥存储到内存映射中
		s.clientPublicKeys.Store(clientID, pubKey)
		log.Printf("成功加载客户端 %s 的SM2公钥", clientID)
	}

	// 打印加载的公钥数量和所有加载的客户端ID
	count := 0
	var clientIDs []string
	s.clientPublicKeys.Range(func(key, _ interface{}) bool {
		count++
		clientIDs = append(clientIDs, key.(string))
		return true
	})
	log.Printf("共加载了 %d 个SM2公钥, 客户端ID列表: %v", count, clientIDs)
}
