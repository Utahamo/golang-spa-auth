// 主要用于SPA包的生成和验证
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// 初始化随机种子
func init() {
	rand.Seed(time.Now().UnixNano())
}

// SpaConfig 存储SPA敲门服务的配置
type SpaConfig struct {
	Secret            string        // 用于验证敲门包的密钥
	UDPPort           int           // UDP敲门端口
	TCPPortRangeStart int           // TCP端口范围起始
	TCPPortRangeEnd   int           // TCP端口范围结束
	AllowedClients    []string      // 允许的客户端密钥列表
	PortValidity      time.Duration // 分配的端口有效期
}

// KnockRequest 表示一个敲门请求
type KnockRequest struct {
	ClientKey string `json:"client_key"` // 客户端密钥
	ClientIP  string `json:"client_ip"`  // 客户端IP
	Timestamp int64  `json:"timestamp"`  // 请求时间戳
	Signature string `json:"signature"`  // 请求签名（可选）
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

// SpaServer 实现单包授权服务
type SpaServer struct {
	config      SpaConfig
	allocations sync.Map // 存储端口分配 key=端口, value=PortAllocation
	mutex       sync.Mutex
}

// NewSpaServer 创建一个新的SPA服务器实例
func NewSpaServer(config SpaConfig) *SpaServer {
	// 设置过期时间，默认值为30秒
	if config.PortValidity == 0 {
		config.PortValidity = 30 * time.Second
	}
	// 减少开销所以使用了指针方式
	server := &SpaServer{
		config: config,
	}

	// 启动过期端口清理任务
	go server.cleanExpiredPorts()

	return server
}

// ValidateKnockRequest 验证敲门请求
func (s *SpaServer) ValidateKnockRequest(req KnockRequest) error {
	// 验证时间戳不超过5分钟
	if time.Now().Unix()-req.Timestamp > 300 {
		return errors.New("请求已过期")
	}

	// 验证客户端密钥是否在允许列表中
	clientAllowed := false
	for _, key := range s.config.AllowedClients {
		if key == req.ClientKey {
			clientAllowed = true
			break
		}
	}

	if !clientAllowed {
		return errors.New("客户端未授权")
	}

	// 如果请求包含签名，验证签名
	if req.Signature != "" {
		expectedSignature := generateSignature(req, s.config.Secret)
		if req.Signature != expectedSignature {
			return errors.New("请求签名无效")
		}
	}

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
		return false, errors.New("未分配的端口")
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
	s.allocations.Store(port, portAlloc)

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
func generateSignature(req KnockRequest, secret string) string {
	data := fmt.Sprintf("%s|%s|%d", req.ClientKey, req.ClientIP, req.Timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// 生成随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
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
