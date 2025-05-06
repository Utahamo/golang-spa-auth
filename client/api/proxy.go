package api

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
)

// ApiConfig 存储API代理配置
type ApiConfig struct {
    ServerIP   string
    ServerPort int
    Timeout    time.Duration
}

// 默认配置
var DefaultConfig = ApiConfig{
    ServerIP:   "localhost",
    ServerPort: 8080,
    Timeout:    5 * time.Second,
}

// ApiProxy 实现API代理
type ApiProxy struct {
    config ApiConfig
    client *http.Client
}

// NewApiProxy 创建API代理实例
func NewApiProxy(config ApiConfig) *ApiProxy {
    return &ApiProxy{
        config: config,
        client: &http.Client{
            Timeout: config.Timeout,
        },
    }
}

// KnockRequest 处理敲门请求
func (p *ApiProxy) KnockRequest(c *gin.Context) {
    var req struct {
        ServerIP   string `json:"server_ip"`
        UDPPort    int    `json:"udp_port"`
        ClientKey  string `json:"client_key"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
        return
    }
    
    // 确保必要参数存在
    serverIP := req.ServerIP
    if serverIP == "" {
        serverIP = p.config.ServerIP
    }
    
    udpPort := req.UDPPort
    if udpPort == 0 {
        udpPort = 9000 // 默认敲门端口
    }
    
    clientKey := req.ClientKey
    if clientKey == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "缺少客户端密钥"})
        return
    }
    
    // 构建转发请求
    url := fmt.Sprintf("http://%s:%d/api/spa/knock", serverIP, p.config.ServerPort)
    
    // 构建请求体
    reqBody, err := json.Marshal(req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "构建请求失败"})
        return
    }
    
    // 创建HTTP请求
    httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "创建HTTP请求失败"})
        return
    }
    
    httpReq.Header.Set("Content-Type", "application/json")
    
    // 执行请求
    resp, err := p.client.Do(httpReq)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("请求失败: %v", err)})
        return
    }
    defer resp.Body.Close()
    
    // 读取响应体
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "读取响应失败"})
        return
    }
    
    // 设置响应状态码
    c.Status(resp.StatusCode)
    
    // 返回响应内容
    c.Writer.Header().Set("Content-Type", "application/json")
    c.Writer.Write(body)
}

// ConnectRequest 处理TCP连接请求
func (p *ApiProxy) ConnectRequest(c *gin.Context) {
    // 获取端口参数
    port := c.Query("port")
    if port == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "缺少端口参数"})
        return
    }
    
    var req map[string]interface{}
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
        return
    }
    
    // 构建转发请求URL
    url := fmt.Sprintf("http://%s:%s/api/auth/connect", p.config.ServerIP, port)
    
    // 准备请求内容
    reqBody, err := json.Marshal(req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "构建请求失败"})
        return
    }
    
    // 创建HTTP请求
    httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "创建HTTP请求失败"})
        return
    }
    
    httpReq.Header.Set("Content-Type", "application/json")
    
    // 执行请求
    resp, err := p.client.Do(httpReq)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("连接失败: %v", err)})
        return
    }
    defer resp.Body.Close()
    
    // 读取响应体
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "读取响应失败"})
        return
    }
    
    // 设置响应状态码
    c.Status(resp.StatusCode)
    
    // 返回响应内容
    c.Writer.Header().Set("Content-Type", "application/json")
    c.Writer.Write(body)
}

// SecureDataRequest 处理安全数据请求
func (p *ApiProxy) SecureDataRequest(c *gin.Context) {
    // 从请求头获取授权令牌
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少授权令牌"})
        return
    }
    
    // 构建转发请求URL
    url := fmt.Sprintf("http://%s:%d/api/secure/data", p.config.ServerIP, p.config.ServerPort)
    
    // 创建HTTP请求
    httpReq, err := http.NewRequest("GET", url, nil)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "创建HTTP请求失败"})
        return
    }
    
    // 添加授权头
    httpReq.Header.Set("Authorization", authHeader)
    
    // 执行请求
    resp, err := p.client.Do(httpReq)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("请求失败: %v", err)})
        return
    }
    defer resp.Body.Close()
    
    // 读取响应体
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "读取响应失败"})
        return
    }
    
    // 设置响应状态码
    c.Status(resp.StatusCode)
    
    // 返回响应内容
    c.Writer.Header().Set("Content-Type", "application/json")
    c.Writer.Write(body)
}