package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang-spa-auth/client/spa"

	"github.com/gin-gonic/gin"
	"golang-spa-auth/client/logger"
)

// 全局配置
var (
	config struct {
		ServerIP     string `json:"server_ip"`
		UDPPort      int    `json:"udp_port"`
		ClientKey    string `json:"client_key"`
		ServerSecret string `json:"server_secret"`
		HTTPPort     int    `json:"http_port"`
	}
)

func init() {
	// 设置默认配置
	config.ServerIP = "localhost"
	config.UDPPort = 9000
	config.ClientKey = "client_secret_key"
	config.ServerSecret = "server_secret_key"
	config.HTTPPort = 3000

	// 尝试加载配置文件
	loadConfig()
}

// 加载配置文件
func loadConfig() {
	configFile := "config.json"
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err == nil {
			if err := json.Unmarshal(data, &config); err != nil {
				log.Printf("配置文件格式错误: %v", err)
			} else {
				log.Println("已加载配置文件")
			}
		}
	}
}

func main() {
	// 创建Gin路由
	router := gin.Default()

	// 配置静态文件服务
	staticFS := http.Dir("./")
	staticHandler := http.StripPrefix("/", http.FileServer(staticFS))

	router.GET("/", func(c *gin.Context) {
		staticHandler.ServeHTTP(c.Writer, c.Request)
	})

	// 提供静态资源
	router.Static("/css", "./css")
	router.Static("/js", "./js")
	router.StaticFile("/index.html", "./index.html")
	router.StaticFile("/jwt.html", "./jwt.html")
	router.StaticFile("/auth.html", "./auth.html")

	// API路由组
	api := router.Group("/api")
	{
		// SPA敲门
		api.POST("/spa/knock", handleKnock)

		// TCP连接和令牌获取
		api.POST("/auth/connect", handleConnect)

		// 用户相关
		api.POST("/register", handleRegister)
		api.POST("/login", handleLogin)

		// 受保护资源
		api.GET("/data", handleData)
		api.GET("/secure/data", handleSecureData)
	}
	// 初始化日志系统
    logger.Init()
    logger.Info("SPA单包授权客户端启动")

	// 启动服务器
	addr := fmt.Sprintf(":%d", config.HTTPPort)
	log.Printf("客户端服务启动在 http://localhost%s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}

// SPA敲门请求处理
func handleKnock(c *gin.Context) {
	var req struct {
		ServerIP  string `json:"server_ip"`
		UDPPort   int    `json:"udp_port"`
		ClientKey string `json:"client_key"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 使用请求中的值或默认配置
	serverIP := config.ServerIP
	udpPort := config.UDPPort
	clientKey := config.ClientKey

	if req.ServerIP != "" {
		serverIP = req.ServerIP
	}

	if req.UDPPort != 0 {
		udpPort = req.UDPPort
	}

	if req.ClientKey != "" {
		clientKey = req.ClientKey
	}

	// 发送真实UDP敲门请求
	response, err := spa.SendKnockRequest(serverIP, udpPort, clientKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("敲门失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// TCP连接请求处理
func handleConnect(c *gin.Context) {
    // 从查询参数获取端口
    portStr := c.Query("port")
    if portStr == "" {
        logger.Error("缺少端口参数")
        c.JSON(http.StatusBadRequest, gin.H{"error": "缺少端口参数"})
        return
    }
    
    var req struct {
        ClientKey string `json:"client_key"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        logger.Error("无效的请求参数: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
        return
    }
    
    clientKey := req.ClientKey
    if clientKey == "" {
        clientKey = config.ClientKey // 使用默认客户端密钥
        logger.Info("使用默认客户端密钥: %s", clientKey)
    }
    
    logger.Info("尝试连接TCP端口: %s 服务器: %s", portStr, config.ServerIP)
    
    // 连接到TCP端口获取JWT令牌
    response, err := spa.ConnectToTcpPort(config.ServerIP, portStr, clientKey)
    if err != nil {
        logger.Error("TCP连接失败: %v", err)
        
        
        // 检查服务器状态
        _, httpErr := http.Get(fmt.Sprintf("http://%s:8080/", config.ServerIP))
        if httpErr != nil {
            logger.Error("HTTP连接测试失败: %v", httpErr)
        } else {
            logger.Info("HTTP连接测试成功，服务器响应")
        }
        
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": fmt.Sprintf("TCP连接失败: %v", err),
        })
        return
    }
    
    logger.Info("TCP连接成功，获取令牌: %+v", response)
    c.JSON(http.StatusOK, response)
}

// 转发注册请求
func handleRegister(c *gin.Context) {
	proxyRequest(c, "POST", fmt.Sprintf("http://%s:8080/api/register", config.ServerIP))
}

// 转发登录请求
func handleLogin(c *gin.Context) {
	proxyRequest(c, "POST", fmt.Sprintf("http://%s:8080/api/login", config.ServerIP))
}

// 转发数据请求
func handleData(c *gin.Context) {
	proxyRequest(c, "GET", fmt.Sprintf("http://%s:8080/api/data", config.ServerIP))
}

// 转发安全数据请求
func handleSecureData(c *gin.Context) {
	proxyRequest(c, "GET", fmt.Sprintf("http://%s:8080/api/secure/data", config.ServerIP))
}

// 通用请求转发函数
func proxyRequest(c *gin.Context, method string, url string) {
	// 创建新的HTTP请求
	req, err := http.NewRequest(method, url, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建请求失败"})
		return
	}

	// 复制原始请求的头信息
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 执行HTTP请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("请求失败: %v", err)})
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// 设置状态码
	c.Status(resp.StatusCode)

	// 复制响应内容
	_, err = io.Copy(c.Writer, resp.Body)
	if err != nil {
		log.Printf("复制响应内容失败: %v", err)
	}
}
