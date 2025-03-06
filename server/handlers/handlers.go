package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang-spa-auth/server/auth"
	"golang-spa-auth/server/spa"

	"github.com/gin-gonic/gin"
)

// Handler 处理器结构体，包含依赖项
type Handler struct {
	SPAServer   *spa.SpaServer
	AuthManager *auth.AuthManager
}

// NewHandler 创建一个新的处理器实例
func NewHandler(spaServer *spa.SpaServer, authManager *auth.AuthManager) *Handler {
	return &Handler{
		SPAServer:   spaServer,
		AuthManager: authManager,
	}
}

// LoginHandler 处理登录请求
func (h *Handler) LoginHandler(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的登录请求"})
		return
	}

	// 简单的用户验证
	if loginReq.Username == "admin" && loginReq.Password == "password" {
		token, err := h.AuthManager.GenerateToken(loginReq.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
	}
}

// DataHandler 处理常规JWT保护的数据请求
func (h *Handler) DataHandler(c *gin.Context) {
	username := c.GetString("username")

	c.JSON(http.StatusOK, gin.H{
		"message":   "这是受保护的数据",
		"username":  username,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// KnockHandler 处理SPA敲门请求
func (h *Handler) KnockHandler(c *gin.Context) {
	var req spa.KnockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	// 如果客户端没有提供IP，使用请求的远程地址
	if req.ClientIP == "" || req.ClientIP == "模拟客户端IP" {
		req.ClientIP = c.ClientIP()
	}

	// 验证敲门请求
	if err := h.SPAServer.ValidateKnockRequest(req); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("敲门请求被拒绝: %v", err)})
		return
	}

	// 分配端口
	resp, err := h.SPAServer.AllocatePort(req)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "无法分配端口"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ConnectHandler 处理TCP连接和JWT授权
func (h *Handler) ConnectHandler(c *gin.Context) {
	// 获取TCP端口
	portStr := c.Query("port")
	if portStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未指定端口"})
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的端口参数"})
		return
	}

	// 获取客户端密钥
	var req struct {
		ClientKey string `json:"client_key" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据"})
		return
	}

	// 验证端口分配
	valid, err := h.SPAServer.ValidatePortAllocation(port, req.ClientKey)
	if !valid || err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("无效的端口授权: %v", err),
		})
		return
	}

	// 生成JWT令牌
	token, err := h.AuthManager.GenerateToken("user_" + req.ClientKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成访问令牌失败"})
		return
	}

	// 延长端口分配时间
	h.SPAServer.ExtendPortAllocation(port)

	// 返回访问令牌
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	c.JSON(http.StatusOK, gin.H{
		"status":     "connected",
		"token":      token,
		"expires_at": expiresAt,
	})
}

// SecureDataHandler 处理通过SPA+JWT双重保护的安全数据访问
func (h *Handler) SecureDataHandler(c *gin.Context) {
	username := c.GetString("username")
	clientIP := c.ClientIP()

	// 返回一些敏感数据
	c.JSON(http.StatusOK, gin.H{
		"message":   "您已成功访问受保护的数据",
		"username":  username,
		"timestamp": time.Now().Format(time.RFC3339),
		"clientIP":  clientIP,
		"data": gin.H{
			"id":       123,
			"name":     "敏感数据项",
			"category": "机密",
			"value":    "这是一些需要经过SPA授权和JWT认证才能访问的敏感数据",
		},
	})
}
