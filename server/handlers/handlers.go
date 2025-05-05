package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang-spa-auth/server/database"
	"golang-spa-auth/server/security"

	"github.com/gin-gonic/gin"
)

// Handler 处理器结构体，包含依赖项
type Handler struct {
	SPAServer   *security.SpaServer
	AuthManager *security.AuthManager
}

// NewHandler 创建一个新的处理器实例, 主要负责的是SPA和JWT的处理
func NewHandler(spaServer *security.SpaServer, authManager *security.AuthManager) *Handler {
	return &Handler{
		SPAServer:   spaServer,
		AuthManager: authManager,
	}
}

// RegisterHandler 处理注册请求, 需要邮件地址, 用户名和密码, 最后调用2fa的二维码返回给用户
func (h *Handler) RegisterHandler(c *gin.Context) {
	var registerReq struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	// 一般都这么写，主要是为了验证请求的合法性
	if err := c.ShouldBindJSON(&registerReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的注册请求"})
		return
	}

	// 使用pquerna生成2FA的key
	twoFAKey, _ := security.Generate2FAKey(registerReq.Email)
	// 生成2FA的二维码
	_, dataURL, _ := security.Generate2FASecret(twoFAKey)

	// 这里可以添加注册逻辑，例如保存用户信息到数据库
	dbUser := database.User{
		Email:    registerReq.Email,
		Username: registerReq.Username,
		Password: registerReq.Password,
		TwoFA:    twoFAKey.Secret(), // 这里可以存储2FA密钥
	}
	db := database.Getdb()
	if err := db.Create(&dbUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "注册成功", "qrcode_url": dataURL})
}

// LoginHandler 处理登录请求, 登录过程需要输入邮箱，用户名和密码，并且需要经过2fa验证
func (h *Handler) LoginHandler(c *gin.Context) {
	var loginReq struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		TwoFA    string `json:"2fa" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的登录请求"})
		return
	}

	// 对比数据库中的用户信息
	db := database.Getdb()
	var dbUser database.User
	if err := db.Where("email = ? AND username = ?", loginReq.Email, loginReq.Username).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	// 验证密码
	if dbUser.Password != loginReq.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	// 验证2FA，第一个参数是数据库中存储的2FA密钥，第二个参数是用户输入的2FA代码
	valid, _ := security.Validate2FACode(dbUser.TwoFA, loginReq.TwoFA)
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的2FA代码"})
		return
	}
	fmt.Println(valid)
	// 生成JWT令牌
	token, err := h.AuthManager.GenerateToken(dbUser.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}
	// 返回JWT令牌
	c.JSON(http.StatusOK, gin.H{"token": token})
	
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
	var req security.KnockRequest
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
