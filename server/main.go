package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"golang-spa-auth/server/auth"
	"golang-spa-auth/server/handlers"
	"golang-spa-auth/server/middleware"
	"golang-spa-auth/server/spa"

	"github.com/gin-gonic/gin"
)

func main() {
	// 初始化SPA服务器实例
	spaConfig := spa.SpaConfig{
		Secret:            "server_secret_key", // 用于验证敲门包的密钥
		UDPPort:           9000,
		TCPPortRangeStart: 10000, //开放的TCP端口范围, 用于分配给客户端(每个用户一个端口)
		TCPPortRangeEnd:   10100,
		AllowedClients:    []string{"client_secret_key"}, 
		PortValidity:      30 * time.Second, // 过期时间
	}

	spaServer := spa.NewSpaServer(spaConfig)
	log.Printf("SPA服务器已初始化，监听UDP端口: %d", spaConfig.UDPPort)

	// 创建请求处理器实例
	handler := handlers.NewHandler(spaServer, auth.DefaultAuthManager())

	// 创建Gin引擎
	r := gin.Default()

	// CORS中间件，api请求需要跨域
	r.Use(middleware.CORSMiddleware())

	// API路由如下
	api := r.Group("/api")
	{
		// SPA敲门处理
		api.POST("/spa/knock", handler.KnockHandler)

		// TCP连接和JWT授权
		api.POST("/auth/connect", handler.ConnectHandler)

		// 原有登录接口
		api.POST("/login", handler.LoginHandler)
		api.GET("/data", middleware.JWTAuthMiddleware(), handler.DataHandler)

		// 安全数据路由
		secure := api.Group("/secure")
		secure.Use(middleware.JWTAuthMiddleware())
		{
			secure.GET("/data", handler.SecureDataHandler)
		}
	}

	// 配置静态文件服务
	r.Static("/js", "./client/js")
	r.Static("/css", "./client/css")
	r.StaticFile("/spa_client.html", "./client/spa_client.html")
	r.StaticFile("/index.html", "./client/index.html")
	r.StaticFile("/", "./client/index.html")

	// 处理所有其他路由 - SPA应用的HTML5历史模式支持
	r.NoRoute(func(c *gin.Context) {
		// 检查是否是API请求
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API路径不存在"})
			return
		}

		// 非API请求可能是客户端路由
		c.File("./client/index.html")
	})

	log.Println("服务启动在 http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
