package main

import (
	"net/http"
	"strings"

	"golang-spa-auth/server/handlers"
	"golang-spa-auth/server/middleware"

	"github.com/gin-gonic/gin"
)

func SetRouter(handler *handlers.Handler) *gin.Engine {
	// 创建Gin引擎
	r := gin.Default()

	// CORS中间件，api请求需要跨域
	r.Use(middleware.CORSMiddleware())

	// API路由组
	api := r.Group("/api")
	{
		// SPA敲门处理
		api.POST("/spa/knock", handler.KnockHandler)

		// TCP连接和JWT授权
		api.POST("/auth/connect", handler.ConnectHandler)

		// 注册接口
		api.POST("/register", handler.RegisterHandler)

		// 用户登录
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
	r.StaticFile("/index.html", "./client/index.html")
	r.StaticFile("/jwt.html", "./client/jwt.html")
	r.StaticFile("/spa_client.html", "./client/spa_client.html") // 添加SPA客户端页面
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

	return r
}
