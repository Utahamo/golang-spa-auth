package main

import (
	"log"
	"path/filepath"
	"time"

	"golang-spa-auth/server/database"
	"golang-spa-auth/server/handlers"
	"golang-spa-auth/server/router"
	"golang-spa-auth/server/security"
)

func main() {
	// 设置SM2公钥目录
	publicKeysDir := filepath.Join(".", "server", "keys")
	log.Printf("配置SM2公钥目录: %s", publicKeysDir)

	// 初始化SPA服务器实例
	spaConfig := security.SpaConfig{
		Secret:            "server_secret_key", // 用于验证敲门包的密钥
		UDPPort:           9000,
		TCPPortRangeStart: 10000, // 开放的TCP端口范围, 用于分配给客户端(每个用户一个端口)
		TCPPortRangeEnd:   10100,
		AllowedClients:    []string{"client_secret_key"},
		PortValidity:      30 * time.Second, // 过期时间
		PublicKeysDir:     publicKeysDir,    // SM2公钥目录
	}
	// 初始化数据库连接
	database.InitDB()
	// 初始化SPA服务器
	spaServer := security.NewSpaServer(spaConfig)
	log.Printf("SPA服务器已初始化，监听UDP端口: %d", spaConfig.UDPPort)
	log.Printf("配置的端口范围: %d-%d, 有效期: %v",
		spaConfig.TCPPortRangeStart, spaConfig.TCPPortRangeEnd, spaConfig.PortValidity)

	// 初始化2fa服务器
	// twpfaServer := spa.New2faServer(spaConfig)
	// log.Printf("2FA服务器已初始化，监听UDP端口: %d", spaConfig.UDPPort)

	// 创建请求处理器实例, 相当于整合了所有的处理器, 更好的方法是创建router.go, 然后在router.go中创建处理器
	handler := handlers.NewHandler(spaServer, security.DefaultAuthManager())

	// 调用SetRouter函数, 传入处理器实例, 设置路由
	router := router.SetRouter(handler)

	log.Println("服务启动在 http://localhost:8080")
	if err := router.Run("127.0.0.1:8080"); err != nil {
		log.Fatal(err)
	}
}
