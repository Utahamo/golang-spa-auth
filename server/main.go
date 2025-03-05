package main

import (
	"golang-spa-auth/server/handlers"
	"golang-spa-auth/server/middleware"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// API 路由
	r.HandleFunc("/api/login", handlers.LoginHandler).Methods("POST")

	// 保护的API路由 - 使用中间件
	protectedRoutes := r.PathPrefix("/api").Subrouter()
	protectedRoutes.Use(middleware.AuthMiddleware)
	protectedRoutes.HandleFunc("/data", handlers.GetDataHandler).Methods("GET")

	// 为静态文件提供服务
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./client")))

	http.Handle("/", r)

	log.Println("服务启动在 http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
