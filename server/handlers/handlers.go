package handlers

import (
	"encoding/json"
	"net/http"

	"golang-spa-auth/server/auth"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type DataResponse struct {
	Message  string `json:"message"`
	Username string `json:"username"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return
	}

	// 简单验证 - 实际应用中应该查询数据库
	if loginReq.Username == "admin" && loginReq.Password == "password" {
		token, err := auth.GenerateToken(loginReq.Username)
		if err != nil {
			http.Error(w, "生成令牌失败", http.StatusInternalServerError)
			return
		}

		response := LoginResponse{Token: token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := auth.ValidateToken(token)
	if err != nil || claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("This is a protected route"))
}

func GetDataHandler(w http.ResponseWriter, r *http.Request) {
	// 从请求上下文获取用户信息
	token := r.Header.Get("Authorization")
	claims, _ := auth.ValidateToken(token[7:]) // 去掉 "Bearer " 前缀

	response := DataResponse{
		Message:  "这是受保护的数据",
		Username: claims.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
