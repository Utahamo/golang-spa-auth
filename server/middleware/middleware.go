package middleware

import (
	"net/http"
	"strings"

	"golang-spa-auth/server/auth"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := auth.ValidateToken(token)
		if err != nil || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 可以选择将claims添加到请求上下文中，以便后续处理函数使用
		// 例如：r = r.WithContext(context.WithValue(r.Context(), "claims", claims))

		next.ServeHTTP(w, r)
	})
}
