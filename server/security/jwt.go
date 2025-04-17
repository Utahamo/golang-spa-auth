// 主要用于处理JWT令牌的生成和验证
package security

import (
	"errors"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	defaultManager     *AuthManager
	defaultManagerOnce sync.Once
)

// Claims JWT声明结构
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// AuthManager 认证管理器, 作用是生成和验证JWT令牌
type AuthManager struct {
	secretKey []byte
}

// NewAuthManager 创建一个新的认证管理器
func NewAuthManager(secretKey string) *AuthManager {
	return &AuthManager{
		secretKey: []byte(secretKey),
	}
}

// DefaultAuthManager 获取默认的认证管理器实例（单例模式）
func DefaultAuthManager() *AuthManager {
	defaultManagerOnce.Do(func() {
		defaultManager = NewAuthManager("04nc9x0w3kv0ab5pc91c") // 这里最好换成随机字符串，保证安全性
	})
	return defaultManager
}

// GenerateToken 生成JWT令牌
func (am *AuthManager) GenerateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   "api_access",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(am.secretKey)
}

// GenerateConnectionToken 生成用于连接的短期令牌
func (am *AuthManager) GenerateConnectionToken(username string, connectionKey string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   "connection",
			Id:        connectionKey,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(am.secretKey)
}

// ValidateToken 验证JWT令牌
func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	// 解析令牌
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 确保算法匹配
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return am.secretKey, nil
	})

	// 处理错误
	if err != nil {
		return nil, err
	}

	// 验证令牌有效性
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
