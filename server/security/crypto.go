// crypto.go 提供加密/解密相关功能
package security

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang-spa-auth/server/gmsm/sm4"
)

// SM4静态密钥，在实际环境中应该使用更安全的方式管理密钥
var (
	SM4Key = []byte("1234567890abcdef") // 16字节SM4密钥
	SM4IV  = []byte("0000000000000000") // 16字节IV向量
)

// 初始化SM4加密环境
func init() {
	// 设置SM4的IV
	err := sm4.SetIV(SM4IV)
	if err != nil {
		fmt.Printf("SM4初始化错误: %v\n", err)
	}
}

// EncryptSPARequest 使用SM4加密SPA请求
func EncryptSPARequest(req KnockRequest) (string, error) {
	// 序列化请求为JSON
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %v", err)
	}

	// 使用SM4 ECB模式加密
	encrypted, err := sm4.Sm4Ecb(SM4Key, data, true)
	if err != nil {
		return "", fmt.Errorf("SM4加密失败: %v", err)
	}

	// Base64编码加密后的数据
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptSPARequest 使用SM4解密SPA请求
func DecryptSPARequest(encryptedBase64 string) (*KnockRequest, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	// 使用SM4 ECB模式解密
	decrypted, err := sm4.Sm4Ecb(SM4Key, encrypted, false)
	if err != nil {
		return nil, fmt.Errorf("SM4解密失败: %v", err)
	}

	// 解析JSON
	var req KnockRequest
	err = json.Unmarshal(decrypted, &req)
	if err != nil {
		return nil, fmt.Errorf("解析请求失败: %v", err)
	}

	return &req, nil
}

// EncryptSPAResponse 使用SM4加密SPA响应
func EncryptSPAResponse(resp KnockResponse) (string, error) {
	// 序列化响应为JSON
	data, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("序列化响应失败: %v", err)
	}

	// 使用SM4 ECB模式加密
	encrypted, err := sm4.Sm4Ecb(SM4Key, data, true)
	if err != nil {
		return "", fmt.Errorf("SM4加密失败: %v", err)
	}

	// Base64编码加密后的数据
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptSPAResponse 使用SM4解密SPA响应
func DecryptSPAResponse(encryptedBase64 string) (*KnockResponse, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	// 使用SM4 ECB模式解密
	decrypted, err := sm4.Sm4Ecb(SM4Key, encrypted, false)
	if err != nil {
		return nil, fmt.Errorf("SM4解密失败: %v", err)
	}

	// 去除填充
	decrypted = bytes.TrimRight(decrypted, string([]byte{0}))

	// 解析JSON
	var resp KnockResponse
	err = json.Unmarshal(decrypted, &resp)
	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v，响应数据: %s", err, string(decrypted))
	}

	return &resp, nil
}

// EncryptedSPARequest 表示加密后的敲门请求
type EncryptedSPARequest struct {
	EncryptedData string `json:"encrypted_data"` // Base64编码的加密数据
}

// EncryptedSPAResponse 表示加密后的敲门响应
type EncryptedSPAResponse struct {
	EncryptedData string `json:"encrypted_data"` // Base64编码的加密数据
}
