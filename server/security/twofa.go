package security

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

func Generate2FASecret(key *otp.Key) (string, string, error) {
	now := time.Now()
	passcode, _ := totp.GenerateCode(key.Secret(), now)
	fmt.Println("Current OTP:", passcode)
	// 生成对应的二维码
	qrCodeURL := key.URL() // 这里可以生成二维码的URL

	// 生成二维码的字节数组
	qrBytes, _ := qrcode.Encode(qrCodeURL, qrcode.Medium, 256)

	// 转换为 Base64 data URL
	base64Image := base64.StdEncoding.EncodeToString(qrBytes)
	dataURL := "data:image/png;base64," + base64Image

	return passcode, dataURL, nil
}

func Generate2FAKey(email string) (*otp.Key, error) {
	// 生成一个新的2FA密钥
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SPA授权app",
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}
	// key.Secret()的值是一个Base32编码的字符串，是用来生成TOTP的密钥
	return key, nil
}

func Validate2FACode(secret, code string) (bool, error) {
	// 验证2FA代码
	valid := totp.Validate(code, secret)
	if !valid {
		return false, fmt.Errorf("无效的2FA代码")
	}
	return true, nil
}
