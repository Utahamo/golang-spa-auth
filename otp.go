package main

import (
	"bytes"
	"fmt"
	"image/png"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "MyApp",

		AccountName: "user@example.com",
		Period:      60,
	})
	if err != nil {
		fmt.Println("Error generating OTP key:", err)
		return
	}
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	png.Encode(&buf, img)

	// display the QR code to the user.
	// display(buf.Bytes())

	fmt.Println("Key URL:", key.Secret())
	now := time.Now()
	passcode, err := totp.GenerateCode(key.Secret(), now)
	fmt.Println("Current OTP:", passcode)

	fmt.Println("qrcodeURL:", key.URL())

	fmt.Println(totp.Validate(key.Secret(), passcode))
}
