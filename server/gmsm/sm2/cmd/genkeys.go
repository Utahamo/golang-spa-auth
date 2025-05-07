package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang-spa-auth/server/gmsm/sm2"
)

func main() {
	// 定义命令行参数
	var (
		outputDir  string
		privateKey string
		publicKey  string
		help       bool
	)

	flag.StringVar(&outputDir, "out", "keys", "密钥输出目录")
	flag.StringVar(&privateKey, "priv", "sm2private.pem", "私钥文件名")
	flag.StringVar(&publicKey, "pub", "sm2public.pem", "公钥文件名")
	flag.BoolVar(&help, "h", false, "显示帮助信息")
	flag.Parse()

	if help {
		fmt.Println("SM2密钥生成工具")
		fmt.Println("用法: genkeys [选项]")
		fmt.Println("选项:")
		flag.PrintDefaults()
		return
	}

	// 确保输出目录存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			fmt.Printf("创建输出目录失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 构建完整的文件路径
	privateKeyPath := filepath.Join(outputDir, privateKey)
	publicKeyPath := filepath.Join(outputDir, publicKey)

	// 生成SM2密钥对并保存到文件
	fmt.Println("正在生成SM2密钥对...")
	err := sm2.GenerateAndSaveKeyPair(privateKeyPath, publicKeyPath)
	if err != nil {
		fmt.Printf("密钥生成失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("SM2密钥对生成成功:\n")
	fmt.Printf("私钥已保存到: %s\n", privateKeyPath)
	fmt.Printf("公钥已保存到: %s\n", publicKeyPath)
	fmt.Println("\n重要提示: 请安全保管私钥，并将公钥分发给需要验证签名的客户端。")
}
