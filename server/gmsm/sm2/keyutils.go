/*
Copyright 2023. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

// SM2密钥序列化结构
type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier
	PublicKey     asn1.BitString
}

// SM2公钥序列化结构
type sm2PublicKey struct {
	X, Y *big.Int
}

// 国密曲线OID - SM2椭圆曲线的OID
var oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

// GenerateAndSaveKeyPair 生成SM2密钥对并保存到指定文件
func GenerateAndSaveKeyPair(privateKeyPath, publicKeyPath string) error {
	// 生成SM2私钥
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("生成SM2密钥对失败: %v", err)
	}

	// 保存私钥
	err = SavePrivateKeyToPEM(priv, privateKeyPath)
	if err != nil {
		return fmt.Errorf("保存SM2私钥失败: %v", err)
	}

	// 保存公钥
	err = SavePublicKeyToPEM(&priv.PublicKey, publicKeyPath)
	if err != nil {
		return fmt.Errorf("保存SM2公钥失败: %v", err)
	}

	return nil
}

// SavePrivateKeyToPEM 将SM2私钥保存为PEM格式文件
func SavePrivateKeyToPEM(priv *PrivateKey, filePath string) error {
	// 将私钥序列化
	privateKeyBytes, err := MarshalSM2PrivateKey(priv)
	if err != nil {
		return err
	}

	// 创建PEM块
	block := &pem.Block{
		Type:  "SM2 PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// 写入文件
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

// SavePublicKeyToPEM 将SM2公钥保存为PEM格式文件
func SavePublicKeyToPEM(pub *PublicKey, filePath string) error {
	// 将公钥序列化
	pubKeyBytes, err := MarshalSM2PublicKey(pub)
	if err != nil {
		return err
	}

	// 创建PEM块
	block := &pem.Block{
		Type:  "SM2 PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// 写入文件
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

// LoadPrivateKeyFromPEM 从PEM文件加载SM2私钥
func LoadPrivateKeyFromPEM(filePath string) (*PrivateKey, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 解析PEM块
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "SM2 PRIVATE KEY" {
		return nil, errors.New("无效的SM2私钥PEM文件")
	}

	// 解析私钥
	return ParseSM2PrivateKey(block.Bytes)
}

// LoadPublicKeyFromPEM 从PEM文件加载SM2公钥
func LoadPublicKeyFromPEM(filePath string) (*PublicKey, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 解析PEM块
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "SM2 PUBLIC KEY" {
		return nil, errors.New("无效的SM2公钥PEM文件")
	}

	// 解析公钥
	return ParseSM2PublicKey(block.Bytes)
}

// MarshalSM2PrivateKey 将SM2私钥序列化为ASN.1 DER编码
func MarshalSM2PrivateKey(key *PrivateKey) ([]byte, error) {
	// 创建公钥的ASN.1 DER编码
	publicKeyBytes, err := MarshalSM2PublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	privateKey := sm2PrivateKey{
		Version:       1,
		PrivateKey:    key.D.Bytes(),
		NamedCurveOID: oidNamedCurveP256SM2,
		PublicKey:     asn1.BitString{Bytes: publicKeyBytes},
	}

	return asn1.Marshal(privateKey)
}

// MarshalSM2PublicKey 将SM2公钥序列化为ASN.1 DER编码
func MarshalSM2PublicKey(key *PublicKey) ([]byte, error) {
	pubKey := sm2PublicKey{
		X: key.X,
		Y: key.Y,
	}

	return asn1.Marshal(pubKey)
}

// ParseSM2PrivateKey 从ASN.1 DER编码解析SM2私钥
func ParseSM2PrivateKey(derBytes []byte) (*PrivateKey, error) {
	var privKey sm2PrivateKey
	_, err := asn1.Unmarshal(derBytes, &privKey)
	if err != nil {
		return nil, err
	}

	// 创建SM2私钥
	curve := P256Sm2()
	priv := new(PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(privKey.PrivateKey)

	// 从存储的公钥解析X和Y坐标
	pub, err := ParseSM2PublicKey(privKey.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	priv.PublicKey.X = pub.X
	priv.PublicKey.Y = pub.Y

	return priv, nil
}

// ParseSM2PublicKey 从ASN.1 DER编码解析SM2公钥
func ParseSM2PublicKey(derBytes []byte) (*PublicKey, error) {
	var pubKey sm2PublicKey
	_, err := asn1.Unmarshal(derBytes, &pubKey)
	if err != nil {
		return nil, err
	}

	// 创建SM2公钥
	curve := P256Sm2()
	pub := new(PublicKey)
	pub.Curve = curve
	pub.X = pubKey.X
	pub.Y = pubKey.Y

	return pub, nil
}

// GenerateKeyWithFixedRandom 使用固定的随机数据生成可重复的密钥（仅用于测试）
func GenerateKeyWithFixedRandom(random io.Reader) (*PrivateKey, error) {
	return GenerateKey(random)
}
