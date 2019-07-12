package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"crypto/sha1"
	"math/big"
	"fmt"
)

// 生成秘钥对
func GenerateEccKey()  {
	// 1.使用ecdsa生成秘钥对
	privateKey,err := ecdsa.GenerateKey(elliptic.P521(),rand.Reader)
	if err != nil {
		panic(err)
	}
	// 2.将私钥写入磁盘
	// -使用x509进行序列化
	derText,err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	// 3.将得到的切片字符串放到pem.Block结构体中
	block := pem.Block{
		Type:"ecdsa privateKey",
		Bytes:derText,
	}
	// 4.pem编码
	f,err := os.Create("eccPrivateKey.pem")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pem.Encode(f,&block)

	// ==========生成公钥===================
	// 1.从私钥取出公钥
	publicKey := privateKey.PublicKey
	// 2.使用x509进行序列化
	derText2,err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	// 3.将得到的字符切片放入pem.Block结构体中
	block2 := pem.Block{
		Type:"ecdsa publicKey",
		Bytes:derText2,
	}
	// 4.pem编码
	f2,err := os.Create("eccPublicKey.pem")
	if err != nil {
		panic(err)
	}
	defer f2.Close()
	pem.Encode(f2,&block2)
}

// ECC签名 - 私钥
func EccSignature(plainText []byte,privateFile string) (rText,sText []byte) {
	// 1.打开私钥文件，将内容读出来
	file,err := os.Open(privateFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// 2.将私钥文件中的内容读取出来
	fileInfo,err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	file.Read(buf)
	// 2.使用pem进行数据解码
	block,_ := pem.Decode(buf)
	// 3.x509将数据解析成私钥结构体 --->得到私钥
	privateKey,err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 4.对原始数据进行哈希运算
	hashText := sha1.Sum(plainText)
	// 5.签名
	r,s,err := ecdsa.Sign(rand.Reader,privateKey,hashText[:])
	if err != nil {
		panic(err)
	}
	// 6.对r,s进行序列化  -> []byte
	rText,err = r.MarshalText()
	if err != nil {
		panic(err)
	}
	sText,err = s.MarshalText()
	if err != nil {
		panic(err)
	}
	return
}

// ecc签名认证
func EccVerify(plainText,rText,sText []byte,publickeyFile string) bool {
	// 1.打开公钥文件，将内容读出来
	file,err := os.Open(publickeyFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// 2.将私钥文件中的内容读取出来
	fileInfo,err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	file.Read(buf)
	// 2.使用pem进行数据解码
	block,_ := pem.Decode(buf)
	// 3.x509将数据解析成私钥结构体 --->得到私钥
	pubInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 4.类型断言
	publicKey := pubInterface.(*ecdsa.PublicKey)
	// 5.对原始数据进行哈希运算
	hashText := sha1.Sum(plainText)
	// 6.将rText,sText转换成int数据
	var r,s big.Int
	err = r.UnmarshalText(rText)
	if err != nil {
		panic(err)
	}
	err = s.UnmarshalText(sText)
	if err != nil {
		panic(err)
	}
	// 7.签名认证
	return ecdsa.Verify(publicKey,hashText[:],&r,&s)
}
func main()  {
	//GenerateEccKey()
	src := []byte("数字签名是一种将相当于现实世界中的盖章、签字的功能在计算机")
	rText,sText := EccSignature(src,"eccPrivateKey.pem")
	b := EccVerify(src,rText,sText,"eccPublicKey.pem")
	fmt.Println(b)
}
