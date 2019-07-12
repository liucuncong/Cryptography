package main

import (
	"os"
	"encoding/pem"
	"crypto/x509"
		"crypto/sha512"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"fmt"
)

// RSA签名 - 私钥
func SignatureRSA(plainText []byte,fileName string) []byte {
	// 1.打开磁盘的私钥文件
	file,err := os.Open(fileName)
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
	// 3.使用pem对数据解码,得到pem.Block结构体变量
	block,_ := pem.Decode(buf)
	// 4.x509将数据解析成私钥结构体 --->得到私钥
	privateKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 5.创建一个哈希对象，mds/sha1
	mySha512 := sha512.New()
	// 6.给哈希对象添加数据
	mySha512.Write(plainText)
	// 7.计算哈希值
	hash := mySha512.Sum(nil)
	// 8.使用rsa中的函数对散列值进行签名
	sigText,err := rsa.SignPKCS1v15(rand.Reader,privateKey,crypto.SHA512,hash)
	if err != nil {
		panic(err)
	}
	return sigText
}

// RSA签名认证
func VerifyRSA(plainText,sigText []byte,fileName string) bool {
	// 1.打开公钥文件
	f,err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// 2.将文件内容读出
	fileInfo,err := f.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	f.Read(buf)
	// 3.使用pem对数据解码,得到pem.Block结构体变量
	block,_ := pem.Decode(buf)
	// 4.x509将数据解析
	pubInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 5.类型断言,获取公钥
	publicKey := pubInterface.(*rsa.PublicKey)
	// 6.对原始数据进行哈希运算
	hashText := sha512.Sum512(plainText)

	// 7.签名认证
	err = rsa.VerifyPKCS1v15(publicKey,crypto.SHA512,hashText[:],sigText)
	if err == nil {
		return true
	}
	return false
}
func main()  {
	plainText := []byte("数字签名是一种将相当于现实世界中的盖章、签字的功能在计算机")
	sigText := SignatureRSA(plainText,"private.pem")
	bl := VerifyRSA(plainText,sigText,"publicKey.pem")
	fmt.Println(bl)

}
