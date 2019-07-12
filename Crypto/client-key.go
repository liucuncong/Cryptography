package main

import (
	"net"
	"crypto/rsa"
	"encoding/hex"
	"crypto/aes"
	"fmt"
	"encoding/pem"
	"crypto/x509"
	"crypto/md5"
	"crypto/rand"
	"crypto/cipher"
	"time"
)

func main()  {
	// 连接服务器
	conn,err := net.Dial("udp","127.0.0.1:8080")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// 循环发送数据
	count := 0
	var publicKey *rsa.PublicKey
	data := make([]byte,4096)
	// 生成对称加密的秘钥
	hvalue := md5.Sum([]byte("12345678"))  // 生成的为16字节的二进制
	hexText := hex.EncodeToString(hvalue[:])  // 通过base64编码方式转换成32字节的16进制的字符串
	aesKey := []byte(hexText)[:aes.BlockSize]  // aes.BlockSize就是16
	for  {
		count++
		if count == 1{
			// 1.第一次发送数据，给服务端打招呼
			conn.Write([]byte("服务器，你好。。。"))
			// 2.接收服务器数据
			n,err := conn.Read(data)
			if err != nil {
				panic(err)
			}
			// 3.pem解码
			fmt.Println(string(data[:n]))
			block,_ := pem.Decode(data[:n])
			// 4.x509解析出公钥
			pubInterence,err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				panic(err)
			}
			// 5.类型断言
			publicKey = pubInterence.(*rsa.PublicKey)
		}
		if count == 2 {
			// 1.使用公钥加密秘钥
			cipherText,err := rsa.EncryptPKCS1v15(rand.Reader,publicKey,aesKey)
			if err != nil {
				panic(err)
			}
			// 通过非对称加密得到的密文是一个二进制串，在网络传输过程中，不要传输二进制数据，可能会出错，把数据编码之后再传输，比如编码成16进制或base64格式
			conn.Write([]byte(hex.EncodeToString(cipherText)))
		}
		if count > 2{
			// 1.创建aes接口
			block,err := aes.NewCipher(aesKey)
			if err != nil {
				panic(err)
			}
			// 2.创建ctr分组模式接口
			text := []byte("你知道吗。这是一个对称加密通信")
			stream := cipher.NewCTR(block,aesKey)
			stream.XORKeyStream(text,text)
			conn.Write([]byte(hex.EncodeToString(text)))
		}
		if count > 1{
			n,_ := conn.Read(data)
			fmt.Printf("接收到的数据：%s\n",string(data[:n]))

		}
		time.Sleep(time.Second)

	}

}
