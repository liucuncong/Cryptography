package main

import (
	"net"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"bytes"
	"encoding/hex"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
)

// 1.通过UDP通信，在服务器端生成一个rsa秘钥对
// 2.服务器端将公钥发送给客户端
// 3.在客户端生成一个对称加密的秘钥
// 4.在客户端使用公钥对对称加密的秘钥加密，发送给服务端
// 5.服务端接收对称加密的秘钥，使用私钥解密
// 6.使用对称加密的方式通信

/*
	第一步：客户端主动连接服务器，客户端给服务器发送消息 -> 打个招呼
		--- 服务器得到了客户端的地址信息
		--- 服务器生成秘钥对
		--- 将公钥发送给客户端
		--- 客户端将公钥解析出来
	第二步：
		--- 在客户端生成对称加密的秘钥
		--- 在客户端使用得到的rsa公钥对秘钥进行加密
		--- 将加密之后的秘钥发送给服务器
		--- 服务器接收这个加密之后的秘钥，用私钥进行解密，得到对称加密的秘钥
	第三步：
		--- 数据通信，使用对称加密的秘钥对数据进行加密
 */
func main()  {
	// 1.构造服务器地址信息
	udpAddr,err := net.ResolveUDPAddr("udp","127.0.0.1:8080")
	if err != nil {
		panic(err)
	}
	// 2.创建监听连接
	udpConn,err := net.ListenUDP("udp",udpAddr)
	defer udpConn.Close()
	if err != nil {
		panic(err)
	}
	count := 0
	length := 0
	data := make([]byte,4096)
	var aesKey []byte
	var privateKey *rsa.PrivateKey
	// 通信
	for  {
		count++
		// 接收数据
		// 第一次客户端向服务器打招呼
		n,caddr,err := udpConn.ReadFromUDP(data)
		if err != nil {
			panic(err)
		}
		length = n
		if count == 1 {
			// 1.生成秘钥对
			privateKey,err = rsa.GenerateKey(rand.Reader,1024)
			if err != nil {
				panic(err)
			}
			// 2.取出公钥
			publicKey := privateKey.PublicKey
			// 3. 使用x509格式化公钥
			pubText,err := x509.MarshalPKIXPublicKey(&publicKey)
			if err != nil {
				panic(err)
			}
			// 4.创建pem block结构体
			block := pem.Block{
				Type:"rsa publicKey",
				Bytes:pubText,
			}
			// 5.pem编码
			var buf bytes.Buffer
			pem.Encode(&buf,&block)  // 得到base64编码
			// 6.将数据发送给客户端
			_,err = udpConn.WriteToUDP(buf.Bytes(),caddr)
			if err != nil {
				panic(err)
			}
		}
		// 第二次，将接收到的数据中的秘钥解析出来
		if count == 2 {
			// 1.base64数据解码
			text,err := hex.DecodeString(string(data[:length]))
			if err != nil {
				panic(err)
			}
			// 2.私钥解密数据
			aesKey,err = rsa.DecryptPKCS1v15(rand.Reader,privateKey,text)
			if err != nil {
				panic(err)
			}
			fmt.Printf("对称加密的秘钥:%s\n",string(aesKey))
			// 3.回复数据
			udpConn.WriteToUDP([]byte("私钥接收完毕..."),caddr)
		}
		if count > 2{
			// 1.创建aes接口
			block,err := aes.NewCipher(aesKey)
			if err != nil {
				panic(err)
			}
			// 2.创建ctr分组模式接口
			stream := cipher.NewCTR(block,aesKey)
			cipherText,err := hex.DecodeString(string(data[:length]))
			if err != nil {
				panic(err)
			}
			plainText := make([]byte,len(cipherText))
			stream.XORKeyStream(plainText,cipherText)
			fmt.Printf("接收并解析出的数据：%s\n",string(plainText))
			udpConn.WriteToUDP([]byte("加密数据接收完毕.."),caddr)
		}

	}
}
