package main

import (
		"crypto/elliptic"
	"crypto/rand"
	"crypto/ecdsa"
		"log"
	"crypto/x509"
	"encoding/pem"
	"os"
	"crypto/sha256"
	"fmt"
	"math/big"
)
// 生成秘钥对
func GenerateEccKey2()  {
	privateKey,err := ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	derTxt,err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Panic(err)
	}
	block := pem.Block{
		Type:"privateKey",
		Bytes:derTxt,
	}
	f,err := os.Create("eccPri.pem")
	if err != nil {
		log.Panic(err)
	}
	defer f.Close()
	pem.Encode(f,&block)
	// ===========生成公钥============
	publicKey := privateKey.PublicKey
	detex,err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		log.Panic(err)
	}
	block2 := pem.Block{
		Type:"eccPub",
		Bytes:detex,
	}
	f2,err := os.Create("eccPub.pem")
	if err != nil {
		log.Panic(err)
	}
	defer f2.Close()
	pem.Encode(f2,&block2)

}
// 私钥签名
func EccSignature2(plainTxt []byte,privateFile string) (rText,sText []byte) {
	// 1.打开私钥文件，将内容读出来
	file,err := os.Open(privateFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// 2.将私钥文件内容读出来
	fileInfo,err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	_,err = file.Read(buf)
	if err != nil {
		panic(err)
	}
	// 3.pem解码
	block,_ := pem.Decode(buf)
	derTxt := block.Bytes
	privateKey,err := x509.ParseECPrivateKey(derTxt)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(plainTxt)
	r,s,err := ecdsa.Sign(rand.Reader,privateKey,hash[:])
	if err != nil {
		panic(err)
	}

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
// 签名验证
func EccVerify2(plainText,rText,sText []byte,publickeyFile string) bool {
	// 1.打开私钥文件，将内容读出来
	file,err := os.Open(publickeyFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// 2.将私钥文件内容读出来
	fileInfo,err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	_,err = file.Read(buf)
	if err != nil {
		panic(err)
	}
	// 3.pem解码
	block,_ := pem.Decode(buf)
	derTxt := block.Bytes
	// 4.x509解码
	pubInterface,err := x509.ParsePKIXPublicKey(derTxt)
	if err != nil {
		panic(err)
	}
	punKey := pubInterface.(*ecdsa.PublicKey)
	// 5.验签
	hash := sha256.Sum256(plainText)
	var r,s big.Int
	err = r.UnmarshalText(rText)
	if err != nil {
		panic(err)
	}

	err = s.UnmarshalText(sText)
	if err != nil {
		panic(err)
	}
	b := ecdsa.Verify(punKey,hash[:],&r,&s)
	return b
}

func main()  {
	plainTxt := []byte("还是离开花了快好了")
	GenerateEccKey2()
	rText,sText := EccSignature2(plainTxt,"eccPri.pem")
	b := EccVerify2(plainTxt,rText,sText,"eccPub.pem")
	fmt.Println(b)
}
