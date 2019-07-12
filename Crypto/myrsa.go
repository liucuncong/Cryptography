package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	)

// 生成私钥和公钥
func GenerateKey(keySize int)  {
	// 1.使用rsa中的GenerateKey方法生成私钥
	privateKey,err := rsa.GenerateKey(rand.Reader,keySize)
	if err != nil {
		panic(err)
	}
	// 2.通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derTxt := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3.组织一个pem.Block
	block := pem.Block{
		Type:"rsa privateKey",  // 这地方写什么都行，一般用来描述block存的是什么
		Bytes:derTxt,
	}
	// 4.pem编码
	f,err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pem.Encode(f,&block)

	// ==========公钥=============
	// 1.从得到的私钥对象中将公钥信息取出
	publicKey := privateKey.PublicKey
	// 2.通过x509标准将得到 的rsa公钥序列化为字符串
	derPub,err := x509.MarshalPKIXPublicKey(&publicKey)  //注意，这里要传指针
	if err != nil {
		panic(err)
	}
	// 3.将公钥字符串设置到pem格式块中
	block2 := pem.Block{
		Type:"rsa publicKey",
		Bytes:derPub,
	}
	// 4.pem编码
	f,err = os.Create("publicKey.pem")
	defer f.Close()
	if err != nil {
		panic(err)
	}
	pem.Encode(f,&block2)

}

// 生成公钥和私钥2
func GenerateKey2(keySize int)  {
	// 1.生成私钥
	privateKey,err := rsa.GenerateKey(rand.Reader,keySize)
	if err != nil {
		panic(err)
	}
	// 2.通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3.组织一个pem.block
	block := pem.Block{
		Type:"rsa privateKey",
		Bytes:derText,
	}
	// 4.编码
	f,err := os.Create("private2.pem")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pem.Encode(f,&block)

	//  ==============生成公钥=============
	// 1.取出公钥
	publickey := privateKey.PublicKey
	// 2.通过x509标准对公钥进行序列化
	derPub,err := x509.MarshalPKIXPublicKey(&publickey)
	if err != nil {
		panic(err)
	}
	// 3.组织一个pem.block
	block2 := pem.Block{
		Type:"rsa publicKey",
		Bytes:derPub,
	}
	// 4.pem编码
	f,err = os.Create("public")
	if err != nil {
		panic(err)
	}
	pem.Encode(f,&block2)

}


// 公钥加密
func RSAEncrypt(plainText []byte,fileName string) []byte {
	// 1.将公钥文件中的公钥读出, 得到使用pem编码的字符串
	f,err :=os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo,err := f.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	f.Read(buf)

	// 2.将得到的字符串解码
	block,_ := pem.Decode(buf)
	// 3.使用x509将编码之后的公钥解析出来
	pubInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey := pubInterface.(*rsa.PublicKey)
	if err != nil {
		panic(err)
	}
	// 4.使用得到的公钥通过rsa进行数据加密
	cipher,err := rsa.EncryptPKCS1v15(rand.Reader,publicKey,plainText)
	if err != nil {
		panic(err)
	}
	return cipher
}

// 公钥加密2
func RSAEncrypt2(plainText []byte,fileName string) []byte {
	// 1.打开共要文件
	f,err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// 2.获取文件信息
	fileInfo,err := f.Stat()
	if err != nil {
		panic(err)
	}
	// 3.创建公钥文件缓存区,读取文件
	buf := make([]byte,fileInfo.Size())
	f.Read(buf)
	// 4.pem解码
	b,_ := pem.Decode(buf)
	// 5.x509标准解码
	pubInterface,err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	// 6.类型断言，获取公钥
	pub := pubInterface.(*rsa.PublicKey)
	// 7.公钥加密
	cipherText,err :=rsa.EncryptPKCS1v15(rand.Reader,pub,plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// 私钥解密
func RSADecrypt(cipher []byte,fileName string) []byte {
	// 1.将私钥文件中的私钥读出, 得到使用pem编码的字符串
	f,err :=os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo,err := f.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte,fileInfo.Size())
	f.Read(buf)
	// 2.将得到的字符串解码
	block,_ := pem.Decode(buf)
	// 3.使用x509将编码之后的私钥解析出来
	privateKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 4.使用得到的私钥通过rsa进行数据解密
	plainText,err := rsa.DecryptPKCS1v15(rand.Reader,privateKey,cipher)
	if err != nil {
		panic(err)
	}
	return plainText
}

// 私钥解密2
func RSADecrypt2(cipherText []byte,fileName string) []byte {
	// 1.打开文件
	f,err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// 2.获取文件信息
	fileInfo,err := f.Stat()
	if err != nil {
		panic(err)
	}
	// 3.把私钥文件读入缓冲区
	buf := make([]byte,fileInfo.Size())
	f.Read(buf)
	// 4.pem解码
	block,_ := pem.Decode(buf)
	// 5.x509解码
	privatekey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 6.私钥解密
	plainText,err := rsa.DecryptPKCS1v15(rand.Reader,privatekey,cipherText)
	if err != nil {
		panic(err)
	}
	return plainText
}

func main()  {
	//GenerateKey(1024)

	//plainText := []byte("刚好就花了好多了，福晶科技老库房管理规范")  // 当需要加密的文件内容太长时，公钥也需要更长
	//cipherText := RSAEncrypt(plainText,"publicKey.pem")
	//plainText2 := RSADecrypt(cipherText,"private.pem")
	//fmt.Println(string(plainText2))



}
