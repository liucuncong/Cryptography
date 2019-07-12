package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// 生成消息认证码
func GenerateHmac(plainText,key []byte) []byte {
	// 1.创建哈希接口，需要指定使用的哈希算法和秘钥
	myHash := hmac.New(sha256.New,key)
	// 2.添加数据
	myHash.Write(plainText)
	// 3.计算散列值
	hashText := myHash.Sum(nil)
	return hashText
}

// 验证消息认证码
func VerifyHmac(plainText,key,hashText []byte) bool {
	// 1.创建哈希接口，需要指定使用的哈希算法和秘钥
	myHash := hmac.New(sha256.New,key)
	// 2.添加数据
	myHash.Write(plainText)
	// 3.计算散列值
	hashText1 := myHash.Sum(nil)
	// 4.比较散列值
	return hmac.Equal(hashText,hashText1)
}

func main()  {
	src := []byte("小窗口了解了多少；是是的丰富接口连接费")
	key := []byte("hhsddsds")
	hmac1 := GenerateHmac(src,key)
	b1 := VerifyHmac(src,key,hmac1)
	fmt.Printf("校验结果：%t\n",b1)
}
