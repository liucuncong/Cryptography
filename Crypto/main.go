package main

import "fmt"

// 测试文件
func main()  {
	fmt.Println("des 加解密。。。cbc模式。。")
	key := []byte("jddj1254")
	src := []byte("我们在上一章中介绍的DES和AES都属于分组密码，它们只能加密固定长度的明文。")
	cipherText := desEncrypt(src,key)
	plainText := desDecrypt(cipherText,key)
	fmt.Println("解密后的数据",string(plainText))

	fmt.Println("aes加解密。。。ctr模式。。。")
	key1 := []byte("jddj125412345678")
	cipherText = aesEncrypt(src,key1)
	plainText = aesDecrypt(cipherText,key1)
	fmt.Println(string(plainText))
}

