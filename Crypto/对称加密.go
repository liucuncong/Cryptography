package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"crypto/aes"
)

// des的CBC加密
// 编写填充函数，如果最后一个分组的字节数不够，填充
// 如果最后一个分组的字节数刚好，添加一个新的分组
// 填充的字节的值 == 缺少的字节的数

func paddingLastGroup(plainText []byte,blockSize int) []byte {
	// 1.求出最后一组中需要填充的的字节数
	padNum := blockSize - len(plainText)%blockSize
	// 2.创建新的切片，长度=padNum，每个字节值 byte(padNum)
	char := []byte{byte(padNum)}  //初始化一个切片，切片长度为1
	// 切片创建，并初始化
	newChar := bytes.Repeat(char,padNum)
	// 3.newChar切片追加到原始明文的后面
	plainText = append(plainText,newChar...)
	return plainText
}

// 去掉填充的数据
func unPaddingLastGroup(plainText []byte) []byte {
	// 1.拿去切片中的最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1]
	number := int(lastChar)  //尾部填充的字节个数
	// 2.去掉填充的数据
	plainText = plainText[:length-number]
	return plainText
}

// des加密
func desEncrypt(plainText []byte,key []byte) []byte {
	// 1.创建一个底层使用des的密码接口
	block,err := des.NewCipher(key)
	if err != nil {
		fmt.Println("创建一个底层使用des的密码接口错误",err)
		return nil
	}
	// 2.明文填充
	plainText = paddingLastGroup(plainText,block.BlockSize())
	// 3.创建一个cbc模式的分组接口
	iv := []byte("12345678")
	blockModel := cipher.NewCBCEncrypter(block,iv)
	// 4.加密
	cipherText := make([]byte,len(plainText))
	blockModel.CryptBlocks(cipherText,plainText)
	//blockModel.CryptBlocks(cipherText,plainText) //也可以这么写，因为这两个参数可以指向同一内存地址，加密后的把前面的给覆盖了

	return cipherText
}

// des 解密
func desDecrypt(cipherText []byte,key []byte) []byte {
	// 1.创建一个底层使用des的密码接口
	block,err := des.NewCipher(key)
	if err != nil {
		fmt.Println("创建一个底层使用des的密码接口错误",err)
		return nil
	}
	// 2.创建一个使用cbc模式解密的接口
	iv := []byte("12345678")  // 初始化向量
	blockModel := cipher.NewCBCDecrypter(block,iv)
	// 3.解密
	plainText := make([]byte,len(cipherText))
	blockModel.CryptBlocks(plainText,cipherText)
	// 4.删除填充的尾部数据
	newPlainText := unPaddingLastGroup(plainText)
	return newPlainText
}

// aes 加密，分组模式为ctr
func aesEncrypt(plainText []byte,key []byte) []byte {
	// 1.创建一个底层使用aes的密码接口
	block,err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("创建一个底层使用aes的密码接口错误",err)
		return nil
	}

	// 2.创建一个ctr模式的分组接口
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block,iv)
	// 4.加密
	cipherText := make([]byte,len(plainText))
	stream.XORKeyStream(cipherText,plainText)
	return cipherText
}

// aes 解密，分组模式为ctr
func aesDecrypt(cipherText []byte,key []byte) []byte {
	// 1.创建一个底层使用des的密码接口
	block,err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("创建一个底层使用aes的密码接口错误",err)
		return nil
	}
	// 2.创建一个使用ctr模式解密的接口
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block,iv)
	// 3.解密
	plainText := make([]byte,len(cipherText))
	stream.XORKeyStream(plainText,cipherText)
	return plainText
}