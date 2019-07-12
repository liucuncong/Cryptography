package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// sha256加密
func myHash()  {
	// 1.创建hash接口对象
	myHash := sha256.New()
	// 2.添加数据
	plainText := []byte("刚好就花了好多了，福晶科技老库房管理规范")
	myHash.Write(plainText)
	myHash.Write(plainText)
	myHash.Write(plainText)
	// 3.计算结果
	res := myHash.Sum(nil)  // 二进制数据,32字节
	// 4.格式化为16进制
	myStr := hex.EncodeToString(res)  // 64字节
	fmt.Println(myStr)
}

func main()  {
	myHash()
}

