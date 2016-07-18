//
//  ViewController1.m
//  各种加密手段
//
//  Created by 张国兵 on 16/7/15.
//  Copyright © 2016年 zhangguobing. All rights reserved.
//

#import "ViewController1.h"

@interface ViewController1 ()

@end

@implementation ViewController1

- (void)viewDidLoad {
    [super viewDidLoad];
    /**
     *  前面的东西太多了淡出创建一个vc来记录一些散碎知识点
     *  在加密过程中我们有一个初始化的过程用到了两个C中的函数，下面来介绍一下这两个函数。
     *   void bzero（void *s, int n）
     *   清零函数
     *   功能：置字节字符串s的前n个字节为零且包括‘\0’。　　说明：bzero无返回值，并且使用strings.h头文件，strings.h曾经是posix标准的一部分，但是在POSIX.1-2001标准里面，这些函数被标记为了遗留函数而不推荐使用。在POSIX.1-2008标准里已经没有这些函数了。推荐使用memset替代bzero。
     *   void *memset(void *s, int ch, size_t n)
     *   函数解释：将s中前n个字节替换为ch并返回s；　　memset:作用是在一段内存块中填充某个给定的值，它是对较大的结构体或数组进行清零操作的一种最快方法。
     *
     */
    
    /**
     *  苹果原生提供给我们的加密方法介绍
     *
         CCCryptorStatus CCCrypt(
         CCOperation op,
         CCAlgorithm alg,
         CCOptions options,
         const void *key,
         size_t keyLength,
         const void *iv,
         const void *dataIn,
         size_t dataInLength,
         void *dataOut,
         size_t dataOutAvailable,
         size_t *dataOutMoved
         )
     *1、CCOperation 一共就2中：一种表示加密、一种标示解密
         enum {
         kCCEncrypt = 0,
         kCCDecrypt,
         };
         typedef uint32_t CCOperation;
     *2、CCAlgorithm  加密的算法
     
         enum {
         kCCAlgorithmAES128 = 0,
         kCCAlgorithmAES = 0,
         kCCAlgorithmDES,
         kCCAlgorithm3DES,
         kCCAlgorithmCAST,
         kCCAlgorithmRC4,
         kCCAlgorithmRC2,
         kCCAlgorithmBlowfish
         };
         typedef uint32_t CCAlgorithm;
     *3、CCOptions 选择的模式
        Default is CBC.
        enum {
        kCCOptionCBCMode        = 0x0000,
        kCCOptionPKCS7Padding   = 0x0001,
        kCCOptionECBMode        = 0x0002
        这里要重点介绍一下模式的概念。
     模式从宏观上分两种理解：
     一种是加密模式，加密模式对于AES来说有五中模式：CBC，CFB，ECB，OFB，PCBC；不同的加密模式决定了加密的结果不一样
     一种是填充模式，填充模式对于AES来说支持的有三种：NoPadding，PKCS5Padding，ISO10126Padding不支持SSL3Padding
     *4、key 密钥
     *5、keyLength 密钥长度
     *6、iv 偏移向量CBC模式下的参数和密钥共同参与加密过程
     *7、dataIn 表示要加密/解密的数据。
     *8、dataInLength 表示要加密/解密的数据的长度。
     *9、dataOut 用于接收加密后/解密后的结果。
     *10、dataOutAvailable 表示加密后/解密后的数据的长度。
     *11、dataOutMoved 表示实际加密/解密的数据的长度。（因为有补齐）
     
};
     */
    /**
     *  补充知识点：
     *  DES和3DES
     *  3DES是DES加密算法的一种模式，它使用3条64位的密钥对数据进行三次加密。数据加密标准（DES）是美国的一种由来已久的加密标准，它使用对称密钥加密法。
     *　3DES（即Triple DES）是DES向AES过渡的加密算法（1999年，NIST将3-DES指定为过渡的加密标准），是DES的一个更安全的变形。它以DES为基本模块，通过组合分组方法设计出分组加密算法。
     
     *  3DES即是设计用来提供一种相对简单的方法，即通过增加DES的密钥长度来避免类似的攻击，而不是设计一种全新的块密码算法。
     *
     *
     *
     */

    
    
    
    
    
    
    
    
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
