//
//  ViewController.m
//  各种加密手段
//
//  Created by 张国兵 on 15/9/18.
//  Copyright (c) 2015年 zhangguobing. All rights reserved.
//

#import "ViewController.h"
#import "GBEncodeTool.h"

#define AES_KEY @"D5B6D8584F94B434"
#define AES_IV @"205681D89D731A8E"
#define  PUBLIC_APP_KEY @"helloWord"
#define PUBLICK_KEY @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEChqe80lJLTTkJD3X3Lyd7Fj+\nzuOhDZkjuLNPog3YR20e5JcrdqI9IFzNbACY/GQVhbnbvBqYgyql8DfPCGXpn0+X\nNSxELIUw9Vh32QuhGNr3/TBpechrVeVpFPLwyaYNEk1CawgHCeQqf5uaqiaoBDOT\nqeox88Lc1ld7MsfggQIDAQAB\n-----END PUBLIC KEY-----"
#define PRIVATE_KEY @"-----BEGIN RSA PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMQKGp7zSUktNOQk\nPdfcvJ3sWP7O46ENmSO4s0+iDdhHbR7klyt2oj0gXM1sAJj8ZBWFudu8GpiDKqXw\nN88IZemfT5c1LEQshTD1WHfZC6EY2vf9MGl5yGtV5WkU8vDJpg0STUJrCAcJ5Cp/\nm5qqJqgEM5Op6jHzwtzWV3syx+CBAgMBAAECgYEApSzqPzE3d3uqi+tpXB71oY5J\ncfB55PIjLPDrzFX7mlacP6JVKN7dVemVp9OvMTe/UE8LSXRVaFlkLsqXC07FJjhu\nwFXHPdnUf5sanLLdnzt3Mc8vMgUamGJl+er0wdzxM1kPTh0Tmq+DSlu5TlopAHd5\nIqF3DYiORIen3xIwp0ECQQDj6GFaXWzWAu5oUq6j1msTRV3mRZnx8Amxt1ssYM0+\nJLf6QYmpkGFqiQOhHkMgVUwRFqJC8A9EVR1eqabcBXbpAkEA3DQfLVr94vsIWL6+\nVrFcPJW9Xk28CNY6Xnvkin815o2Q0JUHIIIod1eVKCiYDUzZAYAsW0gefJ49sJ4Y\niRJN2QJAKuxeQX2s/NWKfz1rRNIiUnvTBoZ/SvCxcrYcxsvoe9bAi7KCMdxObJkn\nhNXFQLav39wKbV73ESCSqnx7P58L2QJABmhR2+0A5EDvvj1WpokkqPKmfv7+ELfD\nHQq33LvU4q+N3jPn8C85ZDedNHzx57kru1pyb/mKQZANNX10M1DgCQJBAMKn0lEx\nQH2GrkjeWgGVpPZkp0YC+ztNjaUMJmY5g0INUlDgqTWFNftxe8ROvt7JtUvlgtKC\nXdXQrKaEnpebeUQ=\n-----END RSA PRIVATE KEY-----"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    /**常用的加密手段(适合新手理论加实战)
     *1、首先我们在用一个东西的时候我们不能单纯的为了用而用我们要对他有所了解，简单介绍一下加密
     *
     2、简单的概念
     
     明文：加密前的信息
     密文：机密后的信息
     加密算法：加密或解密的算法
     密钥：算法使用的钥匙（读作miyao，正确应该是miyue，但是大家都读miyao）
     *
     简单的例子
     
     将123456每位数字都加1后得到234567，
     其中123456就是明文，234567就是密文，加密密钥就是1，加密算法是每位加
     
     * 3、加密算法种类
     按照加密的方式我们可以将加密算法大体分成一下三种：
     *      对称加密算法（加密和解密算法是对称的可能有点抽象你可以理解成同一把钥匙）
     *      非对称加密算法（加密和解密算法是非对称的可以理解成加密的时候是一把钥匙解密的时候是一把钥匙，典型的就是rsa公钥和私钥）
     *      经典哈希算法（哈希算法是一种散列算法，有个特殊性是它是不可逆只能通过穷举法超大量的计算才可能算出，一般几率很小，还有就是你同一段的明文两次加密出来的结果是不一样的）
     *
     * 4、算法举例
     对称加密算法：DES算法，3DES算法，TDEA算法，Blowfish算法，RC5算法，IDEA算法，AES算法。
     非对称加密算法：RSA、Elgamal、背包算法、Rabin、D-H、ECC。
     经典的哈希算法：MD2、MD4、MD5 和 SHA-1（目的是将任意长输入通过算法变为固定长输出，且保证输入变化一点输出都不同，且不能反向解密）
     * 今天我们来说一下我们在来发中常用的算法暂时只讲：MD5、Base64、sha、AES、rsa
     * 补充：RSA加密算法中比较重要的加密算法
     *  非对称加密算法可能是世界上最重要的算法，它是当今电子商务等领域的基石。简而言之，非对称加密就是指加密公钥和解密密钥是不同的，而且加密公钥和解密密钥是成对出现。非对称加密又叫公钥加密，也就是说成对的密钥，其中一个是对外公开的，所有人都可以获得，人们称之为公钥；而与之相对应的称为私钥，只有这对密钥的生成者才能拥有。
     *  对于一个私钥，有且只有一个与之对应的公钥。公钥公开给任何人，私钥通常是只有生成者拥有。公/私钥通常是1024位或者2048位，越长安全系数越高，但是解密越困难。尽管拿到了公钥，如果没有私钥，要想解密那几乎是不可能的，至少现在在世界上还没有人公开出来说成功解密的（要是你能写出解密的算法你可以去申请专利权了
     \(^o^)/~）。
     *  总结：公钥和密钥成对出现，其中公钥负责加密 ，私钥负责解密
     *  补充：AES
     *  1. ECB(Electronic Code Book电子密码本)模式
     *     ECB模式是最早采用和最简单的模式，它将加密的数据分成若干组，每组的大小跟加密密钥长度相同，然后每组都用相同的密钥进行加密。
     优点:   1.简单；   2.有利于并行计算；  3.误差不会被扩散；
     缺点:   1.不能隐藏明文的模式；  2.可能对明文进行主动攻击；
     因此，此模式适于加密小消息。
     *  2. CBC(Cipher Block Chaining，加密块链)模式
     优点：  不容易主动攻击,安全性好于ECB,适合传输长度长的报文,是SSL、IPSec的标准。
     缺点：  1.不利于并行计算；  2.误差传递；  3.需要初始化向量IV
     3. CFB(Cipher FeedBack Mode，加密反馈)模式
     优点：1.隐藏了明文模式;  2.分组密码转化为流模式;  3.可以及时加密传送小于分组的数据;
     缺点:  1.不利于并行计算;  2.误差传送：一个明文单元损坏影响多个单元;  3.唯一的IV;
     4. OFB(Output FeedBack，输出反馈)模式
     优点:  1.隐藏了明文模式;  2.分组密码转化为流模式;  3.可以及时加密传送小于分组的数据;
     缺点:  1.不利于并行计算;  2.对明文的主动攻击是可能的;  3.误差传送：一个明文单元损坏影响多个单元;
     *
     *    补充说明：
     今天跟一个网友交流技术的时候发现他给我的一个字符串我解析不出来，搞了好久也
     没发现什么问题，当我们再回过头来看这个字符串的时候发现这个字符串很特别不是
     一般的字母和数字的随机组合，而是一些16进制的字符组成的字符串，对于这样的字
     符串我们在处理的时候一定要注意，要先把这样的字符串由16进制转化成二进制再在
     解析后的二进制的基础上进行操作。事实证明我们的处理方式是对的，并且我对于这
     种情况进行了封装，方便大家的使用。
     *
     */
    
    
    NSString*test=@"123";
    NSString*md5_16=[GBEncodeTool getMd5_16Bit_String:test isUppercase:YES];
    NSLog(@"md5_16-->%@",md5_16);
    NSString*md5_32=[GBEncodeTool getMd5_32Bit_String:test isUppercase:YES];
    NSLog(@"md5_32-->%@",md5_32);
    NSString*sha1=[GBEncodeTool getSha1String:test isUppercase:YES];
    NSLog(@"sha1-->%@",sha1);
    NSString*sha256=[GBEncodeTool getSha256String:test isUppercase:YES];
    NSLog(@"sha256-->%@",sha256);
    NSString*sha384=[GBEncodeTool getSha384String:test isUppercase:YES];
    NSLog(@"sha384-->%@",sha384);
    NSString*sha512=[GBEncodeTool getSha512String:test isUppercase:YES];
    NSLog(@"sha512-->%@",sha512);
    NSString*encodeBase64=[GBEncodeTool encodeBase64String:test];
    NSLog(@"base64加密-->%@",encodeBase64);
    NSString*decodeBase64=[GBEncodeTool decodeBase64String:test];
    NSLog(@"base64解密-->%@",decodeBase64);
    NSString*AES=[GBEncodeTool AES256Encrypt:test WithKey:PUBLIC_APP_KEY];
    NSLog(@"AES加密->%@",AES);
    NSString*AESDecode=[GBEncodeTool AES256Decrypt:AES WithKey:PUBLIC_APP_KEY];
    
    NSLog(@"AES解密-->%@",AESDecode);
    /** 明文 */
    NSString*publicStr=@"E1F2629EE05D8BDEED5033A2C9F9664B";
    
    /** 密文 */
    NSString*secretStr= @"17D032AB2C1186F2001B1A6385EF9720B116910DB19999171708A2D60E31126E5FC3A1186C82BF26E0E094371A9E1517";
    NSString*hexPublickStr=[GBEncodeTool AES128HexDecrypt:secretStr Key:AES_KEY IV:AES_IV];
    NSLog(@"16进制明文-->%@",hexPublickStr);
    
    NSString*AESCBC128Encrypt=[GBEncodeTool AES128Encrypt:publicStr Key:AES_KEY IV:AES_IV];
    NSString*AESCBC128Decrypt=[GBEncodeTool AES128Decrypt:AESCBC128Encrypt Key:AES_KEY IV:AES_IV];
    NSLog(@"AES128->CBC模式下的加密%@",AESCBC128Encrypt);
    NSLog(@"AES128->CBC模式下的解密%@",AESCBC128Decrypt);
    
    /**
     * 这种方式感觉不是很方便主要是为了公钥和密钥的周期性检测，不习惯的可以直接跳过
     * 通过公钥和私钥文件加密和解密
     */
    NSString*privatePath=[[NSBundle mainBundle]pathForResource:@"private_key.p12" ofType:nil];
    NSString*publickPath=[[NSBundle mainBundle]pathForResource:@"public_key.der" ofType:nil];
    [GBEncodeTool configPrivateKey:privatePath Password:@"997756128"];
    [GBEncodeTool configPublickKey:publickPath];
    NSString*RSAEncode=[GBEncodeTool rsaEncryptText:test];
    NSLog(@"rsa加密-->%@",RSAEncode);
    NSString*RSADecode=[GBEncodeTool rsaDecryptText:test];
    NSLog(@"rsa解密-->%@",RSADecode);
    /**直接通过公钥和私钥加密和解密 */
    NSString*rsaEncode=[GBEncodeTool rsaEncryptString:test publicKey:PUBLICK_KEY];
    NSLog(@"RSA加密-->%@",rsaEncode);
    NSString*rsaDecode=[GBEncodeTool rsaDecryptString:rsaEncode privateKey:PRIVATE_KEY];
    NSLog(@"RSA解密-->%@",rsaDecode);
    
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
