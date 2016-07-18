//
//  ViewController.m
//  各种加密手段
//
//  Created by 张国兵 on 15/9/18.
//  Copyright (c) 2015年 zhangguobing. All rights reserved.
//

#import "ViewController.h"
#import "GBEncodeTool.h"
//(key和iv向量这里是16位的)
#define AES_KEY @"D5B6D8584F94B434"
#define AES_IV @"205681D89D731A8E"
#define DES_KEY @"D5B6D8584F94B434"
#define DES_IV @"205681D89D731A8E"
#define PUBLIC_APP_KEY @"helloWord"
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
     * 今天我们来说一下我们在来发中常用的算法暂时只讲：MD5、Base64、sha、AES、RSA
     * 补充：RSA加密算法中比较重要的加密算法
     *  非对称加密算法可能是世界上最重要的算法，它是当今电子商务等领域的基石。简而言之，非对称加密就是指加密公钥和解密密钥是不同的，而且加密公钥和解密密钥是成对出现。非对称加密又叫公钥加密，也就是说成对的密钥，其中一个是对外公开的，所有人都可以获得，人们称之为公钥；而与之相对应的称为私钥，只有这对密钥的生成者才能拥有。
     *  对于一个私钥，有且只有一个与之对应的公钥。公钥公开给任何人，私钥通常是只有生成者拥有。公/私钥通常是1024位或者2048位，越长安全系数越高，但是解密越困难。尽管拿到了公钥，如果没有私钥，要想解密那几乎是不可能的，至少现在在世界上还没有人公开出来说成功解密的（要是你能写出解密的算法你可以去申请专利权了
     \(^o^)/~）。
     *  总结：公钥和密钥成对出现，其中公钥负责加密 ，私钥负责解密
     *  补充：AES
     *  
         1. ECB(Electronic Code Book电子密码本)模式
         ECB模式是最早采用和最简单的模式，它将加密的数据分成若干组，每组的大小跟加密密钥长度相同，然后每组都用相同的密钥进行加密。
         优点:   1.简单；   2.有利于并行计算；  3.误差不会被扩散；
         缺点:   1.不能隐藏明文的模式；  2.可能对明文进行主动攻击；
         因此，此模式适于加密小消息。
         2. CBC(Cipher Block Chaining，加密块链)模式
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
     *  补充：本来觉得DES这种过时的加密方式几乎很少有人用了，但是今天一个网友问这个问题，那今天就补充一下DES的加密知识吧。
     *  DES:
        *DES(Data Encryption Standard)是分组对称密码算法。DES采用了64位的
        分组长度和56位的密钥长度，它将64位的输入经过一系列变换得到64位的输出。解密
        则使用了相同的步骤和相同的密钥。DES的密钥长度为64位，由于第
        n*8(n=1,2,…8)是校验位，因此实际参与加密的长度为56位，密钥空间含有2^56个密钥。
        *DES算法是一种分组加密机制，将明文分成N个组，然后对各个组进行加密，形成各自的密文，最后把所有的分组密文进行合并，形成最终的密文。
     
        *这里关于DES的介绍大家可以去网上去搜一下这样的文章，以及他的加密的过程什么的网上都有详细的介绍，我就不一一列举了，今天只简单的去介绍使用以及他跟AES加密之间的区别。
        详细的关于DES的资料大家可以去下面这篇文章去看看讲述的很详细。
        http://blog.csdn.net/fengbingchun/article/details/42273257
     
     *  AES其实就是DES的加强版，他们两个的模式十分相似，他们之间的加密模式是一样的也是分为上面介绍的ECB、CBC、CFB等几种加密模式，本来AES的产生就是为了替代DES这种加密方式，DES这种加密已经不足以支撑起现在人们的需求。相对来说他的安全强度是众多加密方式中比较低的。
     *   回归正题DES和AES之间的区别
     *   1、AES的加密密钥的长度最低是128位的，DES的密钥长度最多也就是64位，实际上还要排除掉8个校验位，也就是56位，密钥位数越高安全性最好这个是常识，从这一点上看AES的安全性要高于DES很多。而且一旦将校验位作为有效数据的话将不能保证DES加密数据的安全性，对运用DES来达到保密作用的系统产生数据被破译的危险，这正是DES算法在应用上的误区，留下了被人攻击、被人破译的极大隐患 。
     *   2、AES的分组长度是128位，DES的分组长度是64位
     *   注意：
     *   上面我们说到了一个概念性的东西，就是密钥长度。
     *   那是不是密钥长度是越长越好呢？我们来探讨一下这个问题
     *   首先密钥长度越长的优点：
         1、我们首先想到的就是对应的密钥空间就越大，安全性越高，越不容易被破解。
         已知最好的攻击需要 2n步才能破解某个算法 n代表了密钥长度。
     *   但是也带来了一些问题：
         1、首先加密过程耗时跟密钥长度成正比，密钥长度越长的话加密的过程耗时时间就会越长，加密解密的开销会变大。
     *   所以如果在性能和安全性之间选择一个折中的策略的话我觉的128未的密钥长度是比较合适的。
     *   先说到这里吧 我先把常用的方法补充进去。
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
    NSString*AES128Encode=[GBEncodeTool AES128Encrypt:test WithKey:PUBLIC_APP_KEY];
    NSLog(@"AES128加密->%@",AES128Encode);
    NSString*AES128Decode=[GBEncodeTool AES128Decrypt:AES128Encode WithKey:PUBLIC_APP_KEY];
    NSLog(@"AES128解密-->%@",AES128Decode);
    NSString*AES256Encode=[GBEncodeTool AES256Encrypt:test WithKey:PUBLIC_APP_KEY];
    NSLog(@"AES256加密->%@",AES256Encode);
    NSString*AES256Decode=[GBEncodeTool AES256Decrypt:AES256Encode WithKey:PUBLIC_APP_KEY];
    NSLog(@"AES256解密-->%@",AES256Decode);
    
    NSString*AESCBC128Encrypt=[GBEncodeTool AES128Encrypt:test Key:AES_KEY IV:AES_IV];
    NSString*AESCBC128Decrypt=[GBEncodeTool AES128Decrypt:AESCBC128Encrypt Key:AES_KEY IV:AES_IV];
    NSLog(@"AES128->CBC模式下的加密%@",AESCBC128Encrypt);
    NSLog(@"AES128->CBC模式下的解密%@",AESCBC128Decrypt);
    NSString*AESCBC256Encrypt=[GBEncodeTool AES128Encrypt:test Key:AES_KEY IV:AES_IV];
    NSString*AESCBC256Decrypt=[GBEncodeTool AES128Decrypt:AESCBC256Encrypt Key:AES_KEY IV:AES_IV];
    NSLog(@"AES256->CBC模式下的加密%@",AESCBC256Encrypt);
    NSLog(@"AES256->CBC模式下的解密%@",AESCBC256Decrypt);
    
    /**
     * 这种方式感觉不是很方便主要是为了公钥和密钥的周期性检测，不习惯的可以直接跳过
     * 通过公钥和私钥文件加密和解密
     */
    //支持pfx和p12两种格式
    NSString*privatePath1=[[NSBundle mainBundle]pathForResource:@"private_key.p12" ofType:nil];
    NSString*publickPath1=[[NSBundle mainBundle]pathForResource:@"public_key.der" ofType:nil];
    [GBEncodeTool configPrivateKey:privatePath1 Password:@"997756128"];
    [GBEncodeTool configPublickKey:publickPath1];
//    NSString*privatePath2=[[NSBundle mainBundle]pathForResource:@"private_key.pfx" ofType:nil];
//    NSString*publickPath2=[[NSBundle mainBundle]pathForResource:@"rsaCert.der" ofType:nil];
//    [GBEncodeTool configPrivateKey:privatePath2 Password:@"997756128"];
//    [GBEncodeTool configPublickKey:publickPath2];
    
    NSString*RSAEncode=[GBEncodeTool rsaEncryptText:test];
    NSLog(@"rsa加密-->%@",RSAEncode);
    NSString*RSADecode=[GBEncodeTool rsaDecryptText:RSAEncode];
    NSLog(@"rsa解密-->%@",RSADecode);
    /**直接通过公钥和私钥加密和解密 */
    NSString*rsaEncode=[GBEncodeTool rsaEncryptString:test publicKey:PUBLICK_KEY];
    NSLog(@"RSA加密-->%@",rsaEncode);
    NSString*rsaDecode=[GBEncodeTool rsaDecryptString:rsaEncode privateKey:PRIVATE_KEY];
    NSLog(@"RSA解密-->%@",rsaDecode);
   //补充的DES加密
    NSString*DESEncodeStr=[GBEncodeTool DESEncrypt:test WithKey:DES_KEY];
    NSString*DES_CBC_EncodeStr=[GBEncodeTool DESEncrypt:test Key:DES_KEY IV:DES_IV];
    NSLog(@"DES加密-->%@",DESEncodeStr);
    NSLog(@"CBC模式下的DES加x密-->%@",DES_CBC_EncodeStr);
    //补充的DES解密
    NSString*DESDecodeStr=[GBEncodeTool DESDecrypt:DESEncodeStr WithKey:DES_KEY];
    NSString*DES_CBC_DecodeStr=[GBEncodeTool DESDecrypt:DES_CBC_EncodeStr Key:DES_KEY IV:DES_IV];
    NSLog(@"DES解密-->%@",DESDecodeStr);
    NSLog(@"CBC模式下的DES解密-->%@",DES_CBC_DecodeStr);
    
    /** 明文 */
    NSString*publicStr=@"E1F2629EE05D8BDEED5033A2C9F9664B";
    /** 密文 */
    NSString*secretStr= @"17D032AB2C1186F2001B1A6385EF9720B116910DB19999171708A2D60E31126E5FC3A1186C82BF26E0E094371A9E1517";
    NSString*hexPublickStr=[GBEncodeTool AES128HexDecrypt:secretStr Key:AES_KEY IV:AES_IV];
    NSLog(@"16进制明文-->%@",hexPublickStr);
    
    
    /**
     *  补充：公钥和密钥的生成方法
     *
        生成1024位私钥
        openssl genrsa -out private_key.pem 1024
        
        // 根据私钥生成CSR文件
        openssl req -new -key private_key.pem -out rsaCertReq.csr
        
        // 根据私钥和CSR文件生成crt文件
        openssl x509 -req -days 3650 -in rsaCertReq.csr -signkey private_key.pem -out rsaCert.crt
        
        // 为IOS端生成公钥der文件
        openssl x509 -outform der -in rsaCert.crt -out public_key.der
        
        // 将私钥导出为这p12文件
        openssl pkcs12 -export -out private_key.p12 -inkey private_key.pem -in rsaCert.crt
     *
     */
    
    /**
     *  生成ios可引用的私有秘钥文件.pfx:
     *
     *  1. OpenSSL rsa -in private_key.pem -out private_key.key
        2. OpenSSL req -new -key private_key.key -out private_key.crt
        3. OpenSSL x509 -req -days 3650 -in private_key.crt -signkey private_key.key -out rsaCert.crt
        4. OpenSSL x509 -outform der -in rsaCert.crt -out rsaCert.der
        5. OpenSSL pkcs12 -export -out private_key.pfx -inkey private_key.key -in rsaCert.crt
        private_key.pfx即为生成的文件
     *  老规矩在补充知识点之前呢先来了解一下我们接下来要使用的概念
     *  补充关于证书的一些知识点
     *   PKCS 全称是 Public-Key Cryptography Standards ，是由 RSA 实验室与其它安全系统开发商为促进公钥密码的发展而制订的一系列标准，PKCS 目前共发布过 15 个标准。
         常用的有： 
         1、PKCS#12 Personal Information Exchange Syntax Standard  X.
         2、509是常见通用的证书格式。所有的证书都符合为Public Key Infrastructure (PKI) 制定的 ITU-T X509 国际标准。
         3、常用格式后缀
            PKCS#12 常用的后缀有： .P12 .PFX
            X.509 DER 编码(ASCII)的后缀是： .DER .CER .CRT
            X.509 PEM 编码(Base64)的后缀是： .PEM .CER .CRT
            .cer/.crt是用于存放证书，它是2进制形式存放的，不含私钥。
            .pem跟crt/cer的区别是它以Ascii来表示。
            .der是windows下的证书格式，以2进制形式存放。
            pfx/p12用于存放个人证书/私钥，他通常包含保护密码，2进制方式
            p10是证书请求
     
          4、x509
             x509是数字证书的规范，P7和P12是两种封装形式。比如说同样的电影，有的是avi格式，有的是mpg，大概就这个意思。
             P7一般是把证书分成两个文件，一个公钥一个私钥，有PEM和DER两种编码方式。PEM比较多见，就是纯文本的，P7一般是分发公钥用，看到的就是一串可见字符串，扩展名经常是.crt,.cer,.key等。DER是二进制编码。
             P12是把证书压成一个文件，.pfx 。主要是考虑分发证书，私钥是要绝对保密的，不能随便以文本方式散播。所以P7格式不适合分发。.pfx中可以加密码保护，所以相对安全些
          *
             X509   是证书规范，一般只用于公布公钥
             PKCS#7 是消息语法 （常用于数字签名与加密）
             PKCS#12 个人消息交换与打包语法 （如.PFX .P12）打包成带公钥与私钥
             还有其它常用的是PKCS#10 是证书请求语法。
     
     
     
     */
    
    

    

}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
