# GBEncodeTool
#包含了市面上所有常用的加密方式<br>
##目前一直在准备oc的收尾工作，本来打算是在2016年的之前结束看来是结束不了了，东西太多了只能一点点的总结，先公布出一些基本你们可能会用到的小工具给大家共享一下<br>
##大家直接用就可以了节省时间<br>
#下面是我建的一个群，可以来交流技术。群号：433060483欢迎加入组织。如果觉得我的贡献帮助了你请到右上角点个赞<br>
## 扫盲区：
```
/**常用的加密手段(适合新手理论加实战)
     *1、首先我们在用一个东西的时候我们不能单纯的为了用二用我们要对他有所了解，简单介绍一下加密
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
     *    对称加密算法：DES算法，3DES算法，TDEA算法，Blowfish算法，RC5算法，IDEA算法，AES算法。
     *    非对称加密算法：RSA、Elgamal、背包算法、Rabin、D-H、ECC。
     *    经典的哈希算法：MD2、MD4、MD5 和 *       
     *    SHA-1（目的是将任意长输入通过算法变为固定长输出，且保证输入变化一点输出都不同，且不能反向解密）
     *5、 今天我们来说一下我们在来发中常用的算法暂时只讲：MD5、Base64、sha、AES、rsa
     *    补充：RSA加密算法中比较重要的加密算法
     *    非对称加密算法可能是世界上最重要的算法，它是当今电子商务等领域的基石。简而言之，非对称加密就是指加密公钥和解密密钥是不同的，而且加密公钥和解密密钥是成对出现。非对称加密又叫公钥加密，也就是说成对的密钥，其中一个是对外公开的，所有人都可以获得，人们称之为公钥；而与之相对应的称为私钥，只有这对密钥的生成者才能拥有。
     *    对于一个私钥，有且只有一个与之对应的公钥。公钥公开给任何人，私钥通常是只有生成者拥有。公/私钥通常是1024位或者2048位，越长安全系数越高，但是解密越困难。尽管拿到了公钥，如果没有私钥，要想解密那几乎是不可能的，至少现在在世界上还没有人公开出来说成功解密的。
     *    总结：公钥和密钥成对出现，其中公钥负责加密 ，私钥负责解密
     *
     */
```
## 代码实例：
```
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
    
    NSString*privatePath=[[NSBundle mainBundle]pathForResource:@"private_key.p12" ofType:nil];
    NSString*publickPath=[[NSBundle mainBundle]pathForResource:@"public_key.der" ofType:nil];
    [GBEncodeTool configPrivateKey:privatePath Password:@"997756128"];
    [GBEncodeTool configPublickKey:publickPath];
    NSString*RSAEncode=[GBEncodeTool rsaEncryptText:test];
    NSLog(@"rsa加密-->%@",RSAEncode);
    NSString*RSADecode=[GBEncodeTool rsaDecryptText:test];
    NSLog(@"rsa解密-->%@",RSADecode);
    NSString*rsaEncode=[GBEncodeTool rsaEncryptString:test publicKey:PUBLICK_KEY];
    NSLog(@"RSA加密-->%@",rsaEncode);
    NSString*rsaDecode=[GBEncodeTool rsaDecryptString:rsaEncode privateKey:PRIVATE_KEY];
    NSLog(@"RSA解密-->%@",rsaDecode);
    
```
##更新说明<br>
* 添加AES解析16进制的密文的方式，针对于16进制的字符串解析不出来的情况<br>
* AES加密和解密的补充文档重点介绍了CBC模式下的加密和解密。在原有的加密基础上,添加了iv偏移量的参数<br>
* 细数了AES的几种加密模式包括CBC、ECB等模式<br>

