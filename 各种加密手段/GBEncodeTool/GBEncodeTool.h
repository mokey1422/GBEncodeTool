//
//  GBEncodeTool.h
//  各种加密手段
//
//  Created by 张国兵 on 15/9/19.
//  Copyright (c) 2015年 zhangguobing. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "GTMBase64.h"
#import "NSData+AES.h"
#import "RSACodeTool.h"
@interface GBEncodeTool : NSObject

/**
 *  16位MD5加密方式（16个字节长度）
 *  经典的哈希算法不可逆
 *  @param srcString   加密的明文
 *  @param isUppercase 是否大写
 *
 *  @return 加密好的密文
 */
+ (NSString *)getMd5_16Bit_String:(NSString *)srcString isUppercase:(BOOL)isUppercase;
/**
 *  32位MD5加密方式(长度是32字节中间16位字节和16加密的结果相同)
 *  经典的哈希算法不可逆
 *  @param NSString 加密的明文
 *  @param isUppercase 是否大写
 *  @return 加密后的密文
 */
+ (NSString *)getMd5_32Bit_String:(NSString *)srcString isUppercase:(BOOL)isUppercase;
/**
 *  sha1加密方式
 *  经典的哈希算法不可逆
 *  @param NSString 要加密的明文
 *  @param isUppercase 是否大写
 *  @return 密文
 */

+ (NSString *)getSha1String:(NSString *)srcString
                isUppercase:(BOOL)isUppercase;
/**
 *  sha256加密方式
 *  经典的哈希算法不可逆
 *  @param NSString 要加密的明文
 *  @param isUppercase 是否大写
 *  @return 密文
 */

+ (NSString *)getSha256String:(NSString *)srcString
                  isUppercase:(BOOL)isUppercase;
/**
 *  sha384加密方式
 *  经典的哈希算法不可逆
 *  @param NSString 要加密的明文
 *  @param isUppercase 是否大写
 *  @return 密文
 */

+ (NSString *)getSha384String:(NSString *)srcString
                  isUppercase:(BOOL)isUppercase;
/**
 *  sha512加密方式
 *  经典的哈希算法不可逆
 *  @param NSString 要加密的明文
 *  @param isUppercase 是否大写
 *  @return 密文
 */
+ (NSString*) getSha512String:(NSString*)srcString
                  isUppercase:(BOOL)isUppercase;

/**
 *  base64加密
 *
 *  @param input 明文（字符创类型）
 *
 *  @return 密文
 */
+ (NSString*)encodeBase64String:(NSString *)input;
/**
 *  base64解密
 *
 *  @param input 密文
 *
 *  @return 明文
 */
+ (NSString*)decodeBase64String:(NSString *)input;
/**
 *  base64加密
 *
 *  @param data 明文（二进制）
 *
 *  @return 密文（字符串）
 */
+ (NSString*)encodeBase64Data:(NSData *)data;
/**
 *  base64解密
 *
 *  @param data 密文（二进制）
 *
 *  @return 明文（字符串）
 */

+ (NSString*)decodeBase64Data:(NSData *)data;
/**
 *  AES128加密（非CBC模式）
 *
 *  @param plainText 明文
 *  @param key       密钥（16字节）
 *
 *  @return 密文
 */
+ (NSString*) AES128Encrypt:(NSString *)plainText WithKey:(NSString *)key;
/**
 *  AES128解密（非CBC模式）
 *
 *  @param encryptText 密文
 *  @param key         密钥（16字节）
 *
 *  @return 明文
 */

+ (NSString*) AES128Decrypt:(NSString *)encryptText WithKey:(NSString *)key;
/**
 *  AES128加密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param plainText 明文
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 密文
 */
+(NSString*)AES128Encrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv;
/**
 *  AES128解密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param plainText 密文
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 明文
 */
+(NSString*)AES128Decrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv;
/**
 *  AES128解密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param HexPlainText 密文(16进制)
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 明文
 */

+(NSString*)AES128HexDecrypt:(NSString *)HexPlainText
                         Key:(NSString *)key
                          IV:(NSString*)iv;
/**
 *  AES 256解密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param HexPlainText 密文(16进制)
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 明文
 */
+(NSString*)AES256HexDecrypt:(NSString *)HexPlainText
                         Key:(NSString *)key
                          IV:(NSString*)iv;
/**
 *  AES192加密
 *
 *  @param plainText 明文
 *  @param key       密钥（24字节）
 *
 *  @return 密文
 */
+ (NSString*) AES192Encrypt:(NSString *)plainText WithKey:(NSString *)key;
/**
 *  AES192解密
 *
 *  @param encryptText 密文
 *  @param key         密钥（24字节）
 *
 *  @return 明文
 */
+ (NSString*) AES192Decrypt:(NSString *)encryptText WithKey:(NSString *)key;
/**
 *  AES256加密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param plainText 明文
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 密文
 */
+(NSString*)AES256Encrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv;
/**
 *  AES256解密(CBC模式，安全性更高，与java和php互通）
 *
 *  @param plainText 密文
 *  @param key       密钥
 *  @param iv        iv参数（偏移量）
 *
 *  @return 明文
 */
+(NSString*)AES256Decrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv;
/**
 *  AES256加密
 *
 *  @param plainText 明文
 *  @param key       密钥（32字节）
 *
 *  @return 密文
 */
+ (NSString*) AES256Encrypt:(NSString *)plainText WithKey:(NSString *)key;
/**
 *  AES256解密
 *
 *  @param encryptText 密文
 *  @param key         密钥（32字节）
 *
 *  @return 明文
 */
+ (NSString*) AES256Decrypt:(NSString *)encryptText WithKey:(NSString *)key;
/**
 *  计算大文件的md5值
 *
 *  @param path 文件路径
 *
 *  @return md5值
 *
 *  应用场景：一般我们在使用http或者socket上传或者下载文件的时候，经常会在完成之后经行一次MD5值得校验（尤其是在断点续传的时候用的更
 多），校验MD5值是为了防止在传输的过程当中丢包或者数据包被篡改
 */
+(NSString*)getFileMD5:(NSString*)path;
/**
 *  配置公钥
 *  public_key.der公钥
 *  公钥负责加密
 */
+(void)configPublickKey:(NSString*)publickKeyPath;
/**
 *  配置私钥
 *  private_key.p12私钥
 *  私钥负责解密
 *  @param PrivateKeyPath 私钥路径
 *  @param p12Password    私钥密码
 */
+(void)configPrivateKey:(NSString *)privateKeyPath
               Password:(NSString *)p12Password;
/**
 *  rsa加密
 *
 *  @param text 明文 NSString
 *
 *  @return 密文 NSString
 */
+(NSString *)rsaEncryptText:(NSString *)text;
/**
 *  rsa解密
 *
 *  @param text 密文
 *
 *  @return 明文
 */
+(NSString *)rsaDecryptText:(NSString *)text;

/**
 *  rsa加密
 *
 *  @param str    要加密的明文
 *  @param pubKey 加密公钥
 *
 *  @return 加密之后的密文
 */
+ (NSString *)rsaEncryptString:(NSString *)str publicKey:(NSString *)pubKey;
/**
 *  rsa 加密
 *
 *  @param data   数据加密
 *  @param pubKey 公钥
 *
 *  @return 加密之后的数据
 */
+ (NSData *)rsaEncryptData:(NSData *)data publicKey:(NSString *)pubKey;
/**
 *  rsa解密
 *
 *  @param str     密文
 *  @param privKey 密钥
 *
 *  @return 明文
 */
+ (NSString *)rsaDecryptString:(NSString *)str privateKey:(NSString *)privKey;
/**
 *  rsa解密
 *
 *  @param data    数据密文
 *  @param privKey 密钥
 *
 *  @return 数据明文
 */
+ (NSData *)rsaDecryptData:(NSData *)data privateKey:(NSString *)privKey;


@end
