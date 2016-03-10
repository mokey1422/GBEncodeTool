//
//  RSACodeTool.h
//  各种加密手段
//
//  Created by 张国兵 on 15/12/24.
//  Copyright © 2015年 zhangguobing. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "GBEncodeTool.h"
@interface RSACodeTool : NSObject
// 单例对象
+(id)sharedInstance;
// 加密相关
/**
 *  设置公钥
 *
 *  derFilePath 公钥配置路径
 */
- (void)loadPublicKeyWithPath:(NSString *)derFilePath;
/**
 *  rsa加密
 *
 *  @param text 被加密明文
 *
 *  @return 加密之后的密文
 */
- (NSString *)rsaEncryptText:(NSString *)text;
/**
 *  rsa加密
 *
 *  @param data 被加密数据明文
 *
 *  @return 加密之后的数据密文
 */
- (NSData *)rsaEncryptData:(NSData *)data;

// 解密相关
/**
 *  配置密钥
 *  因为这里导入的是p12文件所以需要密码
 *  @param p12FilePath p12文件路径
 *  @param p12Password 授权密码
 */
- (void)loadPrivateKeyWithPath:(NSString *)p12FilePath password:(NSString *)p12Password;
/**
 *  rsa解密
 *
 *  @param text 密文
 *
 *  @return 明文
 */
- (NSString *)rsaDecryptText:(NSString *)text;
/**
 *  rsa加密
 *
 *  @param str    要加密的明文
 *  @param pubKey 加密公钥
 *
 *  @return 加密之后的密文
 */
- (NSString *)rsaEncryptString:(NSString *)str publicKey:(NSString *)pubKey;
/**
 *  rsa 加密
 *
 *  @param data   数据加密
 *  @param pubKey 公钥
 *
 *  @return 加密之后的数据
 */
-(NSData *)rsaEncryptData:(NSData *)data publicKey:(NSString *)pubKey;
/**
 *  rsa解密
 *
 *  @param str     密文
 *  @param privKey 密钥
 *
 *  @return 明文
 */
- (NSString *)rsaDecryptString:(NSString *)str privateKey:(NSString *)privKey;
/**
 *  rsa解密
 *
 *  @param data    数据密文
 *  @param privKey 密钥
 *
 *  @return 数据明文
 */
- (NSData *)rsaDecryptData:(NSData *)data privateKey:(NSString *)privKey;
@end
