//
//  NSData+AES.h
//  各种加密手段
//
//  Created by 张国兵 on 15/9/19.
//  Copyright (c) 2015年 zhangguobing. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (AES)
/**
 *  AES256位加密
 *
 *  @param key 密钥（长度是32个字节）
 *
 *  @return 加密后的二进制密文
 */
- (NSData *)AES256EncryptWithKey:(NSString *)key;
/**
 *  AES256位解密
 *
 *  @param key 密钥（长度是32个字节）
 *
 *  @return 解密后的明文
 */
- (NSData *)AES256DecryptWithKey:(NSString *)key;
/**
 *  AES192位加密
 *
 *  @param key 密钥（长度24字节）
 *
 *  @return 密文
 */
- (NSData *)AES192EncryptWithKey:(NSString *)key;
/**
 *  AES192位解密
 *
 *  @param key 密钥（长度24字节）
 *
 *  @return 明文
 */
- (NSData *)AES192DecryptWithKey:(NSString *)key;
/**
 *  AES128位加密
 *
 *  @param key 密钥（长度16字节）
 *
 *  @return 密文
 */
- (NSData *)AES128EncryptWithKey:(NSString *)key;
/**
 *  AES128位解密
 *
 *  @param key 密钥（长度16字节）
 *
 *  @return 明文
 */
- (NSData *)AES128DecryptWithKey:(NSString *)key;
@end
