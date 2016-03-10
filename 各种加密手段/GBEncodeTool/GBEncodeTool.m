//
//  GBEncodeTool.m
//  各种加密手段
//
//  Created by 张国兵 on 15/9/19.
//  Copyright (c) 2015年 zhangguobing. All rights reserved.
//

#import "GBEncodeTool.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#define C2I(c) ((c >= '0' && c<='9') ? (c-'0') : ((c >= 'a' && c <= 'z') ? (c - 'a' + 10): ((c >= 'A' && c <= 'Z')?(c - 'A' + 10):(-1))))
#define FileHashDefaultChunkSizeForReadingData 1024*8
@implementation GBEncodeTool
// 支持双加密方式
// 32位MD5加密方式

+ (NSString *)getMd5_32Bit_String:(NSString *)srcString isUppercase:(BOOL)isUppercase{
    const char *cStr = [srcString UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (int)strlen(cStr), digest );
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
}
// 16位MD5加密方式

+ (NSString *)getMd5_16Bit_String:(NSString *)srcString isUppercase:(BOOL)isUppercase{
    //提取32位MD5散列的中间16位
    NSString *md5_32Bit_String=[self getMd5_32Bit_String:srcString isUppercase:NO];
    NSString *result = [[md5_32Bit_String substringToIndex:24] substringFromIndex:8];//即9～25位
    
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
}
// sha1加密方式

+ (NSString *)getSha1String:(NSString *)srcString
                isUppercase:(BOOL)isUppercase{
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (int)data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
    
}
// sha256加密方式

+ (NSString *)getSha256String:(NSString *)srcString
                  isUppercase:(BOOL)isUppercase
{
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (int)data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
    
}
// sha384加密方式

+ (NSString *)getSha384String:(NSString *)srcString
                  isUppercase:(BOOL)isUppercase {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (int)data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA384_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
    
}

// sha512加密方式

+ (NSString*) getSha512String:(NSString*)srcString
                  isUppercase:(BOOL)isUppercase {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    
    CC_SHA512(data.bytes, (int)data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    if (isUppercase) {
        return   [result uppercaseString];
    }else{
        return result;
    }
    
    
}
// base64加密和解密

+ (NSString*)encodeBase64String:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSString*)decodeBase64String:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 decodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSString*)encodeBase64Data:(NSData *)data {
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSString*)decodeBase64Data:(NSData *)data {
    data = [GTMBase64 decodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

/**CBC模式下的AES128加密 */
+(NSString*)AES128Encrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv{
    
    char keyPtr[kCCKeySizeAES128+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    int newSize = 0;
    
    if(diff > 0)
    {
        newSize = dataLength + diff;
    }
    
    char dataPtr[newSize];
    memcpy(dataPtr, [data bytes], [data length]);
    for(int i = 0; i < diff; i++)
    {
        dataPtr[i + dataLength] = 0x00;
    }
    
    size_t bufferSize = newSize + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    memset(buffer, 0, bufferSize);
    
    size_t numBytesCrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,               //No padding
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [GTMBase64 stringByEncodingData:resultData];
    }
    free(buffer);
    return nil;

}
/**CBC模式下的AES128解密 */
+(NSString*)AES128Decrypt:(NSString *)encryptText
                      Key:(NSString *)key
                       IV:(NSString*)iv{
    
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData *data = [GTMBase64 decodeData:[encryptText dataUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
   
}
/**AES128 16进制字符串解密 */
+(NSString*)AES128HexDecrypt:(NSString *)HexPlainText
                      Key:(NSString *)key
                       IV:(NSString*)iv{
    
    //16进制转data
    const char* cs = HexPlainText.UTF8String;
    
    int count = strlen(cs);
    
    int8_t bytes[count / 2];
    
    for(int i = 0; i<count; i+=2)
    {
        char c1 = *(cs + i);
        char c2 = *(cs + i + 1);
        if(C2I(c1) >= 0 && C2I(c2) >= 0){
            bytes[i / 2] = C2I(c1) * 16 + C2I(c2);
        }else{
            return nil;
        }
    }
    NSData * data = [NSData dataWithBytes:bytes length:count / 2];
    
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}
/**AES256 16进制字符串解密 */
+(NSString*)AES256HexDecrypt:(NSString *)HexPlainText
                         Key:(NSString *)key
                          IV:(NSString*)iv{
    
    //16进制转data
    const char* cs = HexPlainText.UTF8String;
    
    int count = strlen(cs);
    
    int8_t bytes[count / 2];
    
    for(int i = 0; i<count; i+=2)
    {
        char c1 = *(cs + i);
        char c2 = *(cs + i + 1);
        if(C2I(c1) >= 0 && C2I(c2) >= 0){
            bytes[i / 2] = C2I(c1) * 16 + C2I(c2);
        }else{
            return nil;
        }
    }
    NSData * data = [NSData dataWithBytes:bytes length:count / 2];
    
    char keyPtr[kCCKeySizeAES256 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}

/**CBC模式下的AES256加密 */
+(NSString*)AES256Encrypt:(NSString *)plainText
                      Key:(NSString *)key
                       IV:(NSString*)iv{
    
    char keyPtr[kCCKeySizeAES256+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    int newSize = 0;
    
    if(diff > 0)
    {
        newSize = dataLength + diff;
    }
    
    char dataPtr[newSize];
    memcpy(dataPtr, [data bytes], [data length]);
    for(int i = 0; i < diff; i++)
    {
        dataPtr[i + dataLength] = 0x00;
    }
    
    size_t bufferSize = newSize + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    memset(buffer, 0, bufferSize);
    
    size_t numBytesCrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,               //No padding
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [GTMBase64 stringByEncodingData:resultData];
    }
    free(buffer);
    return nil;
    
}
/**CBC模式下的AES256解密 */
+(NSString*)AES256Decrypt:(NSString *)encryptText
                      Key:(NSString *)key
                       IV:(NSString*)iv{
    
    char keyPtr[kCCKeySizeAES256 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData *data = [GTMBase64 decodeData:[encryptText dataUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
    
}

//  AES128加密

+ (NSString*) AES128Encrypt:(NSString *)plainText WithKey:(NSString *)key{
    //将nsstring转化为nsdata
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [data AES128EncryptWithKey:key];
    
    return [self encodeBase64Data:encryptedData];
}
//  AES128解密

+ (NSString*) AES128Decrypt:(NSString *)encryptText WithKey:(NSString *)key{
    //字符串进行二进制转化
    NSData *strData = [encryptText dataUsingEncoding:NSUTF8StringEncoding];
    NSData*data=[GTMBase64 decodeData:strData];
    //对加密过的二进制
    NSData *decryData = [data AES128DecryptWithKey:key];
    //将解了密码的nsdata转化为nsstring
    NSString *decodeString = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
    
    return decodeString;

}
//  AES192加密

+ (NSString*) AES192Encrypt:(NSString *)plainText WithKey:(NSString *)key{
    
    //将nsstring转化为nsdata
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [data AES192EncryptWithKey:key];
    return [self encodeBase64Data:encryptedData];
    
}
//  AES192解密

+ (NSString*) AES192Decrypt:(NSString *)encryptText WithKey:(NSString *)key{
    
    //字符串进行二进制转化
    NSData *strData = [encryptText dataUsingEncoding:NSUTF8StringEncoding];
    NSData*data=[GTMBase64 decodeData:strData];
    //对加密过的二进制
    NSData *decryData = [data AES192DecryptWithKey:key];
    //将解了密码的nsdata转化为nsstring
    NSString *decodeString = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
    
    return decodeString;

    
    
}
//  AES256加密

+ (NSString*) AES256Encrypt:(NSString *)plainText WithKey:(NSString *)key{
    //将nsstring转化为nsdata
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [data AES256EncryptWithKey:key];
    
    return [self encodeBase64Data:encryptedData];
    
}

//  AES256解密

+ (NSString*) AES256Decrypt:(NSString *)encryptText WithKey:(NSString *)key{

    //字符串进行二进制转化
    NSData *strData = [encryptText dataUsingEncoding:NSUTF8StringEncoding];
    NSData*data=[GTMBase64 decodeData:strData];
    //对加密过的二进制
    NSData *decryData = [data AES256DecryptWithKey:key];
    //将解了密码的nsdata转化为nsstring
    NSString *decodeString = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
    
    return decodeString;
}

+(NSString*)getFileMD5:(NSString*)path{
    
    
    return (__bridge_transfer NSString *)FileMD5HashCreateWithPath((__bridge CFStringRef)path, FileHashDefaultChunkSizeForReadingData);
    
    
}
CFStringRef FileMD5HashCreateWithPath(CFStringRef filePath,size_t chunkSizeForReadingData) {
    
    // Declare needed variables
    
    CFStringRef result = NULL;
    
    CFReadStreamRef readStream = NULL;
    
    // Get the file URL
    
    CFURLRef fileURL =
    
    CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                  
                                  (CFStringRef)filePath,
                                  
                                  kCFURLPOSIXPathStyle,
                                  
                                  (Boolean)false);
    
    if (!fileURL) goto done;
    
    // Create and open the read stream
    
    readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,
                                            
                                            (CFURLRef)fileURL);
    
    if (!readStream) goto done;
    
    bool didSucceed = (bool)CFReadStreamOpen(readStream);
    
    if (!didSucceed) goto done;
    
    // Initialize the hash object
    
    CC_MD5_CTX hashObject;
    
    CC_MD5_Init(&hashObject);
    
    // Make sure chunkSizeForReadingData is valid
    
    if (!chunkSizeForReadingData) {
        
        chunkSizeForReadingData=FileHashDefaultChunkSizeForReadingData;
        
    }
    
    // Feed the data to the hash object
    
    bool hasMoreData = true;
    
    while (hasMoreData) {
        
        uint8_t buffer[chunkSizeForReadingData];
        
        CFIndex readBytesCount = CFReadStreamRead(readStream,(UInt8 *)buffer,(CFIndex)sizeof(buffer));
        
        if (readBytesCount == -1) break;
        
        if (readBytesCount == 0) {
            
            hasMoreData = false;
            
            continue;
            
        }
        
        CC_MD5_Update(&hashObject,(const void *)buffer,(CC_LONG)readBytesCount);
        
    }
    
    // Check if the read operation succeeded
    
    didSucceed = !hasMoreData;
    
    // Compute the hash digest
    
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5_Final(digest, &hashObject);
    
    // Abort if the read operation failed
    
    if (!didSucceed) goto done;
    
    // Compute the string result
    
    char hash[2 * sizeof(digest) + 1];
    
    for (size_t i = 0; i < sizeof(digest); ++i) {
        
        snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
        
    }
    
    result = CFStringCreateWithCString(kCFAllocatorDefault,(const char *)hash,kCFStringEncodingUTF8);
    
    
    
done:
    
    if (readStream) {
        
        CFReadStreamClose(readStream);
        
        CFRelease(readStream);
        
    }
    
    if (fileURL) {
        
        CFRelease(fileURL);
        
    }
    
    return result;
    
}

+(void)configPublickKey:(NSString*)publickKeyPath{
    
    [[RSACodeTool sharedInstance]loadPublicKeyWithPath:publickKeyPath];
    
}
+(void)configPrivateKey:(NSString *)privateKeyPath
               Password:(NSString *)p12Password{
    
    [[RSACodeTool sharedInstance]loadPrivateKeyWithPath:privateKeyPath password:p12Password];
    
}

/**
 *  rsa解密
 *
 *  @param text 密文
 *
 *  @return 明文
 */
+(NSString *)rsaDecryptText:(NSString *)text{
    
    NSString*decryptText=[[RSACodeTool sharedInstance]rsaDecryptText:text];
    return decryptText;
}
/**
 *  rsa加密
 *
 *  @param text 明文 NSString
 *
 *  @return 密文 NSString
 */
+(NSString *)rsaEncryptText:(NSString *)text{
    
    NSString*encryptText=[[RSACodeTool sharedInstance]rsaEncryptText:text];
    return encryptText;
    
}
/**
 *  rsa加密
 *
 *  @param str    要加密的明文
 *  @param pubKey 加密公钥
 *
 *  @return 加密之后的密文
 */
+ (NSString *)rsaEncryptString:(NSString *)str publicKey:(NSString *)pubKey{
    
    NSString*encryptText=[[RSACodeTool sharedInstance]rsaEncryptString:str publicKey:pubKey];
    return encryptText;
    
}
/**
 *  rsa 加密
 *
 *  @param data   数据加密
 *  @param pubKey 公钥
 *
 *  @return 加密之后的数据
 */
+ (NSData *)rsaEncryptData:(NSData *)data publicKey:(NSString *)pubKey{
    
    NSData*encryptData=[[RSACodeTool sharedInstance]rsaEncryptData:data  publicKey:pubKey];
    return encryptData;
}
/**
 *  rsa解密
 *
 *  @param str     密文
 *  @param privKey 密钥
 *
 *  @return 明文
 */
+ (NSString *)rsaDecryptString:(NSString *)str privateKey:(NSString *)privKey{

    NSString*decryptText=[[RSACodeTool sharedInstance]rsaDecryptString:str privateKey:privKey];
    return decryptText;
    
}
/**
 *  rsa解密
 *
 *  @param data    数据密文
 *  @param privKey 密钥
 *
 *  @return 数据明文
 */
+ (NSData *)rsaDecryptData:(NSData *)data privateKey:(NSString *)privKey{
    
    NSData*decryptData=[[RSACodeTool sharedInstance]rsaDecryptData:data privateKey:privKey];
    return decryptData;
}

@end
