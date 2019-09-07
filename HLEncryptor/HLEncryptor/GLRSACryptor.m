//
//  GLRSACryptor.m
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import "GLRSACryptor.h"
#import "GLSha1InHex.h"
#import "GLDataFromHex.h"
#import "GLRSAEncrypt.h"
@implementation GLRSACryptor
// data ->key
+ (NSData *)encrypt:(NSData *)data withKeyInHex:(NSString *)keyInHex {
//    NSParameterAssert(data);
//    NSParameterAssert(keyInHex);
//
//    SecKeyRef *publicKey;
//    NSArray *tokens = [keyInHex componentsSeparatedByString:@"|"];
//    if (tokens.count != 2) {
//        return nil;
//    }
//
//    NSData *exponent = [GLDataFromHex dataFromHex:tokens[0]];
//    NSData *modulus  = [GLDataFromHex dataFromHex:tokens[1]];
//
//    if (!exponent || !modulus) {
//        return nil;
//    }
//
//    //NSData *pubKeyData = [self generateRSAPublicKeyWithModulus:modulus exponent:exponent];
//
//    NSData *pubKeyData = [NSData data];
//    pubKeyData = [pubKeyData OpenSSL_RSA_DataWithPublicModulus: modulus exponent: exponent isDecrypt:NO];
//    NSLog(@"pubKeyData:%@",pubKeyData);
//    //NSLog(@"publicKey:%@",publicKey);
//
//    if (!publicKey) {
//        NSLog(@"Problem obtaining SecKeyRef");
//        return nil;
//    }
//
//    //    return [self encrypt:data RSAPublicKey:publicKey padding:kSecPaddingPKCS1];
//    return [GLRSAEncrypt encryptData:data withKeyRef:publicKey isSign:NO];
    
    NSParameterAssert(data);
    NSParameterAssert(keyInHex);

    NSString *fingerprint = [[GLSha1InHex sha1FromStringInHex:keyInHex] base64EncodedStringWithOptions:0];

    [self deleteRSAPublicKeyWithAppTag:fingerprint];

    SecKeyRef publicKey = [self loadRSAPublicKeyRefWithAppTag:fingerprint];

    if (!publicKey) {

        NSArray *tokens = [keyInHex componentsSeparatedByString:@"|"];
        if (tokens.count != 2) {
            return nil;
        }

        NSData *exponent = [GLDataFromHex dataFromHex:tokens[0]];
        NSData *modulus  = [GLDataFromHex dataFromHex:tokens[1]];

        if (!exponent || !modulus) {
            return nil;
        }

        //NSLog(@"Adding PublicKey to Keystore with fingerprint: %@", fingerprint);

        NSData *pubKeyData = [self generateRSAPublicKeyWithModulus:modulus exponent:exponent];

        [self saveRSAPublicKey:pubKeyData appTag:fingerprint overwrite:YES];
        publicKey = [self loadRSAPublicKeyRefWithAppTag:fingerprint];

    }

    if (!publicKey) {
        NSLog(@"Problem obtaining SecKeyRef");
        return nil;
    }

//    return [self encrypt:data RSAPublicKey:publicKey padding:kSecPaddingPKCS1];
//    NSString *ssss = @"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA03r1JAAtvVnE6TDdhjCBw4dWNIAWPbkH1Cj+UGF6/+cwAMDa4Qo9j/HJxQsObChcIV+rHKYa15fqfHHXlEsjwLGo93i0maiHOY5NHzfC7keA8HrioKtGDLI6ddIwfnSZY2KaUGk0lpjJNquycnTk/exI3Sxj1xbWnxSlxEWJS5+iHadtEpD55XFsnffsOFfwqDed0m1s9OHiA5vsMNE0d+lUFUfgybDJ/sZzEttgjPsA75UbsNzkAmkbn5U+8nyQGp55VObj2ZolOzcZzLBNSXl6utOPm75N8fTaP2oCe09rB66Ro62y+24G7caE02woCgxKyZtmhORS/sHdNZ4d/QIDAQAB-----END PUBLIC KEY-----";
    
//    return [GLRSAEncrypt encryptData:data publicKey: ssss];

    return [GLRSAEncrypt encryptData:data withKeyRef:publicKey isSign:NO];
    
}
// https://github.com/meinside/iphonelib/blob/master/security/CryptoUtil.m

+ (NSData *)generateRSAPublicKeyWithModulus:(NSData*)modulus exponent:(NSData*)exponent
{
    const uint8_t DEFAULT_EXPONENT[] = {0x01, 0x00, 0x01,};    //default: 65537
    const uint8_t UNSIGNED_FLAG_FOR_BYTE = 0x81;
    const uint8_t UNSIGNED_FLAG_FOR_BYTE2 = 0x82;
    const uint8_t UNSIGNED_FLAG_FOR_BIGNUM = 0x00;
    const uint8_t SEQUENCE_TAG = 0x30;
    const uint8_t INTEGER_TAG = 0x02;
    
    uint8_t* modulusBytes = (uint8_t*)[modulus bytes];
    uint8_t* exponentBytes = (uint8_t*)(exponent == nil ? DEFAULT_EXPONENT : [exponent bytes]);
    
    //(1) calculate lengths
    //- length of modulus
    int lenMod = (int)[modulus length];
    if(modulusBytes[0] >= 0x80)
        lenMod ++;    //place for UNSIGNED_FLAG_FOR_BIGNUM
    int lenModHeader = 2 + (lenMod >= 0x80 ? 1 : 0) + (lenMod >= 0x0100 ? 1 : 0);
    //- length of exponent
    int lenExp = exponent == nil ? sizeof(DEFAULT_EXPONENT) : (int)[exponent length];
    int lenExpHeader = 2;
    //- length of body
    int lenBody = lenModHeader + lenMod + lenExpHeader + lenExp;
    //- length of total
    int lenTotal = 2 + (lenBody >= 0x80 ? 1 : 0) + (lenBody >= 0x0100 ? 1 : 0) + lenBody;
    
    int index = 0;
    uint8_t* byteBuffer = malloc(sizeof(uint8_t) * lenTotal);
    memset(byteBuffer, 0x00, sizeof(uint8_t) * lenTotal);
    
    //(2) fill up byte buffer
    //- sequence tag
    byteBuffer[index ++] = SEQUENCE_TAG;
    //- total length
    if(lenBody >= 0x80)
        byteBuffer[index ++] = (lenBody >= 0x0100 ? UNSIGNED_FLAG_FOR_BYTE2 : UNSIGNED_FLAG_FOR_BYTE);
    if(lenBody >= 0x0100)
    {
        byteBuffer[index ++] = (uint8_t)(lenBody / 0x0100);
        byteBuffer[index ++] = lenBody % 0x0100;
    }
    else
        byteBuffer[index ++] = lenBody;
    //- integer tag
    byteBuffer[index ++] = INTEGER_TAG;
    //- modulus length
    if(lenMod >= 0x80)
        byteBuffer[index ++] = (lenMod >= 0x0100 ? UNSIGNED_FLAG_FOR_BYTE2 : UNSIGNED_FLAG_FOR_BYTE);
    if(lenMod >= 0x0100)
    {
        byteBuffer[index ++] = (int)(lenMod / 0x0100);
        byteBuffer[index ++] = lenMod % 0x0100;
    }
    else
        byteBuffer[index ++] = lenMod;
    //- modulus value
    if(modulusBytes[0] >= 0x80)
        byteBuffer[index ++] = UNSIGNED_FLAG_FOR_BIGNUM;
    memcpy(byteBuffer + index, modulusBytes, sizeof(uint8_t) * [modulus length]);
    index += [modulus length];
    //- exponent length
    byteBuffer[index ++] = INTEGER_TAG;
    byteBuffer[index ++] = lenExp;
    //- exponent value
    memcpy(byteBuffer + index, exponentBytes, sizeof(uint8_t) * lenExp);
    index += lenExp;
    
    if(index != lenTotal)
        NSLog(@"lengths mismatch: index = %d, lenTotal = %d", index, lenTotal);
    
    NSMutableData* buffer = [NSMutableData dataWithBytes:byteBuffer length:lenTotal];
    free(byteBuffer);
    
    return buffer;
}

+ (BOOL)saveRSAPublicKey:(NSData*)publicKey appTag:(NSString *)appTag overwrite:(BOOL)overwrite
{
    
    NSDictionary *query = nil;
    query = @{
              (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
              (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeRSA,
              (__bridge id)kSecAttrKeyClass:        (__bridge id)kSecAttrKeyClassPublic,
              (__bridge id)kSecAttrApplicationTag:  [appTag dataUsingEncoding:NSUTF8StringEncoding],
              (__bridge id)kSecValueData:           publicKey,
              (__bridge id)kSecReturnPersistentRef: @(YES)
              };
    
    CFDataRef ref;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&ref);
    
    
    if (status == noErr) {
        return YES;
    } else if(status == errSecDuplicateItem && overwrite == YES) {
        return [self updateRSAPublicKey:publicKey appTag:appTag];
    } else {
        NSLog(@"result = %d", (int)status);
    }
    
    return NO;
}

+ (BOOL)updateRSAPublicKey:(NSData*)publicKey appTag:(NSString*)appTag
{
    NSDictionary *query = nil;
    query = @{
              (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
              (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeRSA,
              (__bridge id)kSecAttrKeyClass:        (__bridge id)kSecAttrKeyClassPublic,
              (__bridge id)kSecAttrApplicationTag:  [appTag dataUsingEncoding:NSUTF8StringEncoding]
              };
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL); //don't need public key ref
    
    if(status == noErr)
    {
        query = @{
                  (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
                  (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeRSA,
                  (__bridge id)kSecAttrKeyClass:        (__bridge id)kSecAttrKeyClassPublic,
                  (__bridge id)kSecAttrApplicationTag:  [appTag dataUsingEncoding:NSUTF8StringEncoding]
                  };
        status = SecItemUpdate((__bridge CFDictionaryRef)query,
                               (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData: publicKey});
        
        NSLog(@"result = %d", (int)status);
        
        return status == noErr;
    } else {
        NSLog(@"result = %d", (int)status);
    }
    return NO;
}

+ (BOOL)deleteRSAPublicKeyWithAppTag:(NSString*)appTag
{
    NSDictionary *query = nil;
    query = @{
              (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
              (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeRSA,
              (__bridge id)kSecAttrKeyClass:        (__bridge id)kSecAttrKeyClassPublic,
              (__bridge id)kSecAttrApplicationTag:  [appTag dataUsingEncoding:NSUTF8StringEncoding]
              };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    if (status != noErr) NSLog(@"result = %d", (int)status);
    
    return status == noErr;
}

/*
 * returned value(SecKeyRef) should be released with CFRelease() function after use.
 *
 */
+ (SecKeyRef)loadRSAPublicKeyRefWithAppTag:(NSString*)appTag
{
    NSDictionary *query = nil;
    query = @{
              (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
              (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeRSA,
              (__bridge id)kSecAttrKeyClass:        (__bridge id)kSecAttrKeyClassPublic,
              (__bridge id)kSecAttrApplicationTag:  [appTag dataUsingEncoding:NSUTF8StringEncoding],
              (__bridge id)kSecReturnRef:           @(YES)
              };
    
    SecKeyRef publicKeyRef;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&publicKeyRef);
    
    if (status == noErr) {
        //NSString *pwd = [[NSString alloc] initWithData:(__bridge NSData * _Nonnull)(publicKeyRef) encoding:NSUTF8StringEncoding];
        //NSLog(@"==result:%@", pwd);

        return publicKeyRef;
        

    } else {
        NSLog(@"result = %d", (int)status);
        return NULL;
    }
}

//SecKeyRef getPrivateKeyFromPem() {
//    // 下面是对于 PEM 格式的密钥文件的密钥多余信息的处理，通常 DER 不需要这一步
//    NSString *key = @"PEM 格式的密钥文件";
//    NSRange spos;
//    NSRange epos;
//    spos = [key rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
//    if(spos.length > 0){
//        epos = [key rangeOfString:@"-----END RSA PRIVATE KEY-----"];
//    }else{
//        spos = [key rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
//        epos = [key rangeOfString:@"-----END PRIVATE KEY-----"];
//    }
//    if(spos.location != NSNotFound && epos.location != NSNotFound){
//        NSUInteger s = spos.location + spos.length;
//        NSUInteger e = epos.location;
//        NSRange range = NSMakeRange(s, e-s);
//        key = [key substringWithRange:range];
//    }
//    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
//    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
//    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
//    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
//
//    // This will be base64 encoded, decode it.
////    NSData *data = base64_decode(key);
//    NSData *data = base64_decode(key);
//
//    if(!data){
//        return nil;
//    }
//
//    // 设置属性字典
//    NSMutableDictionary *options = [NSMutableDictionary dictionary];
//    options[(__bridge id)kSecAttrKeyType] = (__bridge id) kSecAttrKeyTypeRSA;
//    options[(__bridge id)kSecAttrKeyClass] = (__bridge id) kSecAttrKeyClassPrivate;
//    NSNumber *size = @2048;
//    options[(__bridge id)kSecAttrKeySizeInBits] = size;
//    NSError *error = nil;
//    CFErrorRef ee = (__bridge CFErrorRef)error;
//
//    // 调用接口获取密钥对象
//    SecKeyRef ret = SecKeyCreateWithData((__bridge CFDataRef)data, (__bridge CFDictionaryRef)options, &ee);
//    if (error) {
//        return nil;
//    }
//    return ret;
//}


@end
