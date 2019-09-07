//
//  GLCryptor.m
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import "GLCryptor.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import "GLCCMCrypt.h"
#import "GLRSACryptor.h"
#import "GLAESCCMCryptor.h"

@implementation GLCryptor

static NSString* crypt_msg_prefix = @"grablink_0_0_1";
static NSString* crypt_msg_separator = @"$";
static NSUInteger crypt_ivLength = 12;

+ (NSString *)encrypt:(NSData *)data publicKeyInHex:(NSString *)keyInHex {
    NSParameterAssert(data);
    NSParameterAssert(keyInHex);
    
    OSStatus status = noErr;
    
    // generate a unique AES key and (later) encrypt it with the public RSA key of the merchant
    NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
    
    status = SecRandomCopyBytes(NULL, kCCKeySizeAES256, key.mutableBytes);
    if (status != noErr) {
        return nil;
    }
    // generate a nonce
    NSMutableData *iv = [NSMutableData dataWithLength:crypt_ivLength];

    status = SecRandomCopyBytes(NULL, crypt_ivLength, iv.mutableBytes);
    if (status != noErr) {
        return nil;
    }

//    NSData *cipherText = [self aesEncrypt:data withKey:key iv:iv];
    GLCCMCrypt *ccm = [[GLCCMCrypt alloc] initWithKey:key
                                                   iv:iv
                                                adata:nil
                                            tagLength:8];

    NSData *cipherText = [ccm encryptDataWithData:data];

    if (!cipherText) {
        return nil;
    }
    
    // format of the fully composed message:
    // - a prefix
    // - a separator
    // - RSA encrypted AES key, base64 encoded
    // - a separator
    // - a Payload of iv and cipherText, base64 encoded
    NSMutableData *payload = [NSMutableData data];
    [payload appendData:iv];
    [payload appendData:cipherText];
    
    NSData *encryptedKey = [self rsaEncrypt:key withKeyInHex:keyInHex];
    
    NSString *result = nil;
    
    NSString *prefix = (crypt_msg_prefix.length == 0) ? @"" : [crypt_msg_prefix stringByAppendingString:crypt_msg_separator];
    
    if (encryptedKey) {
        result = [NSString stringWithFormat:@"%@%@%@%@",
                  prefix,
                  [encryptedKey base64EncodedStringWithOptions:0],
                  crypt_msg_separator,
                  [payload base64EncodedStringWithOptions:0]];
    }
    return result;
}
+ (NSData *)rsaEncrypt:(NSData *)data withKeyInHex:(NSString *)keyInHex {
    NSParameterAssert(data);
    NSParameterAssert(keyInHex);
    
    return [GLRSACryptor encrypt:data withKeyInHex:keyInHex];
}
+ (NSData *)aesEncrypt:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv {
    NSParameterAssert(data);
    NSParameterAssert(key);
    NSParameterAssert(iv);
    
    return [GLAESCCMCryptor encrypt:data withKey:key iv:iv];
}
@end
