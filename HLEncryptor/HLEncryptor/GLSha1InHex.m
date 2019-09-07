//
//  GLSha1InHex.m
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import "GLSha1InHex.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation GLSha1InHex

+ (NSData *)sha1FromStringInHex:(NSString *)stringInHex {
    NSParameterAssert(stringInHex);
    
    NSMutableData *digest = [NSMutableData dataWithCapacity:CC_SHA1_DIGEST_LENGTH];
    NSData *stringBytes = [stringInHex dataUsingEncoding:NSUTF8StringEncoding];
    if (CC_SHA1(stringBytes.bytes, (CC_LONG)stringBytes.length, digest.mutableBytes)) {
        if (digest.length == 0) {
            // fallback if SHA1 failed
            return stringBytes;
        }
        return digest;
    }
    return nil;
}

@end
