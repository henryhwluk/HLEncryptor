//
//  GLDataFromHex.m
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import "GLDataFromHex.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation GLDataFromHex
+ (NSData *)dataFromHex:(NSString *)hex {
    NSParameterAssert(hex);
    
    hex = [hex stringByReplacingOccurrencesOfString:@" " withString:@""];
    if (hex.length & 1) {
        hex = [@"0" stringByAppendingString:hex];
    }
    NSMutableData *data = [[NSMutableData alloc] initWithCapacity:hex.length/2];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < [hex length]/2; i++) {
        byte_chars[0] = [hex characterAtIndex:i*2];
        byte_chars[1] = [hex characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}
@end
