//
//  GLAESCCMCryptor.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GLAESCCMCryptor : NSObject
+ (nullable NSData *)encrypt:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv;
+ (nullable NSData *)encrypt:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv
                   tagLength:(size_t)tagLength adata:(nullable NSData *)adata;
@end

NS_ASSUME_NONNULL_END
