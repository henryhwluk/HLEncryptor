//
//  GLRSACryptor.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GLRSACryptor : NSObject

+ (NSData *)encrypt:(NSData *)data withKeyInHex:(NSString *)keyInHex;
@end

NS_ASSUME_NONNULL_END
