//
//  GLSha1InHex.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GLSha1InHex : NSObject
+ (NSData *)sha1FromStringInHex:(NSString *)stringInHex;
@end

NS_ASSUME_NONNULL_END
