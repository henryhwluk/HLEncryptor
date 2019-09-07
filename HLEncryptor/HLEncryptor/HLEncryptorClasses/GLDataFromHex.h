//
//  GLDataFromHex.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GLDataFromHex : NSObject
+ (NSData *)dataFromHex:(NSString *)hex;
@end

NS_ASSUME_NONNULL_END
