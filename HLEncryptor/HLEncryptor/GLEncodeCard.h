//
//  GLEncodeCard.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GLEncodeCard : NSObject

@property (nonatomic, strong, nullable) NSDate *generationtime;
@property (nonatomic, strong, nullable) NSString *number;
@property (nonatomic, strong, nullable) NSString *holderName;
@property (nonatomic, strong, nullable) NSString *cvc;
@property (nonatomic, strong, nullable) NSString *expiryMonth;
@property (nonatomic, strong, nullable) NSString *expiryYear;

+ (nullable GLEncodeCard *)decode:(NSData *)json error:(NSError * _Nullable *)error;
- (nullable NSData *)encode;

@end

NS_ASSUME_NONNULL_END

