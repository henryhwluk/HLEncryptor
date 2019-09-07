//
//  ObjC_GLCardEncryptor.h
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ObjC_GLCardEncryptor : NSObject

+ (nullable NSString *)encryptedNumber:(nullable NSString *)number
                             publicKey:(nonnull NSString *)publicKey
                                  date:(nonnull NSDate *)date;

+ (nullable NSString *)encryptedSecurityCode:(nullable NSString *)securityCode
                                   publicKey:(nonnull NSString *)publicKey
                                        date:(nonnull NSDate *)date;

+ (nullable NSString *)encryptedExpiryMonth:(nullable NSString *)expiryMonth
                                  publicKey:(nonnull NSString *)publicKey
                                       date:(nonnull NSDate *)date;

+ (nullable NSString *)encryptedExpiryYear:(nullable NSString *)expiryYear
                                 publicKey:(nonnull NSString *)publicKey
                                      date:(nonnull NSDate *)date;

+ (nullable NSString *)encryptedToTokenWithNumber:(nullable NSString *)number
                                     securityCode:(nullable NSString *)securityCode
                                      expiryMonth:(nullable NSString *)expiryMonth
                                       expiryYear:(nullable NSString *)expiryYear
                                       holderName:(nullable NSString *)holderName
                                        publicKey:(nonnull NSString *)publicKey;

@end

NS_ASSUME_NONNULL_END
