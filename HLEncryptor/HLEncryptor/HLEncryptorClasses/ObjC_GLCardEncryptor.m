//
//  ObjC_GLCardEncryptor.m
//  gl-ios
//
//  Created by henvy on 2019/8/20.
//  Copyright © 2019 henvy. All rights reserved.
//

#import "ObjC_GLCardEncryptor.h"
#import "GLEncodeCard.h"
#import "GLCryptor.h"
//#import "GLCard.h"

@implementation ObjC_GLCardEncryptor

+ (NSString *)encryptedNumber:(NSString *)number publicKey:(NSString *)publicKey date:(NSDate *)date {
    GLEncodeCard *card = [GLEncodeCard new];
    card.number = number;
    
    return [ObjC_GLCardEncryptor encryptCard:card withPublicKey:publicKey date:date];
}

+ (NSString *)encryptedSecurityCode:(NSString *)securityCode publicKey:(NSString *)publicKey date:(NSDate *)date {
    GLEncodeCard *card = [GLEncodeCard new];
    card.cvc = securityCode;
    
    return [ObjC_GLCardEncryptor encryptCard:card withPublicKey:publicKey date:date];
}

+ (NSString *)encryptedExpiryMonth:(NSString *)expiryMonth publicKey:(NSString *)publicKey date:(NSDate *)date {
    GLEncodeCard *card = [GLEncodeCard new];
    card.expiryMonth = expiryMonth;
    
    return [ObjC_GLCardEncryptor encryptCard:card withPublicKey:publicKey date:date];
}

+ (NSString *)encryptedExpiryYear:(NSString *)expiryYear publicKey:(NSString *)publicKey date:(NSDate *)date {
    GLEncodeCard *card = [GLEncodeCard new];
    card.expiryYear = expiryYear;
    
    return [ObjC_GLCardEncryptor encryptCard:card withPublicKey:publicKey date:date];
}

+ (NSString *)encryptedToTokenWithNumber:(NSString *)number
                            securityCode:(NSString *)securityCode
                             expiryMonth:(NSString *)expiryMonth
                              expiryYear:(NSString *)expiryYear
                              holderName:(NSString *)holderName
                               publicKey:(NSString *)publicKey {
    GLEncodeCard *card = [GLEncodeCard new];
    card.number = number;
    card.cvc = securityCode;
    card.expiryMonth = expiryMonth;
    card.expiryYear = expiryYear;
    card.holderName = holderName;
    
    return [ObjC_GLCardEncryptor encryptCard:card withPublicKey:publicKey date:[NSDate new]];
}

+ (nullable NSString *)encryptCard:(GLEncodeCard *)card withPublicKey:(NSString *)publicKey date:(NSDate *)date {
    card.generationtime = date;
    
    NSData *encodedCard = [card encode];
    
    if (encodedCard) {
        return [GLCryptor encrypt: encodedCard publicKeyInHex:publicKey];
    }
    
    return nil;
}
@end
