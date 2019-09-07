//
//  GLEncryptedCard.swift
//  gl-ios
//
//  Created by henvy on 2019/8/21.
//  Copyright © 2019 henvy. All rights reserved.
//

import UIKit

open class EncryptedCard: NSObject {
    
    /// The encrypted card number.
    open var number: String?
    
    /// The card's encrypted security code.
    open var securityCode: String?
    
    /// The encrypted month the card expires.
    open var expiryMonth: String?
    
    /// The encrypted year the card expires.
    open var expiryYear: String?
    
    open class func encryptedCard(for card: Card, publicKey: String) -> EncryptedCard {
        let generationDate = Date()
        
        let encryptedCard = EncryptedCard()
        encryptedCard.number = ObjC_GLCardEncryptor.encryptedNumber(card.number, publicKey: publicKey, date: generationDate)
        encryptedCard.securityCode = ObjC_GLCardEncryptor.encryptedSecurityCode(card.securityCode, publicKey: publicKey, date: generationDate)
        encryptedCard.expiryMonth = ObjC_GLCardEncryptor.encryptedExpiryMonth(card.expiryMonth, publicKey: publicKey, date: generationDate)
        encryptedCard.expiryYear = ObjC_GLCardEncryptor.encryptedExpiryYear(card.expiryYear, publicKey: publicKey, date: generationDate)
        
        return encryptedCard
    }
    
}
