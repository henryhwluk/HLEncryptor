//
//  GLCard.swift
//  gl-ios
//
//  Created by henvy on 2019/8/21.
//  Copyright © 2019 henvy. All rights reserved.
//

import UIKit

open class Card: NSObject {
    
    /// The card number.
    open var number: String?
    
    /// The card's security code.
    open var securityCode: String?
    
    /// The month the card expires.
    open var expiryMonth: String?
    
    /// The year the card expires.
    open var expiryYear: String?
    
    
    public init(number: String? = nil, securityCode: String? = nil, expiryMonth: String? = nil, expiryYear: String? = nil) {
        self.number = number
        self.securityCode = securityCode
        self.expiryMonth = expiryMonth
        self.expiryYear = expiryYear
    }
    
}
