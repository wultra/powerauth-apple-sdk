//
// Copyright 2021 Wultra s.r.o.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.
//

import Foundation
import PowerAuthCore

/// The `Activation` structure contains activation data required for the activation creation.
/// The structure supports all types of activation currently supported in the SDK.
public struct Activation {
    
    /// Defines type of activation.
    public enum ActivationType {
        /// Activation with standard activation code and optional signature.
        case activationCode
        /// Activation with recovery code and PUK.
        case recoveryCode
        /// Activation with a custom identity attributes.
        case custom
    }
    
    /// Type of activation
    public let activationType: ActivationType
    
    
    // The following properties are all internal by purpose,
    // because we cannot guarantee API stability.
    
    /// Contains parsed activation code in case this is a regular activation with activation code.
    let activationCode: PowerAuthCore.ActivationCode?
    /// Contains identity attributes that depends on the type of the activation.
    let identityAttributes: [String:String]
    /// Contains activation name in case that the it was set in constructor.
    let name: String?
    /// Extra attributes of the activation, used for application specific purposes (for example, info about the client
    /// device or system). This extras string will be associated with the activation record on PowerAuth Server.
    let extras: String?
    /// Custom attributes dictionary that are processed on Intermediate Server Application. Note that this custom
    /// data will not be associated with the activation record on PowerAuth Server.
    let customAttributes: [String:Any]?
    /// Additional activation OTP that can be used only with a regular activation, by activation code.
    let additionalActivationOtp: String?
    
    // MARK: Regular activation
    
    /// Construct `Activation` with an already parsed activation code for a regular activation creation process.
    ///
    /// - Parameters:
    ///   - activationCode: Activation code, obtained either via QR code scanning or by manual entry.
    ///   - activationName: Activation name to be used for the activation.
    ///   - extras: Extra attributes of the activation, used for application specific purposes.
    ///   - customAttributes: Custom attributes dictionary that are processed on Intermediate Server Application.
    ///   - additionalActivationOtp: Additional activation OTP.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationData` if additional activation OTP contains an empty string.
    public init(withActivationCode activationCode: ActivationCode,
                activationName: String? = nil,
                extras: String? = nil,
                customAttributes: [String:Any]? = nil,
                additionalActivationOtp: String? = nil) throws {
        self.activationType = .activationCode
        self.activationCode = activationCode.coreActivationCode
        self.identityAttributes = [ "code" : activationCode.activationCode ]
        self.name = activationName
        self.extras = extras
        self.customAttributes = customAttributes
        self.additionalActivationOtp = additionalActivationOtp
        // Validate
        if let additionalActivationOtp = additionalActivationOtp {
            if additionalActivationOtp.isEmpty {
                throw PowerAuthError.invalidActivationData(reason: .emptyOtp)
            }
        }
    }
    
    /// Construct `Activation` with an already parsed activation code for a regular activation creation process.
    /// The activation code may contain an optional signature part, in case that it is scanned from QR code.
    ///
    /// - Parameters:
    ///   - activationCode: Activation code, obtained either via QR code scanning or by manual entry.
    ///   - activationName: Activation name to be used for the activation.
    ///   - extras: Extra attributes of the activation, used for application specific purposes.
    ///   - customAttributes: Custom attributes dictionary that are processed on Intermediate Server Application.
    ///   - additionalActivationOtp: Additional activation OTP.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationData` in case that activation code has wrong format.
    ///   - `PowerAuthError.invalidActivationData` in case that additional activation OTP contains an empty string.
    public init(withActivationCode activationCode: String,
                activationName: String? = nil,
                extras: String? = nil,
                customAttributes: [String:Any]? = nil,
                additionalActivationOtp: String? = nil) throws {
        guard let code = ActivationCodeUtil.parse(fromActivationCode: activationCode) else {
            throw PowerAuthError.invalidActivationData(reason: .wrongActivationCode)
        }
        self.activationType = .activationCode
        self.activationCode = code
        self.identityAttributes = [ "code" : code.activationCode ]
        self.name = activationName
        self.extras = extras
        self.customAttributes = customAttributes
        self.additionalActivationOtp = additionalActivationOtp
        // Validate
        if let additionalActivationOtp = additionalActivationOtp {
            if additionalActivationOtp.isEmpty {
                throw PowerAuthError.invalidActivationData(reason: .emptyOtp)
            }
        }
    }
    
    // MARK: Recovery activation
    
    /// Construct `Activation` with a recovery code and PUK for a recovery activation process purposes.
    ///
    /// - Parameters:
    ///   - recoveryCode: Recovery code, obtained either via QR code scanning or by manual entry.
    ///   - puk: PUK obtained by manual entry.
    ///   - activationName: Activation name to be used for the activation.
    ///   - extras: Extra attributes of the activation, used for application specific purposes.
    ///   - customAttributes: Custom attributes dictionary that are processed on Intermediate Server Application.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationData` in case that recovery code or PUK has wrong format.
    public init(withRecoveryCode recoveryCode: String,
                puk: String,
                activationName: String? = nil,
                extras: String? = nil,
                customAttributes: [String:Any]? = nil) throws {
        guard let code = ActivationCodeUtil.parse(fromRecoveryCode: recoveryCode) else {
            throw PowerAuthError.invalidActivationData(reason: .wrongRecoveryCode)
        }
        guard ActivationCodeUtil.validateRecoveryPuk(puk) else {
            throw PowerAuthError.invalidActivationData(reason: .wrongRecoveryPuk)
        }
        self.activationType = .recoveryCode
        self.activationCode = nil
        self.identityAttributes = [ "recoveryCode" : code.activationCode, "puk": puk ]
        self.name = activationName
        self.extras = extras
        self.customAttributes = customAttributes
        self.additionalActivationOtp = nil
    }
    
    // MARK: Custom activation
    
    
    /// Construct `Activation` with identity attributes, for custom activaton purposes.
    /// - Parameters:
    ///   - identityAttributes: Custom activation parameters that are used to prove identity of a user.
    ///   - activationName: Activation name to be used for the activation.
    ///   - extras: Extra attributes of the activation, used for application specific purposes.
    ///   - customAttributes: Custom attributes dictionary that are processed on Intermediate Server Application.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationData` in case that identity attributes is empty dictionary.
    public init(withIdentityAttributes identityAttributes: [String:String],
                activationName: String? = nil,
                extras: String? = nil,
                customAttributes: [String:Any]? = nil) throws {
        guard !identityAttributes.isEmpty else {
            throw PowerAuthError.invalidActivationData(reason: .emptyIdentityAttributes)
        }
        self.activationType = .custom
        self.activationCode = nil
        self.identityAttributes = identityAttributes
        self.name = activationName
        self.extras = extras
        self.customAttributes = customAttributes
        self.additionalActivationOtp = nil
    }
}
