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
    /// Contains activation name in case that the it was set in builder.
    let name: String?
    /// Contains extra attributes string in case it was set in builder.
    let extras: String?
    /// Contains custom attributes dictionary in case it was set in builder.
    let customAttributes: [String:Any]?
    /// Contains additional activation OTP in case it was set in builder.
    let additionalActivationOtp: String?
}

public extension Activation {
    
    /// Class that builds `Activation` structure.
    class Builder {
        
        let activationType: ActivationType
        let identityAttributes: [String:String]
        var activationCode: PowerAuthCore.ActivationCode?
        var name: String?
        var extras: String?
        var customAttributes: [String:Any]?
        var additionalActivationOtp: String?
        
        /// Construct `Builder` for building activation with an already parsed activation code.
        ///
        /// - Parameters:
        ///   - activationCode: Activation code, obtained either via QR code scanning or by manual entry.
        ///   - activationName: Activation name to be used for the activation.
        /// - Throws: `PowerAuthError.invalidActivationData` in case that wrong activation code is provided.
        public init(withActivationCode activationCode: ActivationCode, activationName: String? = nil) {
            self.activationType = .activationCode
            self.identityAttributes = [ "code" : activationCode.activationCode ]
            self.activationCode = activationCode.coreActivationCode
            self.name = activationName
        }
        
        /// Construct `Builder` for building activation with an activation code. The activation code may contain
        /// an optional signature part, in case that it is scanned from QR code.
        ///
        /// - Parameters:
        ///   - activationCode: Activation code, obtained either via QR code scanning or by manual entry.
        ///   - activationName: Activation name to be used for the activation.
        /// - Throws: `PowerAuthError.invalidActivationData` in case that wrong activation code is provided.
        public init(withActivationCode activationCode: String, activationName: String? = nil) throws {
            guard let code = ActivationCodeUtil.parse(fromActivationCode: activationCode) else {
                throw PowerAuthError.invalidActivationData(reason: .wrongActivationCode)
            }
            self.activationType = .activationCode
            self.identityAttributes = [ "code" : code.activationCode ]
            self.activationCode = code
            self.name = activationName
        }
        
        /// Construct `Builder` for building activation with a recovery code and PUK.
        ///
        /// - Parameters:
        ///   - recoveryCode: Recovery code, obtained either via QR code scanning or by manual entry.
        ///   - puk: PUK obtained by manual entry.
        ///   - activationName: Activation name to be used for the activation.
        /// - Throws: `PowerAuthError.invalidActivationData` in case that wrong recovery code, or wrong PUK is provided.
        public init(withRecoveryCode recoveryCode: String, puk: String, activationName: String? = nil) throws {
            guard let code = ActivationCodeUtil.parse(fromRecoveryCode: recoveryCode) else {
                throw PowerAuthError.invalidActivationData(reason: .wrongRecoveryCode)
            }
            guard ActivationCodeUtil.validateRecoveryPuk(puk) else {
                throw PowerAuthError.invalidActivationData(reason: .wrongRecoveryPuk)
            }
            self.activationType = .recoveryCode
            self.identityAttributes = [ "recoveryCode" : code.activationCode, "puk": puk ]
            self.name = activationName
        }
        
        /// Construct `Builder` for building activation with identity attributes, for custom activaton purposes.
        ///
        /// - Parameters:
        ///   - identityAttributes: Custom activation parameters that are used to prove identity of a user.
        ///   - activationName: Activation name to be used for the activation.
        public init(withIdentityAttributes identityAttributes: [String:String], activationName: String? = nil) {
            self.activationType = .custom
            self.identityAttributes = identityAttributes
            self.name = activationName
        }
        
        /// Sets extra attributes of the activation, used for application specific purposes (for example, info about the client
        /// device or system). This extras string will be associated with the activation record on PowerAuth Server.
        ///
        /// - Parameter extras: Extra attributes string.
        /// - Returns: `Builder` instance.
        public func set(extras: String) -> Builder {
            self.extras = extras
            return self
        }
        
        /// Sets custom attributes dictionary that are processed on Intermediate Server Application.
        /// Note that this custom data will not be associated with the activation record on PowerAuth Server.
        ///
        /// - Parameter customAttributes: Custom attributes. The provided dictionary must contain only objects that conforms to `Codable` protocol.
        /// - Returns: `Builder` instance.
        public func set(customAttributes: [String:Any]) -> Builder {
            self.customAttributes = customAttributes
            return self
        }
        
        /// Sets an additional activation OTP that can be used only with a regular activation, by activation code.
        ///
        /// - Parameter additionalActivationOtp: Additional activation OTP.
        /// - Returns: `Builder` instance.
        public func set(additionalActivationOtp: String) -> Builder {
            self.additionalActivationOtp = additionalActivationOtp
            return self
        }
        
        /// Build `Activation` structure from collected parameters.
        ///
        /// - Throws: `PowerAuthError.invalidActivationData` in case that invalid combination of activation data is provided.
        /// - Returns: `Activation` structure created from collected parameters.
        public func build() throws -> Activation {
            if let additionalActivationOtp = additionalActivationOtp {
                if activationType != .activationCode {
                    throw PowerAuthError.invalidActivationData(reason: .otpInWrongActivationType)
                }
                if additionalActivationOtp.isEmpty {
                    throw PowerAuthError.invalidActivationData(reason: .emptyOtp)
                }
            }
            return Activation(
                activationType: activationType,
                activationCode: activationCode,
                identityAttributes: identityAttributes,
                name: name,
                extras: extras,
                customAttributes: customAttributes,
                additionalActivationOtp: additionalActivationOtp
            )
        }
    }
}
