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
import LocalAuthentication

/// The `Authentication` structure representing multi-factor authentication object.
/// You must provide this object to all PowerAuth functions that calculate PowerAuth
/// multifactor symmetric signature.
public struct Authentication {
    
    /// Factors involved for the signature calculation.
    public enum Factors {
        /// Calculate signature for possession factor only.
        case possession
        /// Calculate signature for possession and knowledge factors.
        case possessionWithKnowledge
        /// Calculate signature for possession and biometry factors.
        case possessionWithBiometry
    }
    
    /// Combination of factors for the signature calculation.
    public let factors: Factors

    /// User's password, must be provided for `Factors.possession`
    let password: Password?
    /// LAContext for the biometric authentication if `Factors.possessionWithBiometry` is used. It's required
    /// for such combination of factors, unless you provide `customBiometryKey`.
    let localAuthentication: LAContext?
    /// Overriden possession key. If not provided, then the default possession key will be used.
    let customPossessionKey: Data?
    /// Overriden biometry key. If not provided, then the default biometry key for the PowerAuth instance,
    /// based on the keychain and instance configuration.
    let customBiometryKey: Data?
}


public extension Authentication {
    
    /// Create `Authentication` structure configured for possession factor only signature calculation.
    /// - Parameter customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for possession factor only signature calculation.
    static func possession(customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .possession,
            password: nil,
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil
        )
    }
    
    /// Create `Authentication` structure configured for possession and biometry factors signature calculation.
    /// - Parameters:
    ///   - localAuthentication: `LAContext` for local biometric authentication.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for possession and biometry factors signature calculation.
    static func biometryWithPossession(localAuthentication: LAContext, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .possessionWithBiometry,
            password: nil,
            localAuthentication: localAuthentication,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil
        )
    }
    
    /// Create `Authentication` structure configured for possession and biometry factors signature calculation.
    /// - Parameters:
    ///   - customBiometryKey: Custom biometry key.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for possession and biometry factors signature calculation.
    static func biometryWithPossession(customBiometryKey: Data, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .possessionWithBiometry,
            password: nil,
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: customBiometryKey
        )
    }
    
    /// Create `Authentication` structure configured for possession and knowledge factors signature calculation.
    /// - Parameters:
    ///   - password: String with user's password.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for possession and knowledge factors signature calculation.
    static func knowledgeWithPossession(password: String, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .possessionWithKnowledge,
            password: Password(string: password),
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil
        )
    }
    
    /// Create `Authentication` structure configured for possession and knowledge factors signature calculation.
    /// - Parameters:
    ///   - password: `PowerAuthCore.Password` object with user's password.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for possession and knowledge factors signature calculation.
    static func knowledgeWithPossession(password: Password, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .possessionWithKnowledge,
            password: password,
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil
        )
    }
}

extension Authentication {
    
    /// Internal function that create `PowerAuthCore.SignatureFactorkKeys` object created from this structure data.
    /// - Parameter dataProvider: `DataProvider` that provide factor keys.
    /// - Throws: `PowerAuthError.internalError` in case that unhandled combination of factor and associated data is detected.
    /// - Returns: `PowerAuthCore.SignatureFactorkKeys` object created from this structure data.
    func getSignatureFactorKeys(with dataProvider: DataProvider) throws -> PowerAuthCore.SignatureFactorkKeys {
        let possessionKey = try customPossessionKey ?? dataProvider.possessionFactorEncryptionKey()
        switch factors {
            case .possession:
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: nil)
            case .possessionWithKnowledge:
                guard let pasword = password else {
                    throw PowerAuthError.internalError(reason: "Password is required but not provided")
                }
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: pasword)
            case .possessionWithBiometry:
                let biometryKey: Data
                if let customBiometryKey = customBiometryKey {
                    biometryKey = customBiometryKey
                } else if let localAuthentication = localAuthentication {
                    biometryKey = try dataProvider.biometryFactorEncryptionKey(authentication: localAuthentication)
                } else {
                    throw PowerAuthError.internalError(reason: "Biometry factor key is required but not provided")
                }
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: biometryKey, password: nil)
        }
    }
}
