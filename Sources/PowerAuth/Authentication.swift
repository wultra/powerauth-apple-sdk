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
        /// Commit new activation with possession and knowledge factors.
        case commitWithKnowledge
        /// Commit new activation with possession, knowledge and biometry factors.
        case commitWithKnowledgeAndBiometry
    }
    
    /// Combination of factors for the signature calculation.
    public let factors: Factors

    // TODO: Make this structure serializable with using `PowerAuthCore.SignatureFactorkKeys` as a construction option.
    //       This is required by React Native that must keep object somehow in JS context.
    
    /// User's password, must be provided for `Factors.possession`
    let password: PowerAuthCore.Password?
    /// LAContext for the biometric authentication if `Factors.possessionWithBiometry` is used. It's required
    /// for such combination of factors, unless you provide `customBiometryKey`.
    let localAuthentication: LAContext?
    /// Overriden possession key. If not provided, then the default possession key will be used.
    let customPossessionKey: Data?
    /// Overriden biometry key. If not provided, then the default biometry key for the PowerAuth instance,
    /// based on the keychain and instance configuration.
    let customBiometryKey: Data?
}

// MARK: - Authentication for commit

public extension Authentication {

    /// Create `Authentication` structure configured for activation commit with possession and knowledge factors.
    /// - Parameters:
    ///   - password: `PowerAuthCore.Password` object with user's password.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for activation commit with possession and knowledge factors.
    static func commitWithKnowledge(password: PowerAuthCore.Password, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .commitWithKnowledge,
            password: password,
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil)
    }
    
    /// Create `Authentication` structure configured for activation commit with possession and knowledge factors.
    /// - Parameters:
    ///   - password: String with user's password.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` configured for activation commit with possession and knowledge factors.
    static func commitWithKnowledge(password: String, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .commitWithKnowledge,
            password: Password(string: password),
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: nil)
    }
    
    /// Create `Authentication` structure configured for activation commit with possession, knowledge and biometry factors.
    /// - Parameters:
    ///   - password: `PowerAuthCore.Password` object with user's password.
    ///   - customBiometryKey: Optional biometry key. If not provided, then new biometry key will be configured.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` structure configured for activation commit with possession, knowledge and biometry factors.
    static func commitWithKnowledgeAndBiometry(password: PowerAuthCore.Password, customBiometryKey: Data? = nil, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .commitWithKnowledgeAndBiometry,
            password: password,
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: customBiometryKey)
    }
    
    /// Create `Authentication` structure configured for activation commit with possession, knowledge and biometry factors.
    /// - Parameters:
    ///   - password: String with user's password.
    ///   - customBiometryKey: Optional biometry key. If not provided, then new biometry key will be configured.
    ///   - customPossessionKey: Optional possession key. If not provided, then the default possession key will be used.
    /// - Returns: `Authentication` structure configured for activation commit with possession, knowledge and biometry factors.
    static func commitWithKnowledgeAndBiometry(password: String, customBiometryKey: Data? = nil, customPossessionKey: Data? = nil) -> Authentication {
        Authentication(
            factors: .commitWithKnowledgeAndBiometry,
            password: Password(string: password),
            localAuthentication: nil,
            customPossessionKey: customPossessionKey,
            customBiometryKey: customBiometryKey)
    }
}

// MARK: - Authentication for signature computation

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
    /// - Parameters:
    ///   - dataProvider: `DataProvider` that provide factor keys.
    ///   - firstLock: If `true` then the missing keys are created automatically.
    /// - Throws:
    ///   - `PowerAuthError.invalidAuthenticationData` in case that some required data is not provided.
    ///   - `PowerAuthError.internalError` in case that password object is not provided.
    /// - Returns: `PowerAuthCore.SignatureFactorkKeys` object created from this structure data.
    func getSignatureFactorKeys(with dataProvider: DataProvider, firstLock: Bool = false) throws -> PowerAuthCore.SignatureFactorkKeys {
        let possessionKey = try customPossessionKey ?? dataProvider.possessionFactorEncryptionKey()
        if factors == .commitWithKnowledge || factors == .commitWithKnowledgeAndBiometry || factors == .possessionWithKnowledge {
            // Test for password existence
            guard let password = password else {
                // This is internal error, so we have to fix how `Authentication` object is constructed.
                throw PowerAuthError.internalError(reason: "Password is required but not provided for \(factors)")
            }
            // TODO: This is also tested in PowerAuthCore, so we should report a special error code from core and wrap it automatically
            guard password.length() >= Constants.KeySizes.MIN_PASSWORD_LENGTH else {
                throw PowerAuthError.invalidAuthenticationData(reason: .passwordIsTooShort)
            }
        }
        switch factors {
            case .possession:
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: nil)
                
            case .possessionWithKnowledge:
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: password)
                
            case .possessionWithBiometry:
                let biometryKey: Data
                if let customBiometryKey = customBiometryKey {
                    biometryKey = customBiometryKey
                } else if let localAuthentication = localAuthentication {
                    biometryKey = try dataProvider.biometryFactorEncryptionKey(authentication: localAuthentication)
                } else {
                    throw PowerAuthError.invalidAuthenticationData(reason: .localAuthenticationContextIsMissing)
                }
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: biometryKey, password: nil)
                
            case .commitWithKnowledge:
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: password)
                
            case .commitWithKnowledgeAndBiometry:
                let biometryKey = try customBiometryKey ?? CryptoUtils.randomBytes(count: Constants.KeySizes.SIGNATURE_FACTOR_KEY_SIZE)
                try dataProvider.save(biometryFactorEncryptionKey: biometryKey)
                return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: biometryKey, password: password)
        }
    }
    
    
    /// Validate authentication structure whether is configured for required list of factors for data signing.
    /// - Parameter requiredFactors: List of required factors that must be configured in authentication structure.
    /// - Throws: `PowerAuthError.invalidAuthenticationData` with proper reason.
    func validate(factorsForSigning requiredFactors: [Authentication.Factors]) throws {
        guard requiredFactors.contains(factors) else {
            if factors.isFactorsForActivationCommit {
                throw PowerAuthError.invalidAuthenticationData(reason: .authenticationForSigningIsRequired)
            }
            throw PowerAuthError.invalidAuthenticationData(reason: .requiredFactorIsMissing)
        }
    }
    
    
    /// Validate authentication structure whether is configured for commit or signing operation and throws
    /// `PowerAuthError.invalidAuthenticationData` error if structure contains wrong class of factors.
    ///
    /// - Parameter requireCommit: If `true` then factors for commit is required.
    /// - Throws: `PowerAuthError.invalidAuthenticationData` in case that structure contains wrong class of factors.
    func validate(factorsForCommit requireCommit: Bool) throws {
        guard factors.isFactorsForActivationCommit == requireCommit else {
            if requireCommit {
                throw PowerAuthError.invalidAuthenticationData(reason: .authenticationForCommitIsRequired)
            } else {
                throw PowerAuthError.invalidAuthenticationData(reason: .authenticationForSigningIsRequired)
            }
        }
    }
}

extension Authentication.Factors {
    
    /// Contains `true` if factors combination represents first activation commit.
    var isFactorsForActivationCommit: Bool {
        return self == .commitWithKnowledge || self == .commitWithKnowledgeAndBiometry
    }
}
