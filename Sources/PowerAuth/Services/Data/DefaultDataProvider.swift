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
import PowerAuthShared
import PowerAuthCore
import LocalAuthentication

/// The `DefaultDataProvider` class implements `DataProvider` protocol with using system
/// keychain as an underlying data storage facility.
class DefaultDataProvider: DataProvider {
    
    let instanceIdentifier: String
    let keychainKeyForPossesionFactor: String
    let keychainKeyForBiometryFactor: String
    let keychainItemAccessForBiometryFactor: PowerAuthKeychainItemAccess
    
    /// Initialize default data provider with provided `KeychainConfiguration`.
    /// - Parameter configuration: `KeychainConfiguration` structure
    /// - Throws:
    ///   - `PowerAuthError.invalidConfiguration` in case that `KeychainConfiguration` contains invalid configuration. Check debug log for more details.
    ///   - `PowerAuthError.unexpectedFailure` in case that other type of error occured.
    init(with configuration: PowerAuth.PrivateConfiguration) throws {
        do {
            let keychainConfiguration = configuration.keychain
            let accessGroup = configuration.keychain.accessGroupName
            let factory = try KeychainFactory.factory(for: keychainConfiguration)
            // Keys & Identifiers
            self.instanceIdentifier = configuration.instance.instanceId
            self.keychainKeyForPossesionFactor = configuration.keychainKeyForPossesionFactor
            self.keychainKeyForBiometryFactor = configuration.keychainKeyForBiometryFactor
            self.keychainItemAccessForBiometryFactor = configuration.biometry.keychainItemAccessProtection
            // Keychains...
            self.statusKeychain = try factory.keychain(identifier: keychainConfiguration.statusKeychainName, accessGroup: accessGroup)
            self.possessionKeychain = try factory.keychain(identifier: keychainConfiguration.possessionKeychainName, accessGroup: accessGroup)
            self.biometryKeychain = try factory.keychain(identifier: keychainConfiguration.biometryKeychainName, accessGroup: accessGroup)
            self.tokenStoreKeychain = try factory.keychain(identifier: keychainConfiguration.tokenStoreKeychainName, accessGroup: accessGroup)
        } catch PowerAuthKeychainError.invalidAccessGroup {
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    // MARK: - DataProvider
    
    let statusKeychain: PowerAuthKeychain
    let possessionKeychain: PowerAuthKeychain
    let biometryKeychain: PowerAuthKeychain
    let tokenStoreKeychain: PowerAuthKeychain
    
    func save(activationState: Data) throws {
        do {
            try statusKeychain.set(activationState, forKey: instanceIdentifier)
        } catch {
            D.error("DefaultDataProvider failed to save activation state: \(error.localizedDescription)")
            throw PowerAuthError.wrap(error)
        }
    }
    
    func activationState() throws -> Data? {
        return try? statusKeychain.data(forKey: instanceIdentifier)
    }
    
    func possessionFactorEncryptionKey() throws -> Data {
        do {
            return try possessionKeychain.data(forKey: keychainKeyForPossesionFactor, orSet: try CryptoUtils.randomBytes(count: Constants.KeySizes.SIGNATURE_FACTOR_KEY_SIZE))
        } catch {
            D.error("DefaultDataProvider failed to acquire possesion factor key: \(error.localizedDescription)")
            throw PowerAuthError.wrap(error)
        }
    }
    
    func hasBiometryFactorEncryptionKey() -> Bool {
        return biometryKeychain.containsData(forKey: keychainKeyForBiometryFactor)
    }
    
    func biometryFactorEncryptionKey(authentication: LAContext) throws -> Data {
        do {
            guard let key = try biometryKeychain.data(forKey: keychainKeyForBiometryFactor, authentication: authentication) else {
                throw PowerAuthError.biometricAuthenticationFailed(reason: .notConfigured)
            }
            return key
        } catch PowerAuthKeychainError.biometryNotAvailable {
            throw PowerAuthError.biometricAuthenticationFailed(reason: .notAvailable)
        } catch {
            D.error("DefaultDataProvider failed to acquire biometry factor key: \(error.localizedDescription)")
            throw PowerAuthError.wrap(error)
        }
    }
    
    func save(biometryFactorEncryptionKey: Data) throws {
        do {
            try biometryKeychain.set(biometryFactorEncryptionKey, for: keychainKeyForBiometryFactor, access: keychainItemAccessForBiometryFactor)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    func removeBiometryFactorEncryptionKey() throws {
        do {
            try biometryKeychain.remove(forKey: keychainKeyForBiometryFactor)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
}


extension BiometryConfiguration {
    
    /// Determine `PowerAuthKeychainItemAccess` protection from the biometric configuration
    var keychainItemAccessProtection: PowerAuthKeychainItemAccess {
        if allowBiometricAuthenticationFallbackToDevicePasscode {
            return .anyBiometricSetOrDevicePasscode
        } else if linkBiometricItemsToCurrentSet {
            return .currentBiometricSet
        } else {
            return .anyBiometricSet
        }
    }
}
