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

// MARK: - KeychainConfiguration -

/// Structure that is used to provide Keychain storage configuration. You can use `.default`
/// configuration or use `KeychainConfiguration.Builder` builder class to build a customized structure.
public struct KeychainConfiguration {
    
    /// Access group name used by the `PowerAuth` keychain instances.
    public let accessGroupName: String?
    
    /// Suite name used by the `UserDefaults` that check for Keychain data presence.
    ///
    /// If the value is not set, `UserDefaults.standardUserDefaults` are used. Otherwise,
    /// user defaults with given suite name are created. In case a developer started using SDK
    /// with no suite name specified, the developer is responsible for migrating data
    /// to the new `UserDefaults` before using the SDK with the new suite name.
    public let userDefaultsSuiteName: String?
    
    /// Name of the Keychain service used to store statuses for different `PowerAuth` instances.
    public let statusKeychainName: String
    
    /// Name of the Keychain service used to store possession factor related key (one value for all `PowerAuth` instances)
    public let possessionKeychainName: String
    
    /// Name of the Keychain service used to store biometry related keys for different `PowerAuth` instances.
    public let biometryKeychainName: String
    
    /// Name of the Keychain service used to store content of `PowerAuthToken` objects.
    public let tokenStoreKeychainName: String
    
    /// Name of the Keychain key used to store possession fator related key in an associated service.
    public let possessionKeyName: String
    
    /// This value specifies 'key' used to store this PowerAuth instance's biometry related key in the biometry key keychain.
    /// If not altered in `Builder` then value from `Configuration.instanceId` is used.
    public let biometryKeyName: String?
    
    /// Default `KeychainConfiguration`.
    public static let `default` = KeychainConfiguration(
        accessGroupName:        nil,
        userDefaultsSuiteName:  nil,
        statusKeychainName:     Constants.KeychainNames.status,
        possessionKeychainName: Constants.KeychainNames.possession,
        biometryKeychainName:   Constants.KeychainNames.biometry,
        tokenStoreKeychainName: Constants.KeychainNames.tokenStore,
        possessionKeyName:      Constants.KeychainNames.possessionKeyName,
        biometryKeyName:        nil
    )
}

// MARK: - KeychainConfiguration.Builder -

public extension KeychainConfiguration {
    
    /// Class that builds `KeychainConfiguration` structure.
    final class Builder {
        
        var accessGroupName: String?
        var userDefaultsSuiteName: String?
        var statusKeychainName: String?
        var possessionKeychainName: String?
        var biometryKeychainName: String?
        var tokenStoreKeychainName: String?
        var possessionKeyName: String?
        var biometryKeyName: String?
        
        /// Construct `Builder` with default parameters.
        public init() {
        }
        
        /// Build `KeychainConfiguration` from collected parameters.
        /// - Throws: `PowerAuthError.invalidConfiguration` In case of failure.
        /// - Returns: `KeychainConfiguration` structure.
        public func build() throws -> KeychainConfiguration {
            let def = KeychainConfiguration.default
            let config = KeychainConfiguration(
                accessGroupName: accessGroupName ?? def.accessGroupName,
                userDefaultsSuiteName: userDefaultsSuiteName ?? def.userDefaultsSuiteName,
                statusKeychainName: statusKeychainName ?? def.statusKeychainName,
                possessionKeychainName: possessionKeychainName ?? def.possessionKeychainName,
                biometryKeychainName: biometryKeychainName ?? def.biometryKeychainName,
                tokenStoreKeychainName: tokenStoreKeychainName ?? def.tokenStoreKeychainName,
                possessionKeyName: possessionKeyName ?? def.possessionKeyName,
                biometryKeyName: biometryKeyName)
            try config.validate()
            return config
        }
        
        
        /// Change access group name used by the `PowerAuth` keychain instances.
        ///
        /// - Parameter accessGroupName: New access group name.
        /// - Returns: `Builder` instance
        public func set(accessGroupName: String) -> Builder {
            self.accessGroupName = accessGroupName
            return self
        }
        
        /// Change suite name used by the `UserDefaults` that check for Keychain data presence.
        ///
        /// If the value is not set, `UserDefaults.standardUserDefaults` are used. Otherwise,
        /// user defaults with given suite name are created. In case a developer started using SDK
        /// with no suite name specified, the developer is responsible for migrating data
        /// to the new `UserDefaults` before using the SDK with the new suite name.
        ///
        /// - Parameter userDefaultsSuiteName: New `UserDefaults` suite name.
        /// - Returns: `Builder` instance.
        public func set(userDefaultsSuiteName: String) -> Builder {
            self.userDefaultsSuiteName = userDefaultsSuiteName
            return self
        }
        
        /// Change name of the Keychain service used to store statuses for different `PowerAuth` instances.
        /// - Parameter statusKeychainName: New name of the status keychain service.
        /// - Returns: `Builder` instance.
        public func set(statusKeychainName: String) -> Builder {
            self.statusKeychainName = statusKeychainName
            return self
        }
        
        /// Change name of the Keychain service used to store statuses for different `PowerAuth` instances.
        ///
        /// - Parameter possessionKeychainName: New name of the possession keychain service.
        /// - Returns: `Builder` instance.
        public func set(possessionKeychainName: String) -> Builder {
            self.possessionKeychainName = possessionKeychainName
            return self
        }
        
        /// Change name of the Keychain service used to store biometry related keys for different `PowerAuth` instances.
        /// - Parameter biometryKeychainName: New name of the biometry keychain service.
        /// - Returns: `Builder` instance.
        public func set(biometryKeychainName: String) -> Builder {
            self.biometryKeychainName = biometryKeychainName
            return self
        }
        
        /// Change name of the Keychain service used to store content of `PowerAuthToken` objects.
        /// - Parameter tokenStoreKeychainName: New name of token store keychain service.
        /// - Returns: `Builder` instance.
        public func set(tokenStoreKeychainName: String) -> Builder {
            self.tokenStoreKeychainName = tokenStoreKeychainName
            return self
        }
        
        /// Change name of the Keychain key used to store possession fator related key in an associated service.
        /// - Parameter possessionKeyName: New name of key.
        /// - Returns: `Builder` instance.
        public func set(possessionKeyName: String) -> Builder {
            self.possessionKeyName = possessionKeyName
            return self
        }
        
        /// Change 'key' used to store PowerAuth instance's biometry related key in the biometry key keychain.
        /// If not altered then value from `Configuration.instanceId` is used.
        /// - Parameter biometryKeyName: Key used to store this PowerAuth instance biometry related key in the biometry key keychain.
        /// - Returns: `Builder` instance
        public func set(biometryKeyName: String) -> Builder {
            self.biometryKeyName = biometryKeyName
            return self
        }
    }
    
    
    /// Validates content of structure.
    /// - Throws: `PowerAuthError.invalidConfiguration` in case of failure.
    fileprivate func validate() throws {
        guard !(accessGroupName?.isEmpty ?? false) else {
            D.error("KeychainConfiguration has empty 'accessGroupName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !(userDefaultsSuiteName?.isEmpty ?? false) else {
            D.error("KeychainConfiguration has empty 'userDefaultsSuiteName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !statusKeychainName.isEmpty else {
            D.error("KeychainConfiguration has empty 'statusKeychainName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !possessionKeychainName.isEmpty else {
            D.error("KeychainConfiguration has empty 'possessionKeychainName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !biometryKeychainName.isEmpty else {
            D.error("KeychainConfiguration has empty 'biometryKeychainName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !tokenStoreKeychainName.isEmpty else {
            D.error("KeychainConfiguration has empty 'tokenStoreKeychainName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !possessionKeyName.isEmpty else {
            D.error("KeychainConfiguration has empty 'possessionKeyName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        guard !(biometryKeyName?.isEmpty ?? false) else {
            D.error("KeychainConfiguration has empty 'biometryKeyName' parameter.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
        }
        let keychainNames = [ possessionKeychainName, statusKeychainName, biometryKeychainName, tokenStoreKeychainName ]
        for i in 0..<keychainNames.count {
            for j in 0..<keychainNames.count {
                if i != j && keychainNames[i] == keychainNames[j] {
                    D.error("Keychain names in KeychainConfiguration must be unique.")
                    throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
                }
            }
        }
    }
}
