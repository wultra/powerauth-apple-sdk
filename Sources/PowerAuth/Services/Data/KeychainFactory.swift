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

/// The `KeychainFactory` helper class provides instance of `PowerAuthKeychainFactory`
/// configured to cleanup all keychain content in case that application was reinstalled.
class KeychainFactory {
    
    private static let lock = Lock()
    private static var keychainFactory: PowerAuthKeychainFactory?
    
    private static var hasUserDefaultsSuiteName = false
    private static var userDefaultsSuiteName: String?
    
    /// Get `PowerAuthKeychainFactory` configured to cleanup all future produced keychains
    /// - Parameter configuration: `KeychainConfiguration`
    /// - Throws: `PowerAuthError.invalidConfiguration` in case you alter `userDefaultsSuiteName` during the factory lifetime.
    /// - Returns: Singleton instance of `PowerAuthKeychainFactory`
    static func factory(for configuration: KeychainConfiguration) throws -> PowerAuthKeychainFactory {
        return try lock.synchronized {
            // Validate `userDefaultsSuiteName` across all used configurations
            if hasUserDefaultsSuiteName {
                // Keychain factory has been previously accessed, so compare suite name.
                guard configuration.userDefaultsSuiteName == userDefaultsSuiteName else {
                    D.error("All KeychainConfiguration stcutures must have the same value for `userDefaultsSuiteName` parameter")
                    throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
                }
            } else {
                // Keep suite name for later validation
                hasUserDefaultsSuiteName = true
                userDefaultsSuiteName = configuration.userDefaultsSuiteName
            }
            // Check whether factory already exists.
            if let factory = keychainFactory {
                return factory
            }
            // Determine whether factory must cleanup all keychains. To do this, PowerAuth SDK use
            // boolean constant stored in UserDefaults. If such boolean is not present, then
            // it means that application has been reinstalled, or this is the first application installation.
            let userDefaults: UserDefaults
            if let suiteName = userDefaultsSuiteName {
                // Application wants to use custom UserDefaults object
                guard let customUserDefaults = UserDefaults(suiteName: suiteName) else {
                    D.error("KeychainConfiguration has invalid user defaults suite name: \(suiteName)")
                    throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
                }
                userDefaults = customUserDefaults
            } else {
                // No suite name provided, then use UserDefaults.standard
                userDefaults = .standard
            }
            // Determine whether the keychains content must be wiped out.
            let cleanupAllKeychains: Bool = !userDefaults.bool(forKey: Constants.KeychainNames.keychainInitializedKey)
            if cleanupAllKeychains {
                D.warning("Content of ALL keychains will be removed due to application reinstallation. You can ignore this warning if this is the first time the application starts.")
                userDefaults.set(true, forKey: Constants.KeychainNames.keychainInitializedKey)
                userDefaults.synchronize()
            }
            let factory = PowerAuthKeychainFactory(removeContentOnFirstAccess: cleanupAllKeychains)
            keychainFactory = factory
            return factory
        }
    }
}
