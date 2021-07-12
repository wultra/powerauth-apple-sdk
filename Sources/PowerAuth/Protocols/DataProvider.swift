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
import LocalAuthentication

/// The `DataProvider` protocol defines inernal interface to access various persistent data
/// stored for `PowerAuth` class purposes.
protocol DataProvider {
    
    // MARK: - Keychains
    
    /// Contains reference to keychain containing tokens data.
    var tokenStoreKeychain: PowerAuthKeychain { get }
   
    // MARK: - Activation state
    
    /// Function save activation status data.
    /// - Parameter activationState: Activation status data
    /// - Throws: `PowerAuthError` in case of failure.
    func save(activationState: Data) throws
    
    /// Function restore previously saved status data. If there's no previously saved data, then returns `nil`.
    /// - Returns: Previously saved status data or `nil` if no such data was stored.
    /// - Throws: `PowerAuthError` in case of failure.
    func activationState() throws -> Data?
    
    // MARK: - Factor keys
    
    /// Function returns possession factor encryption key, or create a new one, if key has not been created before.
    /// - Returns: Possession factor encryption key.
    /// - Throws: `PowerAuthError` in case of failure.
    func possessionFactorEncryptionKey() throws -> Data

    /// Function returns `true` if underlying keychain contains biometry factor encryption key.
    func hasBiometryFactorEncryptionKey() -> Bool
    
    /// Function returns biometry factor encryption key. If key is not stored or accessible, then throws error.
    /// - Parameters:
    ///   - authentication: Local authentication object to acquire key from underlying keychain.
    /// - Returns: Biometry factor encryption key.
    /// - Throws: `PowerAuthError` in case of failure.
    func biometryFactorEncryptionKey(authentication: LAContext) throws -> Data
    
    /// Function saves biometry factor encryption key.
    /// - Parameter biometryFactorEncryptionKey: Key to save.
    /// - Throws: `PowerAuthError` in case of failure.
    func save(biometryFactorEncryptionKey: Data) throws
    
    /// Function removes biometry factor encryption key.
    /// - Throws: `PowerAuthError` in case of failure.
    func removeBiometryFactorEncryptionKey() throws
}
