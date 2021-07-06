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
@testable import PowerAuth

class FakeDataProvider: DataProvider {
    
    let possessionKey: Data
    var biometryKey: Data?
    
    init(possessionKey: Data = Data.random(count: 16), biometryKey: Data? = nil) {
        self.possessionKey = possessionKey
        self.biometryKey = biometryKey
    }
    
    var tokenStoreKeychain: PowerAuthKeychain {
        D.notImplementedYet()
    }
    
    var savedActivationState: Data?
    
    func save(activationState: Data) throws {
        self.savedActivationState = activationState
    }
    
    func activationState() throws -> Data? {
        return self.savedActivationState
    }
    
    func possessionFactorEncryptionKey() throws -> Data {
        return possessionKey
    }
    
    func hasBiometryFactorEncryptionKey() -> Bool {
        return biometryKey != nil
    }
    
    func biometryFactorEncryptionKey(authentication: LAContext) throws -> Data {
        guard let key = biometryKey else {
            throw PowerAuthError.biometricAuthenticationFailed(reason: .notConfigured)
        }
        return key
    }
    
    func save(biometryFactorEncryptionKey: Data) throws {
        self.biometryKey = biometryFactorEncryptionKey
    }
    
    func removeBiometryFactorEncryptionKey() throws {
        self.biometryKey = nil
    }
    
}
