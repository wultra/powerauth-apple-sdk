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
import LocalAuthentication

public extension PowerAuth {
    
    /// Checks if a biometry related factor is present.
    var hasBiometryFactor: Bool {
        // TODO: update documentation with information about getting biometry status on device
        session.hasBiometryFactor() && dataProvider.hasBiometryFactorEncryptionKey()
    }
    
    /// Remove the biometry related factor key.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` - if instance has no activation.
    func removeBiometryFactor() throws {
        do {
            try session.removeBiometryFactor()
            try saveActivationState()
            try dataProvider.removeBiometryFactorEncryptionKey()
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    /// Regenerate a biometry related factor key.
    ///
    /// This method calls PowerAuth Standard RESTful API endpoint `/pa/vault/unlock` to obtain the vault encryption
    /// key used for original private key decryption.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` with knowledge and possession factors configured for data signing.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from adding biometry factor operation.
    ///   - result: Result that is always `true` in case of success.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` - if instance has no activation or biometry factor is already set.
    ///   - `PowerAuthError.invalidAuthenticationData` - if knowledge factor is missing in authentication object.
    /// - Returns: `OperationTask` associated with the running request.
    func addBiometryFactor(with authentication: Authentication, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) throws -> OperationTask {
        guard hasValidActivation else {
            throw PowerAuthError.invalidActivationState(reason: .missingActivation)
        }
        guard hasBiometryFactor else {
            throw PowerAuthError.invalidActivationState(reason: .biometryFactorAlreadySet)
        }
        try authentication.validate(factorsForSigning: [.possessionWithKnowledge])
        D.notImplementedYet()
    }
    
    
    /// Prepare `Authentication` object for future PowerAuth signature calculation with a biometry and possession factors involved.
    ///
    /// The method is useful for situations where business processes require compute two or more different PowerAuth biometry signatures
    /// in one interaction with the user. To achieve this, the application must acquire the custom-created `Authentication` object first
    /// and then use it for the required signature calculations. It's recommended to keep this instance referenced only for a limited time,
    /// required for all future signature calculations.
    ///
    /// Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the
    /// `401` HTTP status code. If you do, then you risk blocking the user's activation on the server.
    ///
    /// - Parameters:
    ///   - localAuthentication: `LAContext` for biometric authentication
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive `Authentication` object.
    ///   - result: Result with `Authentication` structure in case of success. The following errors are reported in case of failure:
    ///     - `PowerAuthError.biometricAuthenticationCancel` if user did cancel biometric authentication dialog.
    ///     - `PowerAuthError.biometricAuthenticationFailed` if biometric authentication failed.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` - if instance has no activation.
    func authenticateUsingBiometry(localAuthentication: LAContext, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Authentication, PowerAuthError>) -> Void) throws {
        guard hasValidActivation else {
            throw PowerAuthError.invalidActivationState(reason: .missingActivation)
        }
    }
    
    // TODO: Do we need old `unlockBiometryKeys()` once LAContext can be reused?
}
