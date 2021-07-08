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

public extension PowerAuth {
    
    // MARK: - Create activation
    
    /// Create a new activation.
    ///
    /// - Parameters:
    ///   - activation: `Activation` structure with parameters for activation creation.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from create activation operation.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has valid or pending activation.
    /// - Returns: `OperationTask` associated with the running request.
    func create(activation: Activation, callbackQueue: DispatchQueue = .main, callback: (Result<ActivationResult, PowerAuthError>)->Void) throws -> OperationTask {
        guard canCreateActivation else {
            throw PowerAuthError.invalidActivationState
        }
        D.notImplementedYet()
    }
    
    // MARK: - Commit activation
    
    /// Commit activation that was created and store related data using provided authentication structure. Be aware, that `Authentication` must be
    /// created with `.commitWithKnowledge()` or `.commitWithKnowledgeAndBiometry()` functions.
    ///
    /// `PowerAuth` instance will be activated after successfull call to this function and prepared for other tasks, like data signing.
    ///
    /// - Parameter authentication: `Authentication` structure created for activation commit.
    /// - Throws:
    ///   - `PowerAuthError.invalidAuthenticationData` in case that authentication structure is created for wrong operation type.
    ///   - `PowerAuthError.invalidActivationState` in case that function is called in wrong state.
    ///   - `PowerAuthError.invalidParam` in case that provided password is too short.
    ///   - `PowerAuthError.unexpectedError` for other failures.
    func commitActivation(with authentication: Authentication) throws {
        guard authentication.factors.isFactorsForActivationCommit else {
            throw PowerAuthError.invalidAuthenticationData(reason: .authenticationForCommitIsRequired)
        }
        do {
            try session.completeActivation(withKeys: try authentication.getSignatureFactorKeys(with: dataProvider, firstLock: true))
            try saveActivationState()
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    /// Commit activation that was created and store related data using provided password and optional biometry.
    ///
    /// `PowerAuth` instance will be activated after successfull call to this function and prepared for other tasks, like data signing.
    ///
    /// - Parameters:
    ///   - password: Password to be used for the knowledge related authentication factor.
    ///   - biometry: If `true` then the activation will be prepared also for biometric data signing.
    /// - Throws:
    ///   - `PowerAuthError.invalidAuthenticationData` in case that authentication structure is created for wrong operation type.
    ///   - `PowerAuthError.invalidActivationState` in case that function is called in wrong state.
    ///   - `PowerAuthError.invalidParam` in case that provided password is too short.
    ///   - `PowerAuthError.unexpectedError` for other failures.
    func commitActivation(with password: String, biometry: Bool = false) throws {
        let authentication: Authentication = biometry ? .commitWithKnowledgeAndBiometry(password: password) : .commitWithKnowledge(password: password)
        try commitActivation(with: authentication)
    }
    
    /// Remove activation by calling a PowerAuth Standard RESTful API endpoint `/pa/activation/remove` and then remove all
    /// remaining activation data from the device.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` structure for data signing, that must contain knowledge or biometry factor.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from remove activation operation.
    /// - Throws:
    ///   - `PowerAuthError.invalidAuthenticationData` in case that authentication structure is created for wrong operation type.
    ///   - `PowerAuthError.invalidActivationState` in case that function is called in wrong state.
    /// - Returns: `OperationTask` associated with the running request.
    func removeActivation(with authentication: Authentication, callbackQueue: DispatchQueue = .main, callback:(Result<Bool,PowerAuthError>)->Void) throws -> OperationTask {
        guard authentication.factors.isFactorsForActivationCommit else {
            throw PowerAuthError.invalidAuthenticationData(reason: .authenticationForSigningIsRequired)
        }
        guard hasValidActivation else {
            throw PowerAuthError.invalidActivationState
        }
        D.notImplementedYet()
    }
    
    /// Removes activation in any state from the device.
    ///
    /// This method removes the activation session state and biometry factor key. Cached possession related key remains intact.
    /// Unlike the `removeActivation(with:)`, this method doesn't inform server about activation removal. In this case
    /// user has to remove the activation by using another channel (typically internet banking, or similar web management console).
    func removeActivationLocal() {
        do {
            session.reset()
            try saveActivationState()
            try dataProvider.removeBiometryFactorEncryptionKey()
            lastFetchedActivationStatus = nil
        } catch {
            D.error("PowerAuth.removeActivationLocal() failed with error: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Activation identifier & fingerprint
    
    /// Contains activation identifier or `nil` if object has no valid activation.
    var activationIdentifier: String? {
        session.activationIdentifier
    }
    
    /// Contains decimalized fingerprint calculated from device's and server's public keys or `nil` if object has no valid activation.
    var activationFingerprint: String? {
        session.activationFingerprint
    }
}

extension PowerAuth {
    func saveActivationState() throws {
        try dataProvider.save(activationState: session.serializedState())
    }
}

