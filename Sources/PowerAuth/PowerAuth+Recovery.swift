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
    
    /// Contains `true` if this instance contains an activation recovery data.
    var hasActivationRecoveryData: Bool {
        session.hasActivationRecoveryData
    }
    
    /// Get an activation recovery data.
    ///
    /// This method calls PowerAuth Standard RESTful API endpoint `/pa/vault/unlock` to obtain the vault encryption key
    /// used for private recovery data decryption.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` with knowledge and possession factors configured for data signing.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from getting recovery code operation.
    ///   - result: Result with `ActivationRecoveryData` in case of success. The following errors can occur in case of failure:
    ///     - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///     - `PowerAuthError.invalidActivationState` in case that instance doesn't contain an encrypted recovery data.
    /// - Returns: `OperationTask` associated with the running request.
    func getActivationRecoveryData(with authentication: Authentication, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<ActivationRecoveryData, PowerAuthError>) -> Void) -> OperationTask {
        D.notImplementedYet()
    }
    
    /// Confirm given recovery code on the server.
    ///
    /// The method is useful for situations when user receives a recovery information via OOB channel (for example via postcard). Such
    /// recovery codes cannot be used without a proper confirmation on the server. To confirm codes, user has to authenticate himself
    /// with a knowledge factor.
    ///
    /// Note that the provided recovery code can contain a `"R:"` prefix, if it's scanned from QR code.
    ///
    /// - Parameters:
    ///   - recoveryCode: Recovery code to confirm
    ///   - authentication: `Authentication` with knowledge and possession factors configured for data signing.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from confirm recovery code operation.
    ///   - result: Result with `Bool` in case of success that contains information whether the recovery code was already confirmed before. The The following errors can occur in case of failure:
    ///     - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///     - `PowerAuthError.invalidActivationData` in case that provided recovery code has invalid format.
    /// - Returns: `OperationTask` associated with the running request.
    func confirmRecoveryCode(recoveryCode: String, with authentication: Authentication, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) -> OperationTask {
        D.notImplementedYet()
    }
}
