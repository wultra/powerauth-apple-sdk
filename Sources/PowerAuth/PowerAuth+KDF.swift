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
    
    /// Generate an derived encryption key with given index.
    ///
    /// This method calls PowerAuth Standard RESTful API endpoint `/pa/vault/unlock` to obtain the vault encryption key used for subsequent
    /// key derivation using given index.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` with knowledge and possession factors configured for data signing.
    ///   - keyIndex: Index of the derived key using KDF.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from key derivation operation.
    ///   - result: Result with `Data` containing derived key material in case of success. The following errors can occur in case of failure:
    ///     - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func deriveEncryptionKey(with authentication: Authentication, keyIndex: UInt64, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Data, PowerAuthError>) -> Void) -> OperationTask {
        D.notImplementedYet()
    }
    
}
