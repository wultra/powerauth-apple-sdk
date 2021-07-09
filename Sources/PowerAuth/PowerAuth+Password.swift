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

public extension PowerAuth {
    
    /// Validate a user password by calling PowerAuth Standard RESTful API endpoint `/pa/signature/validate`.
    ///
    /// - Parameters:
    ///   - password: `PowerAuthCore.Password` object with user's password to validate.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from password validation.
    ///   - result: Result that is always `true` in case of success.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func validatePassword(password: PowerAuthCore.Password, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) throws -> OperationTask {
        D.notImplementedYet()
    }
    
    /// Validate a user password by calling PowerAuth Standard RESTful API endpoint `/pa/signature/validate`.
    ///
    /// - Parameters:
    ///   - password: String with user's password to validate.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from password validation.
    ///   - result: Result that is always `true` in case of success.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func validatePassword(password: String, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) throws -> OperationTask {
        try validatePassword(password: Password(string: password), callbackQueue: callbackQueue, callback: callback)
    }
    
    /// Change the password, validate old password by calling a PowerAuth Standard RESTful API endpoint `/pa/signature/validate`.
    ///
    /// - Parameters:
    ///   - old: `PowerAuthCore.Password` object with old user's password.
    ///   - new: `PowerAuthCore.Password` object with new password, to be set in case authentication with old password passes.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from change password.
    ///   - result: Result that is always `true` in case of success.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func changePassword(from old: PowerAuthCore.Password, to new: PowerAuthCore.Password, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) throws -> OperationTask {
        D.notImplementedYet()
    }
    
    /// Change the password, validate old password by calling a PowerAuth Standard RESTful API endpoint `/pa/signature/validate`.
    ///
    /// - Parameters:
    ///   - old: String with old user's password.
    ///   - new: String with new password, to be set in case authentication with old password passes.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from change password.
    ///   - result: Result that is always `true` in case of success.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func changePassword(from old: String, to new: String, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Bool, PowerAuthError>) -> Void) throws -> OperationTask {
        try changePassword(from: Password(string: old), to: Password(string: new), callbackQueue: callbackQueue, callback: callback)
    }
    
    
    /// Change the password using local re-encryption, do not validate old password by calling any endpoint.
    ///
    /// You are responsible for validating the old password against some server endpoint yourself before using it in this method.
    /// If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
    /// existing data will be decrypted using invalid password and re-encrypted with a new one.
    ///
    /// - Parameters:
    ///   - old: `PowerAuthCore.Password` object with old user's password.
    ///   - new: `PowerAuthCore.Password` object with new password.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    func unsafeChangePassword(from old: PowerAuthCore.Password, to new: PowerAuthCore.Password) throws {
        do {
            try session.changeUserPassword(old: old, new: new)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    /// Change the password using local re-encryption, do not validate old password by calling any endpoint.
    ///
    /// You are responsible for validating the old password against some server endpoint yourself before using it in this method.
    /// If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
    /// existing data will be decrypted using invalid password and re-encrypted with a new one.
    ///
    /// - Parameters:
    ///   - old: String with old user's password.
    ///   - new: String object with new password.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    func unsafeChangePassword(from old: String, to new: String) throws {
        try unsafeChangePassword(from: Password(string: old), to: Password(string: new))
    }
}
