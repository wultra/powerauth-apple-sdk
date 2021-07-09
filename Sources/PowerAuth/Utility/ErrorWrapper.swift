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

extension PowerAuthError {
    /// Wrap any error to `PowerAuthError`. If given error is already `PowerAuthError` instance then returns this instance,
    /// otherwise `.unexpectedError` is returned.
    /// - Parameter error: Error object to wrap into `PowerAuthError`
    /// - Returns: The same instance if `error` is already instance of `PowerAuthError`, or `.unexpectedError`
    static func wrap(_ error: Error) -> PowerAuthError {
        error.asPowerAuthError(or: wrapOtherError(error: error))
    }
    
    /// Wrap or reinterpret any error type to `PowerAuthError`.
    /// - Parameter error: Error to wrap or reinterpret.
    /// - Returns: `PowerAuthError`
    private static func wrapOtherError(error: Error) -> PowerAuthError {
        // PowerAuthCore errors
        let nsError = error as NSError
        let errorCode = nsError.powerAuthCoreErrorCode
        if errorCode != .NA {
            return wrapCoreError(error: nsError, errorCode: errorCode)
        }
        // All other errors
        return .unexpectedFailure(reason: error)
    }
    
    /// Wrap `NSError` from `PowerAuthCore` module into `PowerAuthError`.
    /// - Parameters:
    ///   - error: Original error from `PowerAuthCore`
    ///   - errorCode: `PowerAuthCore.ErrorCode` already retrieved from `NSError`
    /// - Returns: `NSError` translated, or wrapped to `PowerAuthError`
    private static func wrapCoreError(error: NSError, errorCode: PowerAuthCore.ErrorCode) -> PowerAuthError {
        // TODO: handle more error cores here
        switch errorCode {
            case .wrongSetup:
                return .invalidConfiguration(reason: .invalidInstanceConfiguration)
            case .wrongCode:
                return .invalidActivationData(reason: .wrongActivationCode)
            case .wrongState:
                return .invalidActivationState(reason: .other)
            case .wrongParam:
                return .invalidParameter
            default:
                return .unexpectedFailure(reason: error)
        }
    }
}



