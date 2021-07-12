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

/// The `ActivationStatus` structure represents state of the activation
/// on PowerAuth Server.
public struct ActivationStatus {
    
    /// The state represents an activation state on the server.
    public enum State {
        
        /// The activation is not completed yet on the server.
        case pendingCommit
        
        /// The shared secure context is valid and active.
        case active
        
        /// The activation is blocked.
        case blocked
        
        /// The activation doesn't exist anymore. You can remove activation locally.
        case removed
    
        /// The activation is technically blocked. You cannot use it anymore
        /// for the signature calculations.
        ///
        /// This state is determined locally on the device and doesn't reflect
        /// an actual state on the server. The activation on the server may be
        /// stil valid, but client's local state prevents to sign data properly.
        ///
        /// The rigth reaction to this situation is to inform user about sudden
        /// activation lost then remove activation locally.
        case deadlock
    }
    
    /// State of activation on the server.
    public let state: State
    
    /// Number of failed authentication attempts in a row.
    public let failCount: Int
    
    /// Maximum number of allowed failed authentication attempts in a row.
    public let maxFailCount: Int
    
    /// Contains (maxFailCount - failCount) if state is `.active`, otherwise `0`.
    public let remainingAttempts: Int
}


extension PowerAuthCore.ActivationStatus {
    
    /// Convert `PowerAuthCore.ActivationStatus` object to `ActivationStatus` structure.
    /// - Throws: `PowerAuthError.internalError` in case that state cannot be converted.
    /// - Returns: `ActivationStatus` structure converted from core object.
    func toSdkActivationStatus() throws -> ActivationStatus {
        ActivationStatus(
            state: try state.toSdkState(),
            failCount: Int(failCount),
            maxFailCount: Int(maxFailCount),
            remainingAttempts: Int(remainingAttempts)
        )
    }
}

extension PowerAuthCore.ActivationState {
    
    /// Conver `PowerAuthCore.ActivationState` into `ActivationStatus.State`.
    /// - Throws: `PowerAuthError.internalError` in case that state cannot be converted.
    /// - Returns: `ActivationStatus.State` converted from core state enumeration.
    func toSdkState() throws -> ActivationStatus.State {
        switch self {
            case .pendingCommit:
                return .pendingCommit
            case .active:
                return .active
            case .blocked:
                return .blocked
            case .deadlock:
                return .deadlock
            default:
                // In case that `.created` state is somehow reported, or server contains a new state that is not supported by this SDK
                throw PowerAuthError.internalError(reason: "Activation state received from the server contains unexpected value \(self.rawValue)")
        }
    }
}
