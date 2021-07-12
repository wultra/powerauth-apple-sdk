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

extension PowerAuth: ActivationStateProvider {
    
    /// Contains `true` if it is possible to start an activation process.
    public var canCreateActivation: Bool {
        session.canStartActivation
    }
    
    /// Contains `true` if there is a pending activation (activation in progress).
    public var hasPendingActivation: Bool {
        session.hasPendingActivation
    }
    
    /// Contains `true` if there is a valid activation.
    public var hasValidActivation: Bool {
        session.hasValidActivation
    }
    
    /// Contains `true` if there's a valid activation that requires a protocol upgrade. Contains `false` once the upgrade
    /// process is started. The application should fetch the activation's status to do the upgrade.
    public var hasProtocolUpgradeAvailable: Bool {
        session.hasProtocolUpgradeAvailable
    }
    
    /// Contains `true` if there is a pending protocol upgrade.
    public var hasPendingProtocolUpgrade: Bool {
        session.hasPendingProtocolUpgrade
    }
}

public extension PowerAuth {
    
    /// Fetch the activation status for current activation.
    /// - Parameters:
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from fetch status operation.
    ///   - result: Result with `ActivationStatus` structure in case of success. The following errors can occur in case of failure:
    ///     - `PowerAuthError.invalidActivationState` in case that activation is missing or is in wrong state.
    /// - Returns: `OperationTask` associated with the running request.
    func fetchActivationStatus(callbackQueue: DispatchQueue = .main, callback: (_ result: Result<ActivationStatus, PowerAuthError>) -> Void) -> OperationTask {
        D.notImplementedYet()
    }
    
    /// Contains last fetched `ActivationStatus` or `nil` if status was not fetched yet.
    /// Use `fetchActivationStatus()` function to fill this value.
    internal(set) var lastFetchedActivationStatus: ActivationStatus? {
        get {
            lock.synchronized { lastActivationStatus }
        }
        set {
            lock.synchronized { lastActivationStatus = newValue }
        }
    }
}
