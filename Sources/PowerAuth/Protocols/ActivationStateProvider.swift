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

/// The `ActivationStateProvider` protocol contains brief information about
/// activation state. The protocol is internal, but can be exposed in
/// public object.
protocol ActivationStateProvider {
    
    /// Contains `true` if it is possible to start an activation process.
    var canCreateActivation: Bool { get }
    
    /// Contains `true` if there is a pending activation (activation in progress).
    var hasPendingActivation: Bool { get }
    
    /// Contains `true` if there is a valid activation.
    var hasValidActivation: Bool { get }
    
    /// Contains `true` if there's a valid activation that requires a protocol upgrade.
    /// Contains `false` once the upgrade process is started. The application should
    /// fetch the activation's status to do the upgrade.
    var hasProtocolUpgradeAvailable: Bool { get }
    
    /// Contains `true` if there is a pending protocol upgrade.
    var hasPendingProtocolUpgrade: Bool { get }
}
