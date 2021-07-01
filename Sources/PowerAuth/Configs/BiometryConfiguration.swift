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

/// Structure that is used to provide biomety configuration for `PowerAuth`. You can use `.default`
/// configuration or use `Configuration.Builder` builder class to build a customized structure.
public struct BiometryConfiguration {
    /// If set, then the data protected with the biometry is invalidated if fingers are added or removed
    /// for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing
    /// biometry in the system doesn't invalidate the entry)
    public let linkBiometricItemsToCurrentSet: Bool
    
    /// If set to `true`, then the data protected with the biometry can be accessed also with a device passcode.
    /// If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is `false`, so fallback
    /// to device's passcode is not enabled.
    public let allowBiometricAuthenticationFallbackToDevicePasscode: Bool
    
    /// Default `BiometryConfiguration`
    public static let `default` = BiometryConfiguration(
        linkBiometricItemsToCurrentSet: false,
        allowBiometricAuthenticationFallbackToDevicePasscode: false
    )
}


public extension BiometryConfiguration {
    
    /// Class that builds custom `BiometryConfiguration` structure.
    final class Builder {
        
        var linkBiometricItemsToCurrentSet = false
        var allowBiometricAuthenticationFallbackToDevicePasscode = false
        
        /// Initialize builder object with default values.
        public init() {
        }
        
        /// Build `BiometryConfiguration` from collected parameters.
        /// - Returns: `BiometryConfiguration` structure.
        public func build() -> BiometryConfiguration {
            return BiometryConfiguration(
                linkBiometricItemsToCurrentSet: linkBiometricItemsToCurrentSet,
                allowBiometricAuthenticationFallbackToDevicePasscode: allowBiometricAuthenticationFallbackToDevicePasscode)
        }
        
        /// Change whether the data protected with the biometry is invalidated if fingers are added or removed for Touch ID,
        /// or if the user re-enrolls for Face ID.
        ///
        /// - Parameter linkBiometricItemsToCurrentSet: If set, then the data protected with the biometry is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID.
        /// - Returns: `Builder` instance
        public func set(linkBiometricItemsToCurrentSet: Bool) -> Builder {
            self.linkBiometricItemsToCurrentSet = linkBiometricItemsToCurrentSet
            return self
        }
        
        /// Change whether the data protected with the biometry can be accessed also with a device passcode. If set, then `linkBiometricItemsToCurrentSet` option has no effect.
        /// - Parameter allowBiometricAuthenticationFallbackToDevicePasscode: If set to `true`, then the data protected with the biometry can be accessed also with a device passcode.
        /// - Returns: `Builder` instance.
        public func set(allowBiometricAuthenticationFallbackToDevicePasscode: Bool) -> Builder {
            self.allowBiometricAuthenticationFallbackToDevicePasscode = allowBiometricAuthenticationFallbackToDevicePasscode
            return self
        }
    }
}
