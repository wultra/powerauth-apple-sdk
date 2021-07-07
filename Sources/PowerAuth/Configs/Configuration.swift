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

// MARK: - PowerAuthConfiguration -


/// Structure that represents `PowerAuth` instance configuration. You can use
/// `Configuration.Builder` builder class to prepare this structure.
public struct Configuration {
    /// Identifier of the `PowerAuth` instance, used as a 'key' to store session state in the session state keychain.
    public let instanceId: String
    
    /// Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
    public let baseEndpointUrl: URL
    
    /// `APPLICATION_KEY` constant as defined in PowerAuth specification - a key identifying an application version.
    public let applicationKey: String
    
    /// `APPLICATION_SECRET` constant as defined in PowerAuth specification - a secret associated with an application version.
    public let applicationSecret: String

    /// `KEY_SERVER_MASTER_PUBLIC` constant as defined in PowerAuth specification - a master server public key.
    public let masterServerPublicKey: String

    /// Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
    public let externalEncryptionKey: Data?
    
    /// If set to `true`, then PowerAuth will not automatically upgrade activation to a newer protocol version.
    /// This option should be used only for the testing purposes.
    ///
    /// Default and recommended value is `false`.
    public let disableAutomaticProtocolUpgrade: Bool
}

// MARK: - PowerAuthConfiguration.Builder -

public extension Configuration {

    /// Class that builds `Configuration` structure.
    final class Builder {
        // Required
        let instanceId: String
        let baseEndpointUrl: URL
        let applicationKey: String
        let applicationSecret: String
        let masterServerPublicKey: String
        // Optional
        var externalEncryptionKey: Data?
        var disableAutomaticProtocolUpgrade = false
        
        /// Create `Builder` with all required parameters.
        /// - Parameters:
        ///   - instanceId: Identifier of the `PowerAuth` instance, used as a 'key' to store session state in the session state keychain.
        ///   - baseEndpointUrl: Base URL to the PowerAuth Standard RESTful API.
        ///   - applicationKey: `APPLICATION_KEY` constant as defined in PowerAuth specification.
        ///   - applicationSecret: `APPLICATION_SECRET` constant as defined in PowerAuth specification.
        ///   - masterServerPublicKey: `KEY_SERVER_MASTER_PUBLIC` constant as defined in PowerAuth specification.
        public init(
            instanceId: String,
            baseEndpointUrl: URL,
            applicationKey: String,
            applicationSecret: String,
            masterServerPublicKey: String) {
            // Required parameters
            self.instanceId = instanceId
            self.baseEndpointUrl = baseEndpointUrl
            self.applicationKey = applicationKey
            self.applicationSecret = applicationSecret
            self.masterServerPublicKey = masterServerPublicKey
        }
        
        /// Change encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
        /// - Parameter externalEncryptionKey: Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
        /// - Returns: `Builder` instance
        public func set(externalEncryptionKey: Data) -> Builder {
            self.externalEncryptionKey = externalEncryptionKey
            return self
        }
        
        /// Disable automatic protocol upgrade. If set to `true`, then PowerAuth will not automatically upgrade activation to a newer protocol version.
        /// This option should be used only for the testing purposes.
        /// - Parameter disableAutomaticProtocolUpgrade: Disable automatic protocol upgrade
        /// - Returns: `Builder` instance.
        public func set(disableAutomaticProtocolUpgrade: Bool) -> Builder {
            self.disableAutomaticProtocolUpgrade = disableAutomaticProtocolUpgrade
            return self
        }
        
        /// Build `Configuration` structure from collected parameters.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case that some parameter is invalid.
        /// - Returns: `Configuration` structure
        public func build() throws -> Configuration {
            try validateConfig()
            return Configuration(
                instanceId: instanceId,
                baseEndpointUrl: baseEndpointUrl,
                applicationKey: applicationKey,
                applicationSecret: applicationSecret,
                masterServerPublicKey: masterServerPublicKey,
                externalEncryptionKey: externalEncryptionKey,
                disableAutomaticProtocolUpgrade: disableAutomaticProtocolUpgrade
            )
        }
        
        /// Validate `Builder` parameters.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case that some parameter is invalid.
        private func validateConfig() throws {
            guard !instanceId.isEmpty else {
                D.error("PowerAuthConfiguration contains empty 'instanceId' parameter")
                throw PowerAuthError.invalidConfiguration(reason: .invalidConfiguration)
            }
            guard InputValidator.validate(base64String: applicationKey, expectedCount: Constants.KeySizes.APP_KEY_SIZE) else {
                D.error("PowerAuthConfiguration has invalid 'applicationKey' parameter")
                throw PowerAuthError.invalidConfiguration(reason: .invalidConfiguration)
            }
            guard InputValidator.validate(base64String: applicationSecret, expectedCount: Constants.KeySizes.APP_SECRET_SIZE) else {
                D.error("PowerAuthConfiguration has invalid 'applicationSecret' parameter")
                throw PowerAuthError.invalidConfiguration(reason: .invalidConfiguration)
            }
            guard InputValidator.validate(base64String: masterServerPublicKey, min: 30, max: nil) else {
                D.error("PowerAuthConfiguration has invalid 'masterServerPublicKey' parameter")
                throw PowerAuthError.invalidConfiguration(reason: .invalidConfiguration)
            }
            if let eek = externalEncryptionKey {
                guard eek.count == Constants.KeySizes.EEK_SIZE else {
                    D.error("PowerAuthConfiguration has invalid 'externalEncryptionKey' parameter")
                    throw PowerAuthError.invalidConfiguration(reason: .invalidConfiguration)
                }
            }
        }
    }
}
