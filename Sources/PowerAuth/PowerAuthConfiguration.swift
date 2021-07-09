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

/// Structure that represents `PowerAuth` configuration.
public struct PowerAuthConfiguration {
    
    // MARK: - Instance
    
    /// Identifier of the `PowerAuth` instance, used as a 'key' to store session state in the session state keychain.
    public let instanceId: String
    
    /// Base URL to the PowerAuth Standard RESTful API (the URL part before `"/pa/..."`).
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
    
    /// Keychans configuration.
    public let keychains: PowerAuthConfiguration.Keychains
    
    /// HttpClient configuration.
    public let httpClient: PowerAuthConfiguration.HttpClient
    
    /// Biometry configuration.
    public let biometry: PowerAuthConfiguration.Biometry
    
    /// Construct configuration for `PowerAuth` class instance.
    /// - Parameters:
    ///   - instanceId: Identifier of the `PowerAuth` instance, used as a 'key' to store session state in the session state keychain.
    ///   - baseEndpointUrl: Base URL to the PowerAuth Standard RESTful API (the URL part before `"/pa/..."`).
    ///   - applicationKey: `APPLICATION_KEY` constant as defined in PowerAuth specification - a key identifying an application version.
    ///   - applicationSecret: `APPLICATION_SECRET` constant as defined in PowerAuth specification - a secret associated with an application version.
    ///   - masterServerPublicKey: `KEY_SERVER_MASTER_PUBLIC` constant as defined in PowerAuth specification - a master server public key.
    ///   - externalEncryptionKey: Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
    ///   - disableAutomaticProtocolUpgrade: If set to `true`, then PowerAuth will not automatically upgrade activation to a newer protocol version. This option should be used only for the testing purposes.
    ///   - keychainsConfiguration: `PowerAuthConfiguration.Keychains` structure.
    ///   - httpClientConfiguration: `PowerAuthConfiguration.HttpClient` structure.
    ///   - biometryConfiguration: `PowerAuthConfiguration.Biometry` structure.
    /// - Throws: `PowerAuthError.invalidConfiguration` in case that configuration contains invalid data.
    public init(
        instanceId: String,
        baseEndpointUrl: URL,
        applicationKey: String,
        applicationSecret: String,
        masterServerPublicKey: String,
        externalEncryptionKey: Data? = nil,
        disableAutomaticProtocolUpgrade: Bool = false,
        keychainsConfiguration: PowerAuthConfiguration.Keychains = .default,
        httpClientConfiguration: PowerAuthConfiguration.HttpClient = .default,
        biometryConfiguration: PowerAuthConfiguration.Biometry = .default) throws {
        self.instanceId = instanceId
        self.baseEndpointUrl = baseEndpointUrl
        self.applicationKey = applicationKey
        self.applicationSecret = applicationSecret
        self.masterServerPublicKey = masterServerPublicKey
        self.externalEncryptionKey = externalEncryptionKey
        self.disableAutomaticProtocolUpgrade = disableAutomaticProtocolUpgrade
        self.keychains = keychainsConfiguration
        self.httpClient = httpClientConfiguration
        self.biometry = biometryConfiguration
        try validate()
    }
    
    /// Validate `PowerAuthConfiguration` parameters.
    /// - Throws: `PowerAuthError.invalidConfiguration` in case that some parameter is invalid.
    private func validate() throws {
        guard !instanceId.isEmpty else {
            D.error("PowerAuthConfiguration contains empty 'instanceId' parameter")
            throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
        }
        guard InputValidator.validate(base64String: applicationKey, expectedCount: Constants.KeySizes.APP_KEY_SIZE) else {
            D.error("PowerAuthConfiguration has invalid 'applicationKey' parameter")
            throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
        }
        guard InputValidator.validate(base64String: applicationSecret, expectedCount: Constants.KeySizes.APP_SECRET_SIZE) else {
            D.error("PowerAuthConfiguration has invalid 'applicationSecret' parameter")
            throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
        }
        guard InputValidator.validate(base64String: masterServerPublicKey, min: 30, max: nil) else {
            D.error("PowerAuthConfiguration has invalid 'masterServerPublicKey' parameter")
            throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
        }
        if let eek = externalEncryptionKey {
            guard eek.count == Constants.KeySizes.EEK_SIZE else {
                D.error("PowerAuthConfiguration has invalid 'externalEncryptionKey' parameter")
                throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
            }
        }
    }
    
    // MARK: - HttpClient
    
    /// Structure that is used to provide RESTful API client configuration.
    public struct HttpClient {
        
        /// Specifies the HTTP client request timeout. The default value is 20.0 (seconds).
        public let requestTimeout: TimeInterval
        
        /// Specifies the TSL validation strategy applied by the client. The default `URLSession`
        /// validation is performed if not altered.
        public let tlsValidationStrategy: TlsValidationStrategy
        
        /// List of request interceptors used by the client before the request is executed.
        public let requestInterceptors: [HttpRequestInterceptor]
        
        /// Default `HttpClient`
        public static let `default` = try! HttpClient(
            requestTimeout: Constants.Http.defaultConnectionTimeout,
            tlsValidationStrategy: .default,
            requestInterceptors: []
        )
        
        /// Construct `HttpClient` with custom parameters.
        /// - Parameters:
        ///   - requestTimeout: Specifies the HTTP client request timeout. The default value is 20.0 (seconds).
        ///   - tlsValidationStrategy: Specifies the TSL validation strategy applied by the client. The default `URLSession` validation is performed if not altered.
        ///   - requestInterceptors: List of request interceptors used by the client before the request is executed.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case that request timeout is too short.
        public init(
            requestTimeout: TimeInterval? = nil,
            tlsValidationStrategy: TlsValidationStrategy = .default,
            requestInterceptors: [HttpRequestInterceptor] = []) throws {
            self.requestTimeout = requestTimeout ?? Constants.Http.defaultConnectionTimeout
            self.tlsValidationStrategy = tlsValidationStrategy
            self.requestInterceptors = requestInterceptors
            try validate()
        }
        
        /// Validates values in structure.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case that request timeout is too short.
        fileprivate func validate() throws {
            guard requestTimeout >= Constants.Http.minimumConnectionTimeout else {
                D.error("PowerAuthConfiguration.HttpClient contains too short request timeout.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidHttpClientConfiguration)
            }
        }
    }
    
    // MARK: - Keychains
    
    /// Structure that is used to provide Keychain storage configuration.
    public struct Keychains {
        
        /// Access group name used by the `PowerAuth` keychain instances.
        public let accessGroupName: String?
        
        /// Suite name used by the `UserDefaults` that check for Keychain data presence.
        ///
        /// If the value is not set, `UserDefaults.standardUserDefaults` are used. Otherwise,
        /// user defaults with given suite name are created. In case a developer started using SDK
        /// with no suite name specified, the developer is responsible for migrating data
        /// to the new `UserDefaults` before using the SDK with the new suite name.
        public let userDefaultsSuiteName: String?
        
        /// Name of the Keychain service used to store statuses for different `PowerAuth` instances.
        public let statusKeychainName: String
        
        /// Name of the Keychain service used to store possession factor related key (one value for all `PowerAuth` instances)
        public let possessionKeychainName: String
        
        /// Name of the Keychain service used to store biometry related keys for different `PowerAuth` instances.
        public let biometryKeychainName: String
        
        /// Name of the Keychain service used to store content of `PowerAuthToken` objects.
        public let tokenStoreKeychainName: String
        
        /// Name of the Keychain key used to store possession fator related key in an associated service.
        public let possessionKeyName: String
        
        /// This value specifies 'key' used to store this PowerAuth instance's biometry related key in the biometry key keychain.
        /// If not altered in `Builder` then value from `PowerAuthConfiguration.instanceId` is used.
        public let biometryKeyName: String?
        
        /// Default `PowerAuthConfiguration.Keychains`.
        public static let `default` = try! Keychains(
            accessGroupName:        nil,
            userDefaultsSuiteName:  nil,
            statusKeychainName:     Constants.KeychainNames.status,
            possessionKeychainName: Constants.KeychainNames.possession,
            biometryKeychainName:   Constants.KeychainNames.biometry,
            tokenStoreKeychainName: Constants.KeychainNames.tokenStore,
            possessionKeyName:      Constants.KeychainNames.possessionKeyName,
            biometryKeyName:        nil
        )
        
        /// Construct structure with custom parameters.
        ///
        /// - Parameters:
        ///   - accessGroupName: Access group name used by the `PowerAuth` keychain instances.
        ///   - userDefaultsSuiteName: Suite name used by the `UserDefaults` that check for Keychain data presence.
        ///   - statusKeychainName: Name of the Keychain service used to store statuses for different `PowerAuth` instances.
        ///   - possessionKeychainName: Name of the Keychain service used to store possession factor related key (one value for all `PowerAuth` instances)
        ///   - biometryKeychainName: Name of the Keychain service used to store biometry related keys for different `PowerAuth` instances.
        ///   - tokenStoreKeychainName: Name of the Keychain service used to store content of `PowerAuthToken` objects.
        ///   - possessionKeyName: Name of the Keychain key used to store possession fator related key in an associated service.
        ///   - biometryKeyName: This value specifies 'key' used to store this PowerAuth instance's biometry related key in the biometry key keychain.
        ///     If not altered in `Builder` then value from `PowerAuthConfiguration.instanceId` is used.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case configuration contains invalid data.
        public init(
            accessGroupName: String? = nil,
            userDefaultsSuiteName: String? = nil,
            statusKeychainName: String? = nil,
            possessionKeychainName: String? = nil,
            biometryKeychainName: String? = nil,
            tokenStoreKeychainName: String? = nil,
            possessionKeyName: String? = nil,
            biometryKeyName: String? = nil) throws {
            self.accessGroupName = accessGroupName
            self.userDefaultsSuiteName = userDefaultsSuiteName
            self.statusKeychainName = statusKeychainName ?? Constants.KeychainNames.status
            self.possessionKeychainName = possessionKeychainName ?? Constants.KeychainNames.possession
            self.biometryKeychainName = biometryKeychainName ?? Constants.KeychainNames.biometry
            self.tokenStoreKeychainName = tokenStoreKeychainName ?? Constants.KeychainNames.tokenStore
            self.possessionKeyName = possessionKeyName ?? Constants.KeychainNames.possessionKeyName
            self.biometryKeyName = biometryKeyName
            try validate()
        }
        
        /// Validates content of structure.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case of failure.
        private func validate() throws {
            guard !(accessGroupName?.isEmpty ?? false) else {
                D.error("PowerAuthConfiguration.Keychains has empty 'accessGroupName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !(userDefaultsSuiteName?.isEmpty ?? false) else {
                D.error("PowerAuthConfiguration.Keychains has empty 'userDefaultsSuiteName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !statusKeychainName.isEmpty else {
                D.error("PowerAuthConfiguration.Keychains has empty 'statusKeychainName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !possessionKeychainName.isEmpty else {
                D.error("PowerAuthConfiguration.Keychains has empty 'possessionKeychainName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !biometryKeychainName.isEmpty else {
                D.error("PowerAuthConfiguration.Keychains has empty 'biometryKeychainName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !tokenStoreKeychainName.isEmpty else {
                D.error("PowerAuthConfiguration.Keychains has empty 'tokenStoreKeychainName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !possessionKeyName.isEmpty else {
                D.error("PowerAuthConfiguration.Keychains has empty 'possessionKeyName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            guard !(biometryKeyName?.isEmpty ?? false) else {
                D.error("PowerAuthConfiguration.Keychains has empty 'biometryKeyName' parameter.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
            }
            let keychainNames = [ possessionKeychainName, statusKeychainName, biometryKeychainName, tokenStoreKeychainName ]
            for i in 0..<keychainNames.count {
                for j in 0..<keychainNames.count {
                    if i != j && keychainNames[i] == keychainNames[j] {
                        D.error("Keychain names in PowerAuthConfiguration.Keychains must be unique.")
                        throw PowerAuthError.invalidConfiguration(reason: .invalidKeychainConfiguration)
                    }
                }
            }
        }
    }
    
    // MARK: - Biometry
    
    /// Structure that is used to provide biomety configuration for `PowerAuth` class.
    public struct Biometry {
        /// If set, then the data protected with the biometry is invalidated if fingers are added or removed
        /// for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing
        /// biometry in the system doesn't invalidate the entry)
        public let linkItemsToCurrentSet: Bool
        
        /// If set to `true`, then the data protected with the biometry can be accessed also with a device passcode.
        /// If set, then `linkItemsToCurrentSet` option has no effect. The default is `false`, so fallback
        /// to device's passcode is not enabled.
        public let fallbackToDevicePasscode: Bool
        
        /// Default `Biometry`
        public static let `default` = Biometry(
            linkItemsToCurrentSet: false,
            fallbackToDevicePasscode: false
        )
        
        /// Construct `BiometryConfiguration` with custom parameters.
        /// - Parameters:
        ///   - linkItemsToCurrentSet: If set, then the data protected with the biometry is invalidated if fingers are added or removed
        ///     for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing
        ///     biometry in the system doesn't invalidate the entry)
        ///   - fallbackToDevicePasscode: If set to `true`, then the data protected with the biometry can be
        ///     accessed also with a device passcode. If set, then `linkItemsToCurrentSet` option has no effect. The default is `false`,
        ///     so fallback to device's passcode is not enabled.
        public init(
            linkItemsToCurrentSet: Bool,
            fallbackToDevicePasscode: Bool) {
            self.linkItemsToCurrentSet = linkItemsToCurrentSet
            self.fallbackToDevicePasscode = fallbackToDevicePasscode
        }
    }

}

// MARK: - Pinning & Interceptors

/// The `TlsPinningProvider` protocol defines interface for custom TLS pinning validation.
public protocol TlsPinningProvider {
    /// The method is called when an underlying `URLSession` first establishes a connection to a remote
    /// server that uses TLS, to allow your app to verify the server’s certificate chain. The challenge
    /// parameter is already tested for `URLAuthenticationMethodServerTrust`.
    ///
    /// - Parameter challenge: Challenge to validate.
    /// - Returns: `true` if connection to remote server is trusted.
    func validate(challenge: URLAuthenticationChallenge) -> Bool
}

/// Defines how TLS connections are validated.
public enum TlsValidationStrategy {
    /// Use the default `URLSession` behavior.
    case `default`
    /// Accept all incoming connections, so you can connect to testing servers with self-signed, or invalid
    /// certificates.
    case noValidation
    /// Validate server certificate with a custom TLS pinning provider.
    case pinning(provider: TlsPinningProvider)
}

/// The `HttpRequestInterceptor` protocol defines interface for modifying HTTP requests
/// before their execution.
///
/// **WARNING**
///
/// This protocol allows you to tweak the requests created by the `PowerAuth` instance, but
/// also gives you an opportunity to break the things. So, rather than create your own interceptor,
/// try to contact us and describe what's your problem with the networking in the PowerAuth SDK.
///
/// Also note, that this interface may change in the future. We can guarantee the API stability of
/// public classes implementing this interface, but not the stability of interface itself.
public protocol HttpRequestInterceptor {
    /// Method is called by the internal HTTP client, before the request is executed.
    /// The implementation must count with that method is called from other than UI thread.
    ///
    /// - Parameter request: URL request to be modified.
    func process(request: inout URLRequest)
}

// MARK: - Internals

extension PowerAuthConfiguration {
    
    /// Contains key to biometry keychain to obtain value for biometry factor related key.
    var keychainKeyForBiometryFactor: String {
        keychains.biometryKeyName ?? instanceId
    }
    
    /// Contains key to posssession keychain to obtain value for possession factor related key.
    var keychainKeyForPossesionFactor: String {
        keychains.possessionKeyName
    }
    
    /// Contains `PowerAuthCore.SessionSetup` configuration created from the configuration.
    var powerAuthCoreSessionSetup: PowerAuthCore.SessionSetup {
        SessionSetup(
            applicationKey: applicationKey,
            applicationSecret: applicationSecret,
            masterServerPublicKey: masterServerPublicKey,
            externalEncryptionKey: externalEncryptionKey
        )
    }
}
