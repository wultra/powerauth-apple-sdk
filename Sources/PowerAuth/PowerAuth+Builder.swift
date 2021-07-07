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

/// MARK: - PowerAuth.Builder -

public extension PowerAuth {

    /// Class that builds `PowerAuth` instance.
    final class Builder {
        
        // Required
        let powerAuthConfiguration: Configuration
        
        // Optional
        var keychainConfiguration: KeychainConfiguration?
        var biometryConfiguration: BiometryConfiguration?
        var httpClientConfiguration: HttpClientConfiguration?
        
        // For testing only
        var httpClient: HttpClient?
        var dataProvider: DataProvider?
        
        /// Initialize `Builder` with required `Configuration` configuration.
        /// - Parameter configuration: `Configuration` structure
        public init(configuration: Configuration) {
            self.powerAuthConfiguration = configuration
        }
        
        /// Set custom keychain configuration.
        /// - Parameter keychainConfiguration: Custom `KeychainConfiguration`
        /// - Returns: `Builder` instance.
        public func set(keychainConfiguration: KeychainConfiguration) -> Builder {
            self.keychainConfiguration = keychainConfiguration
            return self
        }
        
        /// Set custom biometry configuration.
        /// - Parameter biometryConfiguration: Custom `BiometryConfiguration`
        /// - Returns: `Builder` instance.
        public func set(biometryConfiguration: BiometryConfiguration) -> Builder {
            self.biometryConfiguration = biometryConfiguration
            return self
        }
        
        /// Set custom HTTP client configuraiton.
        /// - Parameter httpClientConfiguration: Custom `HttpClientConfiguration`.
        /// - Returns: `Builder` instance.
        public func set(httpClientConfiguration: HttpClientConfiguration) -> Builder {
            self.httpClientConfiguration = httpClientConfiguration
            return self
        }
        
        /// Set custom `HttpClient` implementation. The setter is internal, so it can be used
        /// for testing purposes only.
        /// - Parameter httpClient: Custom `HttpClient` implementation.
        /// - Returns: `Builder` instance.
        func set(httpClient: HttpClient) -> Builder {
            self.httpClient = httpClient
            return self
        }
        
        /// Set custom `DataProvider` implementation. The setter is internal, so it can be used
        /// for testing purposes only.
        /// - Parameter dataProvider: Custom `DataProvider` implementation.
        /// - Returns: `Builder` instance.
        func set(dataProvider: DataProvider) -> Builder {
            self.dataProvider = dataProvider
            return self
        }
     
        /// Build `PowerAuth` instance from collected parameters.
        /// - Throws:
        ///   - `PowerAuthError.invalidConfiguration` in case that internal `PowerAuthKeychain` object cannot be acquired.
        ///   - `PowerAuthError.invalidConfiguration` in case that `KeychainConfiguration` contains invalid suite name.
        ///   - `PowerAuthError.unexpectedFailure` in case of unexpected error.
        /// - Returns: `PowerAuth` class instance.
        public func build() throws -> PowerAuth {
            let configuration = PowerAuth.PrivateConfiguration(
                instance: powerAuthConfiguration,
                keychain: keychainConfiguration ?? .default,
                biometry: biometryConfiguration ?? .default,
                httpClient: httpClientConfiguration ?? .default)
            let dataProvider = try (dataProvider ?? DefaultDataProvider(with: configuration))
            let httpClient = httpClient ?? DefaultHttpClient(with: configuration.httpClient)
            // Create and prepare PowerAuth instance
            return PowerAuth(configuration: configuration, dataProvider: dataProvider, httpClient: httpClient)
        }
    }
}
