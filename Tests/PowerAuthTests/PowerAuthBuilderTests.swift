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

import XCTest
import PowerAuth

final class PowerAuthBuilderTests: XCTestCase {

    let APP_KEY = String.randomBase64(dataCount: 16)
    let APP_SECRET = String.randomBase64(dataCount: 16)
    let MASTER_SERVER_PUBLIC_KEY = String.randomBase64(dataCount: 33)
    
    func testInstanceBuilder() throws {
        // Prepare various configs
        let instanceConfig = try PowerAuthConfiguration.Builder(
            instanceId: "instance-id",
            baseEndpointUrl: URL(string: "https://google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: MASTER_SERVER_PUBLIC_KEY)
            .build()
        let biometryConfig = BiometryConfiguration.Builder()
            .set(linkBiometricItemsToCurrentSet: !BiometryConfiguration.default.linkBiometricItemsToCurrentSet)
            .set(allowBiometricAuthenticationFallbackToDevicePasscode: !BiometryConfiguration.default.allowBiometricAuthenticationFallbackToDevicePasscode)
            .build()
        let keychainConfig = try KeychainConfiguration.Builder()
            .set(accessGroupName: "access-group-name")
            .build()
        let httpClientConfig = try HttpClientConfiguration.Builder()
            .set(requestTimeout: 10)
            .add(requestInterceptor: HttpClientConfigurationTests.Interceptor1())
            .set(tlsValidationStrategy: .noValidation)
            .build()
        
        // Now build PowerAuth class
        var powerAuth = try PowerAuth.Builder(configuration: instanceConfig)
            .build()
        XCTAssertEqual(instanceConfig, powerAuth.configuration)
        XCTAssertEqual(BiometryConfiguration.default, powerAuth.biometryConfiguration)
        XCTAssertEqual(HttpClientConfiguration.default, powerAuth.httpClientConfiguration)
        XCTAssertEqual(KeychainConfiguration.default, powerAuth.keychainConfiguration)
        // Now try a custom config
        powerAuth = try PowerAuth.Builder(configuration: instanceConfig)
            .set(biometryConfiguration: biometryConfig)
            .set(keychainConfiguration: keychainConfig)
            .set(httpClientConfiguration: httpClientConfig)
            .build()
        XCTAssertEqual(powerAuth.configuration, instanceConfig)
        XCTAssertEqual(biometryConfig, powerAuth.biometryConfiguration)
        XCTAssertEqual(httpClientConfig, powerAuth.httpClientConfiguration)
        XCTAssertEqual(keychainConfig, powerAuth.keychainConfiguration)
    }
}

extension BiometryConfiguration: Equatable {
    public static func == (lhs: BiometryConfiguration, rhs: BiometryConfiguration) -> Bool {
        lhs.linkBiometricItemsToCurrentSet == rhs.linkBiometricItemsToCurrentSet &&
        lhs.allowBiometricAuthenticationFallbackToDevicePasscode == rhs.allowBiometricAuthenticationFallbackToDevicePasscode
    }
}

extension PowerAuthConfiguration: Equatable {
    public static func == (lhs: PowerAuthConfiguration, rhs: PowerAuthConfiguration) -> Bool {
        lhs.instanceId == rhs.instanceId &&
        lhs.applicationKey == rhs.applicationKey &&
        lhs.applicationSecret == rhs.applicationSecret &&
        lhs.baseEndpointUrl == rhs.baseEndpointUrl &&
        lhs.masterServerPublicKey == rhs.masterServerPublicKey &&
        lhs.disableAutomaticProtocolUpgrade == rhs.disableAutomaticProtocolUpgrade &&
        lhs.externalEncryptionKey == rhs.externalEncryptionKey
    }
    
}

extension KeychainConfiguration: Equatable {
    public static func == (lhs: KeychainConfiguration, rhs: KeychainConfiguration) -> Bool {
        lhs.accessGroupName == rhs.accessGroupName &&
        lhs.statusKeychainName == rhs.statusKeychainName &&
        lhs.possessionKeychainName == rhs.possessionKeychainName &&
        lhs.biometryKeychainName == rhs.biometryKeychainName &&
        lhs.tokenStoreKeychainName == rhs.tokenStoreKeychainName &&
        lhs.userDefaultsSuiteName == rhs.userDefaultsSuiteName &&
        lhs.biometryKeyName == rhs.biometryKeyName &&
        lhs.possessionKeyName == rhs.possessionKeyName
    }
    
}

extension HttpClientConfiguration: Equatable {
    public static func == (lhs: HttpClientConfiguration, rhs: HttpClientConfiguration) -> Bool {
        // NOTE: Array of interceptors is not compared, just the number of items in the array.
        lhs.requestTimeout == rhs.requestTimeout &&
        lhs.tlsValidationStrategy == rhs.tlsValidationStrategy &&
        lhs.requestInterceptors.count == rhs.requestInterceptors.count
    }
}

extension TlsValidationStrategy: Equatable {
    public static func == (lhs: TlsValidationStrategy, rhs: TlsValidationStrategy) -> Bool {
        // NOTE: Various pinning providers leads to equal validation strategy.
        switch (lhs, rhs) {
            case (.default, .default): return true
            case (.noValidation, .noValidation): return true
            case ( .pinning(_), .pinning(_)): return true
            default: return false
        }
    }
}
