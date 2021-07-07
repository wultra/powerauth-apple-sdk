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
@testable import PowerAuth

final class PowerAuthConstructorTests: XCTestCase {

    let APP_KEY = String.randomBase64(dataCount: 16)
    let APP_SECRET = String.randomBase64(dataCount: 16)
    let MASTER_SERVER_PUBLIC_KEY = String.randomBase64(dataCount: 33)
    
    func testInstanceBuilder() throws {
        // Prepare various configs
        let instanceConfig = try PowerAuthConfiguration(
            instanceId: "instance-id",
            baseEndpointUrl: URL(string: "https://google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: MASTER_SERVER_PUBLIC_KEY)
        let biometryConfig = PowerAuthConfiguration.Biometry(linkItemsToCurrentSet: !PowerAuthConfiguration.Biometry.default.linkItemsToCurrentSet, fallbackToDevicePasscode: !PowerAuthConfiguration.Biometry.default.fallbackToDevicePasscode)
        let keychainConfig = try PowerAuthConfiguration.Keychains(accessGroupName: "access-group-name")
        let httpClientConfig = try PowerAuthConfiguration.HttpClient(requestTimeout: 10, tlsValidationStrategy: .noValidation, requestInterceptors: [PowerAuthConfigurationTests.Interceptor1()])
        
        // Now build PowerAuth class
        var powerAuth = try PowerAuth(configuration: instanceConfig)
        XCTAssertEqual(instanceConfig, powerAuth.configuration)
        XCTAssertEqual(PowerAuthConfiguration.Biometry.default, powerAuth.configuration.biometry)
        XCTAssertEqual(PowerAuthConfiguration.HttpClient.default, powerAuth.configuration.httpClient)
        XCTAssertEqual(PowerAuthConfiguration.Keychains.default, powerAuth.configuration.keychains)
        
        // Now try a custom config
        // Before that, cleanup cached instances in keychain factory
        try KeychainFactory.factory(for: powerAuth.configuration.keychains).removeAllCachedInstances()
        
        powerAuth = try PowerAuth(configuration: PowerAuthConfiguration(
                                    instanceId: instanceConfig.instanceId,
                                    baseEndpointUrl: instanceConfig.baseEndpointUrl,
                                    applicationKey: instanceConfig.applicationKey,
                                    applicationSecret: instanceConfig.applicationSecret,
                                    masterServerPublicKey: instanceConfig.masterServerPublicKey,
                                    keychainsConfiguration: keychainConfig,
                                    httpClientConfiguration: httpClientConfig,
                                    biometryConfiguration: biometryConfig))
        XCTAssertEqual(powerAuth.configuration.instanceId, instanceConfig.instanceId)
        XCTAssertEqual(powerAuth.configuration.baseEndpointUrl, instanceConfig.baseEndpointUrl)
        XCTAssertEqual(powerAuth.configuration.applicationKey, instanceConfig.applicationKey)
        XCTAssertEqual(powerAuth.configuration.applicationSecret, instanceConfig.applicationSecret)
        XCTAssertEqual(powerAuth.configuration.masterServerPublicKey, instanceConfig.masterServerPublicKey)
        XCTAssertEqual(powerAuth.configuration.disableAutomaticProtocolUpgrade, instanceConfig.disableAutomaticProtocolUpgrade)
        XCTAssertEqual(powerAuth.configuration.externalEncryptionKey, instanceConfig.externalEncryptionKey)
        
        XCTAssertEqual(biometryConfig, powerAuth.configuration.biometry)
        XCTAssertEqual(httpClientConfig, powerAuth.configuration.httpClient)
        XCTAssertEqual(keychainConfig, powerAuth.configuration.keychains)
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
        lhs.externalEncryptionKey == rhs.externalEncryptionKey &&
        lhs.biometry == rhs.biometry &&
        lhs.keychains == rhs.keychains &&
        lhs.httpClient == rhs.httpClient
    }
    
}

extension PowerAuthConfiguration.Biometry: Equatable {
    public static func == (lhs: PowerAuthConfiguration.Biometry, rhs: PowerAuthConfiguration.Biometry) -> Bool {
        lhs.linkItemsToCurrentSet == rhs.linkItemsToCurrentSet &&
        lhs.fallbackToDevicePasscode == rhs.fallbackToDevicePasscode
    }
}

extension PowerAuthConfiguration.Keychains: Equatable {
    public static func == (lhs: PowerAuthConfiguration.Keychains, rhs: PowerAuthConfiguration.Keychains) -> Bool {
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

extension PowerAuthConfiguration.HttpClient: Equatable {
    public static func == (lhs: PowerAuthConfiguration.HttpClient, rhs: PowerAuthConfiguration.HttpClient) -> Bool {
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
