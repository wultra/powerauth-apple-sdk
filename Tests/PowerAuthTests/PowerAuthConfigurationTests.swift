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

final class PowerAuthConfigurationTests: BaseTestCase {

    // MARK: - Instance
    
    let APP_KEY = String.randomBase64(dataCount: 16)
    let APP_SECRET = String.randomBase64(dataCount: 16)
    
    func testInstanceConfiguration() throws {
        var config = try PowerAuthConfiguration(
            instanceId: "my-test",
            baseEndpointUrl: URL(string: "https://www.google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI")
        XCTAssertEqual("my-test", config.instanceId)
        XCTAssertEqual(URL(string: "https://www.google.com"), config.baseEndpointUrl)
        XCTAssertEqual(APP_KEY, config.applicationKey)
        XCTAssertEqual(APP_SECRET, config.applicationSecret)
        XCTAssertEqual("A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI", config.masterServerPublicKey)
        XCTAssertEqual(false, config.disableAutomaticProtocolUpgrade)
        XCTAssertNil(config.externalEncryptionKey)
        
        let EEK = Data.random(count: 16)
        config = try PowerAuthConfiguration(
            instanceId: "my-test",
            baseEndpointUrl: URL(string: "https://www.google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
            externalEncryptionKey: EEK,
            disableAutomaticProtocolUpgrade: true)
            
        XCTAssertEqual("my-test", config.instanceId)
        XCTAssertEqual(URL(string: "https://www.google.com"), config.baseEndpointUrl)
        XCTAssertEqual(APP_KEY, config.applicationKey)
        XCTAssertEqual(APP_SECRET, config.applicationSecret)
        XCTAssertEqual("A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI", config.masterServerPublicKey)
        XCTAssertEqual(true, config.disableAutomaticProtocolUpgrade)
        XCTAssertEqual(EEK, config.externalEncryptionKey)
    }
    
    func testInstanceConfigurationFailures() throws {
        let BAD_MASTER_KEY = String.randomBase64(dataCount: 16)
        let BAD_APP_SECRET = String.randomBase64(dataCount: 12)
        let BAD_APP_KEY = String.randomBase64(dataCount: 17)
        let BAD_EEK = Data.random(count: 1)
        let configParams: [(instanceId: String, baseEndpointUrl: URL, applicationKey: String, applicationSecret: String, masterServerPublicKey: String, externalEncryptionKey: Data?)] =
            [
                (
                    instanceId: "",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: APP_KEY,
                    applicationSecret: APP_SECRET,
                    masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
                    externalEncryptionKey: nil
                ),
                (
                    instanceId: "my-test",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: APP_KEY,
                    applicationSecret: APP_SECRET,
                    masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
                    externalEncryptionKey: BAD_EEK
                ),
                (
                    instanceId: "my-test",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: BAD_APP_KEY,
                    applicationSecret: APP_SECRET,
                    masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
                    externalEncryptionKey: nil
                ),
                (
                    instanceId: "my-test",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: BAD_APP_KEY,
                    applicationSecret: APP_SECRET,
                    masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
                    externalEncryptionKey: nil
                ),
                (
                    instanceId: "my-test",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: APP_KEY,
                    applicationSecret: BAD_APP_SECRET,
                    masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI",
                    externalEncryptionKey: nil
                ),
                (
                    instanceId: "my-test",
                    baseEndpointUrl: URL(string: "https://www.google.com")!,
                    applicationKey: APP_KEY,
                    applicationSecret: APP_SECRET,
                    masterServerPublicKey: BAD_MASTER_KEY,
                    externalEncryptionKey: nil
                )
            ]
        try configParams.forEach { p in
            do {
                _ = try PowerAuthConfiguration(
                    instanceId: p.instanceId,
                    baseEndpointUrl: p.baseEndpointUrl,
                    applicationKey: p.applicationKey,
                    applicationSecret: p.applicationSecret,
                    masterServerPublicKey: p.masterServerPublicKey,
                    externalEncryptionKey: p.externalEncryptionKey
                )
                XCTFail()
            } catch PowerAuthError.invalidConfiguration(let reason) {
                XCTAssertEqual(.invalidInstanceConfiguration, reason)
            }
        }
    }
    
    // MARK: - Biometry
    
    func testBiometryConfiguration() throws {
        let linkBiometricItemsToCurrentSetDefault = PowerAuthConfiguration.Biometry.default.linkItemsToCurrentSet
        let allowBiometricAuthenticationFallbackToDevicePasscodeDefault = PowerAuthConfiguration.Biometry.default.fallbackToDevicePasscode
        var config = PowerAuthConfiguration.Biometry(linkItemsToCurrentSet: linkBiometricItemsToCurrentSetDefault, fallbackToDevicePasscode: allowBiometricAuthenticationFallbackToDevicePasscodeDefault)
        XCTAssertEqual(linkBiometricItemsToCurrentSetDefault, config.linkItemsToCurrentSet)
        XCTAssertEqual(allowBiometricAuthenticationFallbackToDevicePasscodeDefault, config.fallbackToDevicePasscode)
        
        config = PowerAuthConfiguration.Biometry(linkItemsToCurrentSet: !allowBiometricAuthenticationFallbackToDevicePasscodeDefault, fallbackToDevicePasscode: !linkBiometricItemsToCurrentSetDefault)
        XCTAssertEqual(!linkBiometricItemsToCurrentSetDefault, config.linkItemsToCurrentSet)
        XCTAssertEqual(!allowBiometricAuthenticationFallbackToDevicePasscodeDefault, config.fallbackToDevicePasscode)
    }
    
    // MARK: - HttpClient
    
    class Interceptor1: HttpRequestInterceptor {
        func process(request: inout URLRequest) {
        }
    }
    
    class Interceptor2: HttpRequestInterceptor {
        func process(request: inout URLRequest) {
        }
    }
    
    class PinningProvider: TlsPinningProvider {
        func validate(challenge: URLAuthenticationChallenge) -> Bool {
            return true
        }
    }

    func testClientConfiguration() throws {
        // Default config
        let def = PowerAuthConfiguration.HttpClient.default
        var config = try PowerAuthConfiguration.HttpClient()
        XCTAssertEqual(def.requestTimeout, config.requestTimeout)
        XCTAssertEqual(0, config.requestInterceptors.count)
        guard case TlsValidationStrategy.default = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        // Custom interceptors
        config = try PowerAuthConfiguration.HttpClient(requestTimeout: 10, tlsValidationStrategy: .noValidation, requestInterceptors: [Interceptor1(), Interceptor2()])
        XCTAssertEqual(10, config.requestTimeout)
        XCTAssertEqual(2, config.requestInterceptors.count)
        XCTAssertTrue(config.requestInterceptors[0] is Interceptor1)
        XCTAssertTrue(config.requestInterceptors[1] is Interceptor2)
        guard case TlsValidationStrategy.noValidation = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        
        // Pinning
        config = try PowerAuthConfiguration.HttpClient(tlsValidationStrategy: .pinning(provider: PinningProvider()))
        guard case let TlsValidationStrategy.pinning(pinningProvider) = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        XCTAssertTrue(pinningProvider is PinningProvider)
    }
    
    func testClientConfigurationFailures() throws {
        do {
            _ = try PowerAuthConfiguration.HttpClient(requestTimeout: 0)
            XCTFail()
        } catch PowerAuthError.invalidConfiguration(let reason) {
            XCTAssertEqual(.invalidHttpClientConfiguration, reason)
        }
    }
    
    // MARK: - Keychains
    
    func testKeychainConfiguration() throws {
        let def = PowerAuthConfiguration.Keychains.default
        var config = try PowerAuthConfiguration.Keychains()
        XCTAssertNil(config.accessGroupName)
        XCTAssertNil(config.userDefaultsSuiteName)
        XCTAssertEqual(def.statusKeychainName, config.statusKeychainName)
        XCTAssertEqual(def.possessionKeychainName, config.possessionKeychainName)
        XCTAssertEqual(def.biometryKeychainName, config.biometryKeychainName)
        XCTAssertEqual(def.tokenStoreKeychainName, config.tokenStoreKeychainName)
        XCTAssertEqual(def.possessionKeyName, config.possessionKeyName)
        XCTAssertNil(config.biometryKeyName)
        
        config = try PowerAuthConfiguration.Keychains(
            accessGroupName: "access-group",
            userDefaultsSuiteName: "custom-user-defaults",
            statusKeychainName: "status-keychain",
            possessionKeychainName: "possession-keychain",
            biometryKeychainName: "biometry-keychain",
            tokenStoreKeychainName: "tokenstore-keychain",
            possessionKeyName: "shared-possession-key",
            biometryKeyName: "shared-biometry-key")
        XCTAssertEqual("access-group", config.accessGroupName)
        XCTAssertEqual("custom-user-defaults", config.userDefaultsSuiteName)
        XCTAssertEqual("status-keychain", config.statusKeychainName)
        XCTAssertEqual("possession-keychain", config.possessionKeychainName)
        XCTAssertEqual("biometry-keychain", config.biometryKeychainName)
        XCTAssertEqual("tokenstore-keychain", config.tokenStoreKeychainName)
        XCTAssertEqual("shared-possession-key", config.possessionKeyName)
        XCTAssertEqual("shared-biometry-key", config.biometryKeyName)
    }
    
    func testKeychainConfigurationFailures() throws {
        let configParams: [(
            accessGroupName: String?,
            userDefaultsSuiteName: String?,
            statusKeychainName: String?,
            possessionKeychainName: String?,
            biometryKeychainName: String?,
            tokenStoreKeychainName: String?,
            possessionKeyName: String?,
            biometryKeyName: String?
            )] = [
                (
                    accessGroupName: "",
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: "",
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: "",
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: "",
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: "",
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: "",
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: "",
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: ""
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: "conflict",
                    possessionKeychainName: "conflict",
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: "conflict",
                    possessionKeychainName: nil,
                    biometryKeychainName: "conflict",
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: "conflict",
                    possessionKeychainName: nil,
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: "conflict",
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: "conflict",
                    biometryKeychainName: "conflict",
                    tokenStoreKeychainName: nil,
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: "conflict",
                    biometryKeychainName: nil,
                    tokenStoreKeychainName: "conflict",
                    possessionKeyName: nil,
                    biometryKeyName: nil
                ),
                (
                    accessGroupName: nil,
                    userDefaultsSuiteName: nil,
                    statusKeychainName: nil,
                    possessionKeychainName: nil,
                    biometryKeychainName: "conflict",
                    tokenStoreKeychainName: "conflict",
                    possessionKeyName: nil,
                    biometryKeyName: nil
                )
            ]
        try configParams.forEach { p in
            do {
                _ = try PowerAuthConfiguration.Keychains(
                    accessGroupName: p.accessGroupName,
                    userDefaultsSuiteName: p.userDefaultsSuiteName,
                    statusKeychainName: p.statusKeychainName,
                    possessionKeychainName: p.possessionKeychainName,
                    biometryKeychainName: p.biometryKeychainName,
                    tokenStoreKeychainName: p.tokenStoreKeychainName,
                    possessionKeyName: p.possessionKeyName,
                    biometryKeyName: p.biometryKeyName)
                XCTFail()
            } catch PowerAuthError.invalidConfiguration(let reason) {
                XCTAssertEqual(.invalidKeychainConfiguration, reason)
            }
        }
    }

}
