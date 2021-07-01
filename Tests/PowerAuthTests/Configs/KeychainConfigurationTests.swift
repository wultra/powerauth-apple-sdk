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

final class KeychainConfigurationTests: XCTestCase {

    func testConfigurationBuilder() throws {
        let def = KeychainConfiguration.default
        var config = try KeychainConfiguration.Builder().build()
        XCTAssertNil(config.accessGroupName)
        XCTAssertNil(config.userDefaultsSuiteName)
        XCTAssertEqual(def.statusKeychainName, config.statusKeychainName)
        XCTAssertEqual(def.possessionKeychainName, config.possessionKeychainName)
        XCTAssertEqual(def.biometryKeychainName, config.biometryKeychainName)
        XCTAssertEqual(def.tokenStoreKeychainName, config.tokenStoreKeychainName)
        XCTAssertEqual(def.possessionKeyName, config.possessionKeyName)
        XCTAssertNil(config.biometryKeyName)
        
        config = try KeychainConfiguration.Builder()
            .set(accessGroupName: "access-group")
            .set(userDefaultsSuiteName: "custom-user-defaults")
            .set(statusKeychainName: "status-keychain")
            .set(possessionKeychainName: "possession-keychain")
            .set(biometryKeychainName: "biometry-keychain")
            .set(tokenStoreKeychainName: "tokenstore-keychain")
            .set(possessionKeyName: "shared-possession-key")
            .set(biometryKeyName: "shared-biometry-key")
            .build()
        
        XCTAssertEqual("access-group", config.accessGroupName)
        XCTAssertEqual("custom-user-defaults", config.userDefaultsSuiteName)
        XCTAssertEqual("status-keychain", config.statusKeychainName)
        XCTAssertEqual("possession-keychain", config.possessionKeychainName)
        XCTAssertEqual("biometry-keychain", config.biometryKeychainName)
        XCTAssertEqual("tokenstore-keychain", config.tokenStoreKeychainName)
        XCTAssertEqual("shared-possession-key", config.possessionKeyName)
        XCTAssertEqual("shared-biometry-key", config.biometryKeyName)
    }
    
    func testConfigurationBuilderFailures() throws {
        try [
            // Empty option
            KeychainConfiguration.Builder()
                .set(accessGroupName: ""),
            KeychainConfiguration.Builder()
                .set(userDefaultsSuiteName: ""),
            KeychainConfiguration.Builder()
                .set(statusKeychainName: ""),
            KeychainConfiguration.Builder()
                .set(biometryKeychainName: ""),
            KeychainConfiguration.Builder()
                .set(possessionKeychainName: ""),
            KeychainConfiguration.Builder()
                .set(tokenStoreKeychainName: ""),
            KeychainConfiguration.Builder()
                .set(possessionKeyName: ""),
            KeychainConfiguration.Builder()
                .set(biometryKeyName: ""),
            
            // Conflicting names
            KeychainConfiguration.Builder()
                .set(statusKeychainName: "conflict")
                .set(biometryKeychainName: "conflict"),
            KeychainConfiguration.Builder()
                .set(statusKeychainName: "conflict")
                .set(possessionKeychainName: "conflict"),
            KeychainConfiguration.Builder()
                .set(statusKeychainName: "conflict")
                .set(tokenStoreKeychainName: "conflict"),
            KeychainConfiguration.Builder()
                .set(biometryKeychainName: "conflict")
                .set(possessionKeychainName: "conflict"),
            KeychainConfiguration.Builder()
                .set(biometryKeychainName: "conflict")
                .set(tokenStoreKeychainName: "conflict"),
            KeychainConfiguration.Builder()
                .set(possessionKeychainName: "conflict")
                .set(tokenStoreKeychainName: "conflict"),
        ].forEach { builder in
            do {
                _ = try builder.build()
                XCTFail()
            } catch PowerAuthError.invalidConfiguration(let reason) {
                XCTAssertEqual(.invalidKeychainConfiguration, reason)
            }
        }
    }

}
