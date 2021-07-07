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

final class ConfigurationTests: XCTestCase {

    let APP_KEY = String.randomBase64(dataCount: 16)
    let APP_SECRET = String.randomBase64(dataCount: 16)
    
    func testConfigurationBuilder() throws {
        var config = try Configuration.Builder(
            instanceId: "my-test",
            baseEndpointUrl: URL(string: "https://www.google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI")
            .build()
        XCTAssertEqual("my-test", config.instanceId)
        XCTAssertEqual(URL(string: "https://www.google.com"), config.baseEndpointUrl)
        XCTAssertEqual(APP_KEY, config.applicationKey)
        XCTAssertEqual(APP_SECRET, config.applicationSecret)
        XCTAssertEqual("A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI", config.masterServerPublicKey)
        XCTAssertEqual(false, config.disableAutomaticProtocolUpgrade)
        XCTAssertNil(config.externalEncryptionKey)
        
        let EEK = Data.random(count: 16)
        config = try Configuration.Builder(
            instanceId: "my-test",
            baseEndpointUrl: URL(string: "https://www.google.com")!,
            applicationKey: APP_KEY,
            applicationSecret: APP_SECRET,
            masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI")
            .set(disableAutomaticProtocolUpgrade: true)
            .set(externalEncryptionKey: EEK)
            .build()
        XCTAssertEqual("my-test", config.instanceId)
        XCTAssertEqual(URL(string: "https://www.google.com"), config.baseEndpointUrl)
        XCTAssertEqual(APP_KEY, config.applicationKey)
        XCTAssertEqual(APP_SECRET, config.applicationSecret)
        XCTAssertEqual("A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI", config.masterServerPublicKey)
        XCTAssertEqual(true, config.disableAutomaticProtocolUpgrade)
        XCTAssertEqual(EEK, config.externalEncryptionKey)
    }
    
    func testConfigurationBuilderFailures() throws {
        let BAD_MASTER_KEY = String.randomBase64(dataCount: 16)
        let BAD_APP_SECRET = String.randomBase64(dataCount: 12)
        let BAD_APP_KEY = String.randomBase64(dataCount: 17)
        let BAD_EEK = Data.random(count: 1)
        
        try [
            Configuration.Builder(
                instanceId: "",
                baseEndpointUrl: URL(string: "https://www.google.com")!,
                applicationKey: APP_KEY,
                applicationSecret: APP_SECRET,
                masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI"),
            Configuration.Builder(
                instanceId: "my-test",
                baseEndpointUrl: URL(string: "https://www.google.com")!,
                applicationKey: APP_KEY,
                applicationSecret: APP_SECRET,
                masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI")
                .set(externalEncryptionKey: BAD_EEK),
            Configuration.Builder(
                instanceId: "my-test",
                baseEndpointUrl: URL(string: "https://www.google.com")!,
                applicationKey: BAD_APP_KEY,
                applicationSecret: APP_SECRET,
                masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI"),
            Configuration.Builder(
                instanceId: "my-test",
                baseEndpointUrl: URL(string: "https://www.google.com")!,
                applicationKey: APP_KEY,
                applicationSecret: BAD_APP_SECRET,
                masterServerPublicKey: "A+KG3cfFY/PoaH8SKeBuxiDevIkyzqj+E8AJ4Fa8JuiI"),
            Configuration.Builder(
                instanceId: "my-test",
                baseEndpointUrl: URL(string: "https://www.google.com")!,
                applicationKey: APP_KEY,
                applicationSecret: APP_SECRET,
                masterServerPublicKey: BAD_MASTER_KEY),
        ].forEach { builder in
            do {
                _ = try builder.build()
                XCTFail()
            } catch PowerAuthError.invalidConfiguration(let reason) {
                XCTAssertEqual(.invalidConfiguration, reason)
            }
        }
    }
}
