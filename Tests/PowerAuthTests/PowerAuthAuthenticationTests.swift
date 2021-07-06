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
import PowerAuthCore
import LocalAuthentication
@testable import PowerAuth

final class PowerAuthAuthenticationTests: XCTestCase {
    
    let dataProvider = FakeDataProvider(possessionKey: Data.random(count: 16), biometryKey: Data.random(count: 16))
    
    let customPossessionKey = Data.random(count: 16)
    let customBiometryKey = Data.random(count: 16)
    
    func testPossessionFactor() throws {
        let auth1 = PowerAuthAuthentication.possession()
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possession, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNil(keys1.biometryKey)
        XCTAssertNil(keys1.password)
        
        let auth2 = PowerAuthAuthentication.possession(customPossessionKey: customPossessionKey)
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possession, auth2.factors)
        XCTAssertEqual(customPossessionKey, keys2.possessionKey)
        XCTAssertNil(keys2.biometryKey)
        XCTAssertNil(keys2.password)
    }
    
    func testKnowledgeWithPossession() throws {
        let auth1 = PowerAuthAuthentication.knowledgeWithPossession(password: "NBUSR123")
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNil(keys1.biometryKey)
        XCTAssertTrue(keys1.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth2 = PowerAuthAuthentication.knowledgeWithPossession(password: Password(string: "NBUSR123"))
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth2.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys2.possessionKey)
        XCTAssertNil(keys2.biometryKey)
        XCTAssertTrue(keys2.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth3 = PowerAuthAuthentication.knowledgeWithPossession(password: "NBUSR123", customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertNil(keys3.biometryKey)
        XCTAssertTrue(keys3.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
    }
    
    func testBiometryWithPossession() throws {
        let ctx = LAContext()
        let auth1 = PowerAuthAuthentication.biometryWithPossession(localAuthentication: ctx)
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertEqual(dataProvider.biometryKey, keys1.biometryKey)
        
        let auth2 = PowerAuthAuthentication.biometryWithPossession(customBiometryKey: customBiometryKey)
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth2.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys2.possessionKey)
        XCTAssertEqual(customBiometryKey, keys2.biometryKey)
        
        let auth3 = PowerAuthAuthentication.biometryWithPossession(customBiometryKey: customBiometryKey, customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertEqual(customBiometryKey, keys3.biometryKey)
        
        do {
            // Test missing factor
            try dataProvider.removeBiometryFactorEncryptionKey()
            let auth4 = PowerAuthAuthentication.biometryWithPossession(localAuthentication: ctx)
            _ = try auth4.getSignatureFactorKeys(with: dataProvider)
        } catch PowerAuthError.biometricAuthenticationFailed(let reason) {
            XCTAssertEqual(.notConfigured, reason)
        }
    }
}
