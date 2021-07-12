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

final class AuthenticationTests: BaseTestCase {
    
    let dataProvider = FakeDataProvider(possessionKey: Data.random(count: 16), biometryKey: Data.random(count: 16))
    
    let customPossessionKey = Data.random(count: 16)
    let customBiometryKey = Data.random(count: 16)
    
    func testCommitWithKnowledge() throws {
        let auth1 = Authentication.commitWithKnowledge(password: "NBUSR123")
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledge, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNil(keys1.biometryKey)
        XCTAssertTrue(keys1.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)

        let auth2 = Authentication.commitWithKnowledge(password: Password(string: "NBUSR123"), customPossessionKey: customPossessionKey)
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledge, auth2.factors)
        XCTAssertEqual(customPossessionKey, keys2.possessionKey)
        XCTAssertNil(keys2.biometryKey)
        XCTAssertTrue(keys2.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth3 = Authentication.commitWithKnowledge(password: "NBUSR123", customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledge, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertNil(keys3.biometryKey)
        XCTAssertTrue(keys3.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
    }
    
    func testCommitWithKnowledgeAndBiometry() throws {
        let auth1 = Authentication.commitWithKnowledgeAndBiometry(password: "NBUSR123")
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledgeAndBiometry, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNotNil(keys1.biometryKey) // random key, cannot be evaluated
        XCTAssertTrue(keys1.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth2 = Authentication.commitWithKnowledgeAndBiometry(password: Password(string: "NBUSR123"))
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledgeAndBiometry, auth2.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys2.possessionKey)
        XCTAssertNotNil(keys2.biometryKey) // random key, cannot be evaluated
        XCTAssertTrue(keys2.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth3 = Authentication.commitWithKnowledgeAndBiometry(password: Password(string: "NBUSR123"), customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledgeAndBiometry, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertNotNil(keys3.biometryKey) // random key, cannot be evaluated
        XCTAssertTrue(keys3.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth4 = Authentication.commitWithKnowledgeAndBiometry(password: Password(string: "NBUSR123"), customBiometryKey: customBiometryKey, customPossessionKey: customPossessionKey)
        let keys4 = try auth4.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledgeAndBiometry, auth4.factors)
        XCTAssertEqual(customPossessionKey, keys4.possessionKey)
        XCTAssertEqual(customBiometryKey, keys4.biometryKey)
        XCTAssertTrue(keys4.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth5 = Authentication.commitWithKnowledgeAndBiometry(password: Password(string: "NBUSR123"), customBiometryKey: customBiometryKey)
        let keys5 = try auth5.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.commitWithKnowledgeAndBiometry, auth5.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys5.possessionKey)
        XCTAssertEqual(customBiometryKey, keys5.biometryKey)
        XCTAssertTrue(keys5.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
    }
    
    func testPossessionFactor() throws {
        let auth1 = Authentication.possession()
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possession, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNil(keys1.biometryKey)
        XCTAssertNil(keys1.password)
        
        let auth2 = Authentication.possession(customPossessionKey: customPossessionKey)
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possession, auth2.factors)
        XCTAssertEqual(customPossessionKey, keys2.possessionKey)
        XCTAssertNil(keys2.biometryKey)
        XCTAssertNil(keys2.password)
    }
    
    func testKnowledgeWithPossession() throws {
        let auth1 = Authentication.knowledgeWithPossession(password: "NBUSR123")
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertNil(keys1.biometryKey)
        XCTAssertTrue(keys1.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth2 = Authentication.knowledgeWithPossession(password: Password(string: "NBUSR123"))
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth2.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys2.possessionKey)
        XCTAssertNil(keys2.biometryKey)
        XCTAssertTrue(keys2.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
        
        let auth3 = Authentication.knowledgeWithPossession(password: "NBUSR123", customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithKnowledge, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertNil(keys3.biometryKey)
        XCTAssertTrue(keys3.password?.isEqual(to: Password(string: "NBUSR123")) ?? false)
    }
    
    func testBiometryWithPossession() throws {
        let ctx = LAContext()
        let auth1 = Authentication.biometryWithPossession(localAuthentication: ctx)
        let keys1 = try auth1.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth1.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys1.possessionKey)
        XCTAssertEqual(dataProvider.biometryKey, keys1.biometryKey)
        
        let auth2 = Authentication.biometryWithPossession(customBiometryKey: customBiometryKey)
        let keys2 = try auth2.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth2.factors)
        XCTAssertEqual(dataProvider.possessionKey, keys2.possessionKey)
        XCTAssertEqual(customBiometryKey, keys2.biometryKey)
        
        let auth3 = Authentication.biometryWithPossession(customBiometryKey: customBiometryKey, customPossessionKey: customPossessionKey)
        let keys3 = try auth3.getSignatureFactorKeys(with: dataProvider)
        XCTAssertEqual(.possessionWithBiometry, auth3.factors)
        XCTAssertEqual(customPossessionKey, keys3.possessionKey)
        XCTAssertEqual(customBiometryKey, keys3.biometryKey)
        
        do {
            // Test missing factor
            try dataProvider.removeBiometryFactorEncryptionKey()
            let auth4 = Authentication.biometryWithPossession(localAuthentication: ctx)
            _ = try auth4.getSignatureFactorKeys(with: dataProvider)
        } catch PowerAuthError.biometricAuthenticationFailed(let reason) {
            XCTAssertEqual(.notConfigured, reason)
        }
    }
    
    func testFactorVsCommitFlag() throws {
        XCTAssertTrue(Authentication.Factors.commitWithKnowledge.isFactorsForActivationCommit)
        XCTAssertTrue(Authentication.Factors.commitWithKnowledgeAndBiometry.isFactorsForActivationCommit)
        XCTAssertFalse(Authentication.Factors.possession.isFactorsForActivationCommit)
        XCTAssertFalse(Authentication.Factors.possessionWithKnowledge.isFactorsForActivationCommit)
        XCTAssertFalse(Authentication.Factors.possessionWithBiometry.isFactorsForActivationCommit)
    }
}
