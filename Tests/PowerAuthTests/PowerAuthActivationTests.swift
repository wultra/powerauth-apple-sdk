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

final class PowerAuthActicationTests: XCTestCase {
    
    // MARK: - Regular
    
    func testRegularActivation() throws {
        let act1 = try PowerAuthActivation.Builder(withActivationCode: "VVVVV-VVVVV-VVVVV-VTFVA").build()
        XCTAssertEqual(.activationCode, act1.activationType)
        XCTAssertEqual(["code":"VVVVV-VVVVV-VVVVV-VTFVA"], act1.identityAttributes)
        XCTAssertNil(act1.name)
        XCTAssertNil(act1.extras)
        XCTAssertNil(act1.customAttributes)
        
        let act2 = try PowerAuthActivation.Builder(withActivationCode: "3PZ2Z-DOXSL-PSSQI-I5VBA#MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw==", activationName: "Troyplatnitchka")
            .build()
        XCTAssertEqual(.activationCode, act2.activationType)
        XCTAssertEqual(["code":"3PZ2Z-DOXSL-PSSQI-I5VBA"], act2.identityAttributes)
        XCTAssertEqual("3PZ2Z-DOXSL-PSSQI-I5VBA", act2.activationCode?.activationCode)
        XCTAssertEqual("MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw==", act2.activationCode?.activationSignature)
        XCTAssertEqual("Troyplatnitchka", act2.name)
        
        let act3 = try PowerAuthActivation.Builder(withActivationCode: "55555-55555-55555-55YMA", activationName: "Troyplatnitchka")
            .set(additionalActivationOtp: "1234")
            .set(extras: "EXTRAS")
            .set(customAttributes: ["customInt":1, "customString":"STR"])
            .build()
        XCTAssertEqual(["code":"55555-55555-55555-55YMA"], act3.identityAttributes)
        XCTAssertEqual("55555-55555-55555-55YMA", act3.activationCode?.activationCode)
        XCTAssertEqual("1234", act3.additionalActivationOtp)
        XCTAssertEqual("Troyplatnitchka", act3.name)
        XCTAssertEqual("EXTRAS", act3.extras)
        XCTAssertEqual(1, act3.customAttributes?["customInt"] as? Int)
        XCTAssertEqual("STR", act3.customAttributes?["customString"] as? String)
    }
    
    func testRegularActivationInvalid() throws {
        do {
            _ = try PowerAuthActivation.Builder(withActivationCode: "1234")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.wrongActivationCode, reason)
        }
        do {
            _ = try PowerAuthActivation.Builder(withActivationCode: "VVVVV-VVVVV-VVVVV-VTFVA")
                .set(additionalActivationOtp: "")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.emptyOtp, reason)
        }
    }
    
    // MARK: - Recovery
    
    func testRecoveryActivation() throws {
        let act1 = try PowerAuthActivation.Builder(withRecoveryCode: "VVVVV-VVVVV-VVVVV-VTFVA", puk: "0123456789")
            .build()
        XCTAssertEqual(.recoveryCode, act1.activationType)
        XCTAssertEqual(["recoveryCode" : "VVVVV-VVVVV-VVVVV-VTFVA" , "puk" : "0123456789"], act1.identityAttributes)
        XCTAssertNil(act1.name)
        XCTAssertNil(act1.extras)
        XCTAssertNil(act1.customAttributes)
        XCTAssertNil(act1.activationCode)
        
        let act2 = try PowerAuthActivation.Builder(withRecoveryCode: "R:3PZ2Z-DOXSL-PSSQI-I5VBA", puk: "0123456789", activationName: "John Tramonta")
            .set(extras: "EXTRAS")
            .set(customAttributes: ["customInt":1, "customString":"STR"])
            .build()
        XCTAssertEqual(.recoveryCode, act2.activationType)
        XCTAssertEqual(["recoveryCode" : "3PZ2Z-DOXSL-PSSQI-I5VBA" , "puk" : "0123456789"], act2.identityAttributes)
        XCTAssertEqual("John Tramonta", act2.name)
        XCTAssertEqual("EXTRAS", act2.extras)
        XCTAssertEqual(1, act2.customAttributes?["customInt"] as? Int)
        XCTAssertEqual("STR", act2.customAttributes?["customString"] as? String)
        XCTAssertNil(act2.activationCode)
    }
    
    func testRecoveryActivationInvalid() throws {
        do {
            _ = try PowerAuthActivation.Builder(withRecoveryCode: "12345", puk: "0123456789")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.wrongRecoveryCode, reason)
        }
        do {
            _ = try PowerAuthActivation.Builder(withRecoveryCode: "3PZ2Z-DOXSL-PSSQI-I5VBA", puk: "1234")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.wrongRecoveryPuk, reason)
        }
        do {
            _ = try PowerAuthActivation.Builder(withRecoveryCode: "VVVVV-VVVVV-VVVVV-VTFVA", puk: "0123456789")
                .set(additionalActivationOtp: "1234")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.otpInWrongActivationType, reason)
        }
    }
    
    // MARK: - Custom
    
    func testCustomActivation() throws {
        let act1 = try PowerAuthActivation.Builder(withIdentityAttributes: ["login":"johntramonta", "pass":"nbusr123"])
            .build()
        
        XCTAssertEqual(.custom, act1.activationType)
        XCTAssertEqual(["login":"johntramonta", "pass":"nbusr123"], act1.identityAttributes)
        XCTAssertNil(act1.name)
        XCTAssertNil(act1.extras)
        XCTAssertNil(act1.customAttributes)
        
        let act2 = try PowerAuthActivation.Builder(withIdentityAttributes: ["login":"johntramonta", "pass":"nbusr123"], activationName: "John Tramonta")
            .set(extras: "EXTRAS")
            .set(customAttributes: ["customInt":1, "customString":"STR"])
            .build()
        
        XCTAssertEqual(.custom, act2.activationType)
        XCTAssertEqual(["login":"johntramonta", "pass":"nbusr123"], act2.identityAttributes)
        XCTAssertEqual("John Tramonta", act2.name)
        XCTAssertEqual("EXTRAS", act2.extras)
        XCTAssertEqual(1, act2.customAttributes?["customInt"] as? Int)
        XCTAssertEqual("STR", act2.customAttributes?["customString"] as? String)
    }
    
    func testCustomActivationInvalid() throws {
        do {
            _ = try PowerAuthActivation.Builder(withIdentityAttributes: ["login":"johntramonta", "pass":"nbusr123"])
                .set(additionalActivationOtp: "1234")
                .build()
        } catch PowerAuthError.invalidActivationData(let reason) {
            XCTAssertEqual(.otpInWrongActivationType, reason)
        }
    }
}
