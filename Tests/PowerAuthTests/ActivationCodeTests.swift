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

final class ActicationCodeTests: BaseTestCase {
    
    // MARK: Activation code
    
    func testActivationCodeValidation() throws {
        // Valid codes
        [
            // nice codes
            "AAAAA-AAAAA-AAAAA-AAAAA",
            "MMMMM-MMMMM-MMMMM-MUTOA",
            "VVVVV-VVVVV-VVVVV-VTFVA",
            "55555-55555-55555-55YMA",
            // random codes
            "W65WE-3T7VI-7FBS2-A4OYA",
            "DD7P5-SY4RW-XHSNB-GO52A",
            "X3TS3-TI35Z-JZDNT-TRPFA",
            "HCPJX-U4QC4-7UISL-NJYMA",
            "XHGSM-KYQDT-URE34-UZGWQ",
            "45AWJ-BVACS-SBWHS-ABANA",
            "BUSES-ETYN2-5HTFE-NOV2Q",
            "ATQAZ-WJ7ZG-FWA7J-QFAJQ",
            "MXSYF-LLQJ7-PS6LF-E2FMQ",
            "ZKMVN-4IMFK-FLSYX-ARRGA",
            "NQHGX-LNM2S-EQ4NT-G3NAA",
        ].forEach { code in
            XCTAssertTrue(ActivationCodeValidator.validate(activationCode: code))
        }
        // Invalid codes
        [
            "",
            " ",
            "KLMNO-PQRST",
            "KLMNO-PQRST-UVWXY-Z234",
            "KLMNO-PQRST-UVWXY-Z2345 ",
            "KLMNO-PQRST-UVWXY-Z2345#",
            "67AAA-B0BCC-DDEEF-GGHHI",
            "67AAA-BB1CC-DDEEF-GGHHI",
            "67AAA-BBBC8-DDEEF-GGHHI",
            "67AAA-BBBCC-DDEEF-GGHH9",
            "67aAA-BBBCC-DDEEF-GGHHI",
            "6-AAA-BB1CC-DDEEF-GGHHI",
            "67AA#-BB1CC-DDEEF-GGHHI",
            "67AABCBB1CC-DDEEF-GGHHI",
            "67AAB-BB1CCEDDEEF-GGHHI",
            "67AAA-BBBCC-DDEEFZGGHHI",
        ].forEach { code in
            XCTAssertFalse(ActivationCodeValidator.validate(activationCode: code))
        }
    }
    
    func testActivationCodeParser() throws {
        var result: ActivationCode?
        // Valid codes
        result = .parse(fromActivationCode: "BBBBB-BBBBB-BBBBB-BTA6Q")
        XCTAssertEqual("BBBBB-BBBBB-BBBBB-BTA6Q", result?.activationCode)
        XCTAssertNil(result?.activationSignature)
        XCTAssertFalse(result?.hasActivationSignature ?? true)
        result = .parse(fromActivationCode: "CCCCC-CCCCC-CCCCC-CNUUQ#ABCD")
        XCTAssertEqual("CCCCC-CCCCC-CCCCC-CNUUQ", result?.activationCode)
        XCTAssertEqual("ABCD", result?.activationSignature)
        XCTAssertTrue(result?.hasActivationSignature ?? false)
        result = .parse(fromActivationCode: "DDDDD-DDDDD-DDDDD-D6UKA#ABC=")
        XCTAssertEqual("DDDDD-DDDDD-DDDDD-D6UKA", result?.activationCode)
        XCTAssertEqual("ABC=", result?.activationSignature)
        XCTAssertTrue(result?.hasActivationSignature ?? false)
        result = .parse(fromActivationCode: "EEEEE-EEEEE-EEEEE-E2OXA#AB==")
        XCTAssertEqual("EEEEE-EEEEE-EEEEE-E2OXA", result?.activationCode)
        XCTAssertEqual("AB==", result?.activationSignature)
        XCTAssertTrue(result?.hasActivationSignature ?? false)
        // Invalid codes
        [
            "",
            "#",
            "#AB==",
            "KLMNO-PQRST",
            "EEEEE-EEEEE-EEEEE-E2OXA#",
            "OOOOO-OOOOO-OOOOO-OZH2Q#",
            "SSSSS-SSSSS-SSSSS-SX7IA#AB",
            "UUUUU-UUUUU-UUUUU-UAFLQ#AB#",
            "WWWWW-WWWWW-WWWWW-WNR7A#ABA=#",
            "XXXXX-XXXXX-XXXXX-X6RBQ#ABA-="
        ].forEach { code in
            XCTAssertNil(ActivationCode.parse(fromActivationCode:code))
        }
    }
    // MARK: Characters validation
    
    func testCharAutocorrection() throws {
        // Valid characters
        let data: [(original: String, corrected: String)] = [
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            ),
            (
                "abcdefghijklmnopqrstuvwxyz01",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZOI"
            )
        ]
        data.forEach { (original: String, corrected: String) in
            let autoCorrected = autoCorrect(string: original)
            if autoCorrected != corrected {
                XCTFail()
            }
        }
        // Invalid characters
        "89-=#$%^&!@#-=';()".unicodeScalars.forEach { scalar in
            XCTAssertNil(ActivationCodeValidator.validateAndCorrect(typedCharacter: scalar))
        }
    }
    
    func autoCorrect(string: String) -> String {
        let result = string.unicodeScalars
            .map { ActivationCodeValidator.validateAndCorrect(typedCharacter: $0) ?? "\u{00}" }
            .map { Character($0) }
        return String(result)
     }
    
    func testCharValidation() throws {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".unicodeScalars.forEach { scalar in
            XCTAssertTrue(ActivationCodeValidator.validate(typedCharacter: scalar))
        }
        "abcdefghijklmnopqrstuvwxyz0189-=#$%^&!@#-=';()".unicodeScalars.forEach { scalar in
            XCTAssertFalse(ActivationCodeValidator.validate(typedCharacter: scalar))
        }
    }
    
    // MARK: Recovery code
    
    func testRecoveryCodeValidation() throws {
        // Valid
        [
            // nice codes
            "AAAAA-AAAAA-AAAAA-AAAAA",
            "MMMMM-MMMMM-MMMMM-MUTOA",
            "VVVVV-VVVVV-VVVVV-VTFVA",
            "55555-55555-55555-55YMA",
            // random codes
            "W65WE-3T7VI-7FBS2-A4OYA",
            "DD7P5-SY4RW-XHSNB-GO52A",
            "X3TS3-TI35Z-JZDNT-TRPFA",
            "HCPJX-U4QC4-7UISL-NJYMA",
            "XHGSM-KYQDT-URE34-UZGWQ",
            "45AWJ-BVACS-SBWHS-ABANA",

            // With R: prefix
            "R:AAAAA-AAAAA-AAAAA-AAAAA",
            "R:MMMMM-MMMMM-MMMMM-MUTOA",
            "R:VVVVV-VVVVV-VVVVV-VTFVA",
            "R:55555-55555-55555-55YMA",
            "R:BUSES-ETYN2-5HTFE-NOV2Q",
            "R:ATQAZ-WJ7ZG-FWA7J-QFAJQ",
            "R:MXSYF-LLQJ7-PS6LF-E2FMQ",
            "R:ZKMVN-4IMFK-FLSYX-ARRGA",
            "R:NQHGX-LNM2S-EQ4NT-G3NAA",
        ].forEach { code in
            XCTAssertTrue(ActivationCodeValidator.validate(recoveryCode: code))
        }
        // Invalid
        [
            "",
            " ",
            "R",
            "R:",
            "X:AAAAA-AAAAA-AAAAA-AAAAA",
            "KLMNO-PQRST",
            "R:KLMNO-PQRST",
            "KLMNO-PQRST-UVWXY-Z234",
            "KLMNO-PQRST-UVWXY-Z2345 ",
            "R:KLMNO-PQRST-UVWXY-Z2345 ",
            "KLMNO-PQRST-UVWXY-Z2345#",
            "NQHGX-LNM2S-EQ4NT-G3NAA#aGVsbG8td29ybGQ=",
            "R:NQHGX-LNM2S-EQ4NT-G3NAA#aGVsbG8td29ybGQ=",
            "67AAA-B0BCC-DDEEF-GGHHI",
            "67AAA-BB1CC-DDEEF-GGHHI",
            "67AAA-BBBC8-DDEEF-GGHHI",
            "67AAA-BBBCC-DDEEF-GGHH9",
            "67aAA-BBBCC-DDEEF-GGHHI",
            "6-AAA-BB1CC-DDEEF-GGHHI",
            "67AA#-BB1CC-DDEEF-GGHHI",
            "67AABCBB1CC-DDEEF-GGHHI",
            "67AAB-BB1CCEDDEEF-GGHHI",
            "67AAA-BBBCC-DDEEFZGGHHI",
        ].forEach { code in
            XCTAssertFalse(ActivationCodeValidator.validate(recoveryCode: code))
        }
    }
    
    func testRecoveryPukValidation() throws {
        // Valid
        [
            "0000000000",
            "9999999999",
            "0123456789",
            "9876543210",
            "1111111111",
            "3487628763",
        ].forEach { puk in
            XCTAssertTrue(ActivationCodeValidator.validate(recoveryPuk: puk))
        }
        // Invalid
        [
            "",
            " ",
            "11111111111",
            "111111111",
            "0",
            "999999999A",
            "99999999b9",
            "9999999c99",
            "999999d999",
            "99999e9999",
            "9999f99999",
            "999g999999",
            "99h9999999",
            "9i99999999",
            "A999999999",
            "999999999 ",
            "99999999 9",
            "9999999 99",
            "999999 999",
            "99999 9999",
            "9999 99999",
            "999 999999",
            "99 9999999",
            "9 99999999",
            " 999999999",
        ].forEach { puk in
            XCTAssertFalse(ActivationCodeValidator.validate(recoveryPuk: puk))
        }
    }
    
    func testRecoveryCodesParser() throws {
        // Valid
        var result: ActivationCode?
        result = .parse(fromRecoveryCode: "BBBBB-BBBBB-BBBBB-BTA6Q")
        XCTAssertEqual("BBBBB-BBBBB-BBBBB-BTA6Q", result?.activationCode)
        XCTAssertNil(result?.activationSignature)
        result = .parse(fromRecoveryCode: "R:BBBBB-BBBBB-BBBBB-BTA6Q")
        XCTAssertEqual("BBBBB-BBBBB-BBBBB-BTA6Q", result?.activationCode)
        XCTAssertNil(result?.activationSignature)
        // Invalid
        [
            "",
            "#",
            "#AB==",
            "KLMNO-PQRST",
            "EEEEE-EEEEE-EEEEE-E2OXA#",
            "OOOOO-OOOOO-OOOOO-OZH2Q#",
            "SSSSS-SSSSS-SSSSS-SX7IA#AB",
            "UUUUU-UUUUU-UUUUU-UAFLQ#AB#",
            "WWWWW-WWWWW-WWWWW-WNR7A#ABA=#",
            "XXXXX-XXXXX-XXXXX-X6RBQ#ABA-=",
            "DDDDD-DDDDD-DDDDD-D6UKA#ABC=",
            "EEEEE-EEEEE-EEEEE-E2OXA#AB==",
            "R:DDDDD-DDDDD-DDDDD-D6UKA#ABC=",
            "R:EEEEE-EEEEE-EEEEE-E2OXA#AB==",
        ].forEach { code in
            XCTAssertNil(ActivationCode.parse(fromRecoveryCode:code))
        }
    }
}

