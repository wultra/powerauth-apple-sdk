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

final class InputValidatorTests: XCTestCase {

    /// Test Base64 input validator
    func testBase64Validations() throws {
        let d1 = String.randomBase64(dataCount: 16)
        XCTAssertTrue(InputValidator.validate(base64String: d1, expectedCount: 16))
        XCTAssertTrue(InputValidator.validate(base64String: d1, min: 16, max: 16))
        XCTAssertTrue(InputValidator.validate(base64String: d1, min: 16, max: nil))
        XCTAssertTrue(InputValidator.validate(base64String: d1, min: nil, max: 16))
        
        let d2 = String.randomBase64(dataCount: 15)
        XCTAssertFalse(InputValidator.validate(base64String: d2, expectedCount: 16))
        XCTAssertFalse(InputValidator.validate(base64String: d2, min: 16, max: 16))
        XCTAssertFalse(InputValidator.validate(base64String: d2, min: 16, max: nil))
        XCTAssertTrue(InputValidator.validate(base64String: d2, min: nil, max: 16))
        
        XCTAssertTrue(InputValidator.validate(base64String: "SGVsbG8gV29ybGQh", expectedCount: 12))
        XCTAssertFalse(InputValidator.validate(base64String: "SGV;bG8gV29ybGQh", expectedCount: 12))
        XCTAssertFalse(InputValidator.validate(base64String: "SGVsbG8gV29ybGQ", expectedCount: 12))
        XCTAssertFalse(InputValidator.validate(base64String: "SGVsbG8gV29ybGQh==", expectedCount: 12))
    }
    
}
