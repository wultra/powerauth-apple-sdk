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

import Foundation

/// Contains various validation functions to do API-level validations.
enum InputValidator {

    /// Validate whether string contains Base64 formatted string with expected length of data.
    /// - Parameters:
    ///   - base64String: String to validate
    ///   - expectedCount: Expected count of bytes encoded in Base64 formatted string.
    /// - Returns: true if string contains Base64 formatted data with expected length.
    static func validate(base64String: String, expectedCount: Int) -> Bool {
        return validate(base64String: base64String, min: expectedCount, max: expectedCount)
    }
    
    /// Validate whether string contains Base64 formatted string with data length within expected range.
    /// - Parameters:
    ///   - base64String: String to validate.
    ///   - min: If not `nil`, then data length must be at least this value.
    ///   - max: If not `nil`, then data length must not exceed this value.
    /// - Returns: `true` if everything appears OK.
    static func validate(base64String: String, min: Int?, max: Int?) -> Bool {
        guard let data = Data(base64Encoded: base64String) else {
            return false
        }
        if let min = min, data.count < min {
            return false
        }
        if let max = max, data.count > max {
            return false
        }
        return true
    }
}
