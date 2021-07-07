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
import PowerAuthCore

/// The `PowerAuthActivationCode` structure contains parsed components from user-provided activation, or recovery
/// code. You can use methods from `PowerAuthActivationCodeUtil` class to create the structure with valid data.
public struct PowerAuthActivationCode {
    
    /// If object is constructed from an activation code, then the property contains just a code, without a signature part.
    /// If object is constructed from a recovery code, then property contains just a code, without an optional `"R:"` prefix.
    public let activationCode: String
    
    /// Signature calculated from activationCode. The value is typically optional for cases, when the user re-typed activation
    /// code manually.
    ///
    /// If object is constructed from a recovery code, then the activation signature part is always empty.
    public let activationSignature: String?
    
    /// Contains `true` if activation code has signature part.
    public var hasActivationSignature: Bool {
        activationSignature != nil
    }
}

public extension PowerAuthActivationCode {
    
    /// Parses provided activation code (which may not contain an optional signature) and returns `PowerAuthActivationCode`
    /// structure. The method doesn't perform an auto-correction, so the provided code must be valid.
    ///
    /// - Parameter activationCode: Activation code to parse.
    /// - Returns: `PowerAuthActivationCode` structure or `nil` if provided string doesn't contain a valid activation code.
    static func parse(fromActivationCode activationCode: String) -> PowerAuthActivationCode? {
        guard let parsedCode = ActivationCodeUtil.parse(fromActivationCode: activationCode) else {
            return nil
        }
        return PowerAuthActivationCode(activationCode: parsedCode.activationCode, activationSignature: parsedCode.activationSignature)
    }
    
    /// Parses provided recovery code (which may contain an optional `"R:"`prefix) and returns `PowerAuthActivationCode` structure.
    /// The method doesn't perform an auto-correction, so the provided code must be valid.
    /// - Parameter recoveryCode: Recovery code to parse.
    /// - Returns: `PowerAuthActivationCode` structure or `nil` if provided string doesn't contain a valid recovery code.
    static func parse(fromRecoveryCode recoveryCode: String) -> PowerAuthActivationCode? {
        guard let parsedCode = ActivationCodeUtil.parse(fromRecoveryCode: recoveryCode) else {
            return nil
        }
        return PowerAuthActivationCode(activationCode: parsedCode.activationCode, activationSignature: parsedCode.activationSignature)
    }
}

/// The `PowerAuthActivationCodeValidator` class provides various set of methods for validating
/// activation or recovery codes.
///
/// Current format:
/// ------------------
/// ```
/// code without signature: CCCCC-CCCCC-CCCCC-CCCCC
/// code with signature:    CCCCC-CCCCC-CCCCC-CCCCC#BASE64_SIGNATURE
///
/// recovery code:          CCCCC-CCCCC-CCCCC-CCCCC
/// recovery code from QR:  R:CCCCC-CCCCC-CCCCC-CCCCC
///
/// recovery PUK:           DDDDDDDDDD
/// ```
///
/// - Where the `'C'` is Base32 sequence of characters, fully decodable into the sequence of bytes.
///   The validator then compares CRC-16 checksum calculated for the first 10 bytes and compares
///   it to last two bytes (in big endian order).
///
/// - Where the `'D'` is digit (0 - 9)
///
/// As you can see, both activation and recovery codes, shares the same basic principle (like CRC16
/// checksum). That's why `parse()` functions returns the same `PowerAuthActivationCode` structure
/// for both scenarios.
///
/// If you're interested in more details, then please check
/// [our online documentation](https://developers.wultra.com/components/powerauth-crypto/1.0.x/documentation/Activation-Code).
public final class PowerAuthActivationCodeValidator {
    
    /// Validates whether given character is a valid character allowed in the activation or recovery code.
    /// The method strictly checks whether the character is from `[A-Z2-7]` characters range.
    /// - Parameter typedCharacter: Unicode scalar as an user typed character.
    /// - Returns: `true` if provided unicode scalar is a valid character for the activation or recovery code.
    public static func validate(typedCharacter: Unicode.Scalar) -> Bool {
        return ActivationCodeUtil.validateTypedCharacter(typedCharacter.value)
    }
    
    /// Validates whether given character is a valid valid character allowed in the activation or recovery code
    /// and returns the same character, or auto-corrected character if auto-correction is possible.
    ///
    /// You can use this method for validation & auto-correction of user typed characters. The following auto-corrections
    /// are currently performed:
    /// - lowercase characters are corrected to uppercase (e.g. `a` will be corrected to `A`)
    /// - `0` is corrected to `O` (zero to capital 'O')
    /// - `1` is corrected to `I` (number one to capital 'I')
    ///
    /// - Parameter typedCharacter: Unicode scalar as an user typed character.
    /// - Returns: Auto-corrected character or `nil` if provided character is invalid.
    public static func validateAndCorrect(typedCharacter: Unicode.Scalar) -> Unicode.Scalar? {
        let result = ActivationCodeUtil.validateAndCorrectTypedCharacter(typedCharacter.value)
        return result != 0 ? Unicode.Scalar(result) : nil
    }
    
    /// Validates whether the provided string is a valid activation code. The provided code must not
    /// contain a signature part.
    ///
    /// You can use this method to validate a whole user-typed activation code at once.
    /// - Parameter activationCode: Activation code to validate.
    /// - Returns: `true` if provided string is a valid activation code.
    public static func validate(activationCode: String) -> Bool {
        return ActivationCodeUtil.validateActivationCode(activationCode)
    }
    
    /// Validates whether the provided string is a valid recovery code.
    ///
    /// You can use this method to validate a whole user-typed recovery code at once. The input code may contain
    /// `"R:"` prefix, if code is scanned from QR code.
    /// - Parameter recoveryCode: Recovery code to validate.
    /// - Returns: `true` if provided string is a valid recovery code.
    public static func validate(recoveryCode: String) -> Bool {
        return ActivationCodeUtil.validateRecoveryCode(recoveryCode)
    }
    
    /// Validates whether provided string appears to be a valid recovery PUK.
    ///
    /// You can use this method to validate a whole user-typed recovery PUK at once. In current version, only\
    /// 10 digits long string is considered as a valid PUK.
    /// - Parameter recoveryPuk: Recovery PUK to validate.
    /// - Returns: `true` if provided string appears to be a valid recovery PUK.
    public static func validate(recoveryPuk: String) -> Bool {
        return ActivationCodeUtil.validateRecoveryPuk(recoveryPuk)
    }
}

extension PowerAuthActivationCode {
    
    /// Returns activation code in `PowerAuthCore.ActivationCode` representation.
    var coreActivationCode: PowerAuthCore.ActivationCode {
        ActivationCode(activationCode: activationCode, activationSignature: activationSignature)
    }
}
