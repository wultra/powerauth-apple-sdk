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

/// Defines type of public key for asymmetric signature validation.
public enum PublicKeyType {
    
    /// Data is signed with `KEY_SERVER_MASTER_PUBLIC` as defined in PowerAuth protocol specification.
    case masterServerKey
    
    /// Data is signed with personalized `KEY_SERVER_PUBLIC` as defined in PowerAuth protocol specification.
    /// Such key is available only when `PowerAuth` instance has valid activation.
    case personalizedKey
}

public extension PowerAuth {
    
    /// Verify whether activation code scanned from QR code has a valid signature.
    ///
    /// - Parameter activationCode: `ActivationCode` structure that must contain activation signature.
    /// - Throws:
    ///   - `PowerAuthError.invalidParameter` in case that `ActivationCode` has no signature part.
    /// - Returns: `true` in case that
    func verifyActivationCodeSignature(activationCode: ActivationCode) throws -> Bool {
        guard activationCode.hasActivationSignature else {
            D.error("Activation code must contain signature part.")
            throw PowerAuthError.invalidParameter
        }
        guard let data = activationCode.activationCode.data(using: .ascii) else {
            throw PowerAuthError.internalError(reason: "Activation code should be in ASCII encoding")
        }
        guard let signature = Data(base64Encoded: activationCode.activationSignature!) else {
            throw PowerAuthError.internalError(reason: "Activation signature should be BASE64 encoded")
        }
        return try verifyServerSignedData(data: data, signature: signature, publicKeyType: .masterServerKey)
    }
    
    /// Validates whether the data has been signed with master server private key or personalized server's private key.
    ///
    /// - Parameters:
    ///   - data: Signed data
    ///   - signature: Signature calculated for data.
    ///   - publicKeyType: Which public key must be used for signature verification.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` - if instance has no activation and requested key type is `.serverPublicKey`
    /// - Returns: `true` if signature is valid, otherwise `false`
    func verifyServerSignedData(data: Data, signature: Data, publicKeyType: PublicKeyType) throws -> Bool {
        if publicKeyType == .personalizedKey {
            guard hasValidActivation else {
                throw PowerAuthError.invalidActivationState(reason: .missingActivation)
            }
        }
        do {
            let signedData = SignedData()
            signedData.data = data
            signedData.signature = signature
            signedData.signingDataKey = publicKeyType.powerAuthCoreSigningDataKey
            try session.verifyServerSignedData(signedData: signedData)
            return true
        } catch let error as NSError {
            if error.powerAuthCoreErrorCode == .wrongSignature {
                return false
            }
            throw PowerAuthError.wrap(error)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
    
    /// Sign given data with the original device private key.
    ///
    /// This method calls PowerAuth Standard RESTful API endpoint `/pa/vault/unlock` to obtain the vault encryption key used
    /// for private key decryption. Data is then signed using ECDSA algorithm with this key and can be validated on the server side.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` with knowledge and possession factors configured for data signing.
    ///   - data: Data to be signed with the private key.
    ///   - callbackQueue: `DispatchQueue` to execute callback with operation result. The default queue is `.main`.
    ///   - callback: Callback that receive result from data signing operation.
    ///   - result: Result with `Data` containing calculated signature in case of success. The following errors can occur in case of failure:
    ///     - `PowerAuthError.invalidActivationState` - if instance has no activation.
    /// - Returns: `OperationTask` associated with the running request.
    func signDataWithDevicePrivateKey(with authentication: Authentication, data: Data, callbackQueue: DispatchQueue = .main, callback: (_ result: Result<Data, PowerAuthError>) -> Void) -> OperationTask {
        D.notImplementedYet()
    }
}


extension PublicKeyType {
    
    /// Translates `PublicKeyType` into `PowerAuthCore.SigningDataKey` enumeration.
    var powerAuthCoreSigningDataKey: PowerAuthCore.SigningDataKey {
        switch self {
            case .masterServerKey:
                return .ecdsa_MasterServerKey
            case .personalizedKey:
                return .ecdsa_PersonalizedKey
        }
    }
}
