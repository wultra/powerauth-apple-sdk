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

/// `PowerAuthError` is the error type returned by PowerAuth SDK.
public enum PowerAuthError: Error {
    
    // Configuration & State
    
    /// The underlying reason the `.invalidConfiguration` error occured.
    public enum ConfigurationFailureReason {
        /// `Configuration` contains missing or invalid data.
        case invalidConfiguration
        
        /// `KeychainConfiguration` contains missing or invalid data.
        case invalidKeychainConfiguration
        
        /// `HttpClientConfiguration` contains missing or invalid data.
        case invalidHttpClientConfiguration
    }
    
    /// The provided configuration is not valid. You can check the debug log for more details.
    case invalidConfiguration(reason: ConfigurationFailureReason)
    
    /// The provided parameter to function is not valid. Please check the debug log for more details.
    case invalidParameter
    
    /// The operation was requested in wrong `PowerAuth` activation state.
    case invalidActivationState
    
    /// The operation require a valid `PowerAuth` activation.
    case missingActivation
    
    // Activation
    
    /// The underlying reason the `.invalidActivationData` error occured.
    public enum ActivationDataFailureReason {
        /// You have provided wrong activation code.
        case wrongActivationCode
        /// The signature scanned from QR code with activation code doesn't match.
        case wrongActivationSignature
        /// You have provided invalid recovery code.
        case wrongRecoveryCode
        /// You have provided invalid recovery PUK.
        case wrongRecoveryPuk
        /// Additional activation OTP can be used only in activation with activation code.
        case otpInWrongActivationType
        /// Provided additional activation OTP contains an empty string.
        case emptyOtp
    }
    
    /// Data provided to `Activation` structure are invalid.
    case invalidActivationData(reason: ActivationDataFailureReason)
    
    // Biometry
    
    /// The underlying reason the `.biometricAuthenticationFailed`
    public enum BiometricFailureReason {
        /// The biometric authentication is not supported on the device.
        case notSupported
        /// The biometric authentication is not available on the device.
        case notAvailable
        /// There's no enrolled biometry on the device.
        case notEnrolled
        /// The biometric factor is not configured in `PowerAuth` instance.
        case notConfigured
    }
    
    /// User did cancel the biometric authentication dialog.
    case biometricAuthenticationCancel
    
    /// Authentication with biometry failed. Check the reason for more details.
    case biometricAuthenticationFailed(reason: BiometricFailureReason)
    
    /// The requested token doesn't exist.
    case tokenNotFound
    
    
    // Protocol upgrade
    
    /// The requested operation failed due to pending protocol upgrade.
    /// You can retry the operation later.
    case pendingProtocolUpgrade
    
    /// The protocol upgrade failure. The recommended action is to retry the status fetch
    /// operation, or remove the activation locally.
    case protocolUpgrade(reason: Error?)
    
    /// WatchConnectivity feature failure. Check the underlying error or debug log for more details.
    case watchConnectivity(reason: Error?)
    
    
    // Other errors
    
    /// The requested operation was canceled by PowerAuth SDK. This kind of error may occur in situations, when SDK
    /// needs to cancel an asynchronous operation, but the cancel is not initiated by the application
    /// itself. For example, if you reset the state of `PowerAuth` during the pending
    /// fetch for activation status, then the application gets this error in result.
    case operationCanceled
    
    /// The operation failed with an unexpected error.
    case unexpectedFailure(reason: Error?)
    
    /// An internal error or internal data inconsistency in PowerAuth SDK.
    case internalError(reason: String, underlyingError: Error? = nil)
}

public extension PowerAuthError {

    /// Returns an underlying error that caused this failure or `nil` if this is the origin of failure.
    var underlyingError: Error? {
        switch self {
            case let .unexpectedFailure(error):
                return error
            case let .protocolUpgrade(error):
                return error
            case let .watchConnectivity(error):
                return error
            case let .internalError(_, underlyingError):
                return underlyingError
            default:
                return nil
        }
    }
    
    /// Wrap any error to `PowerAuthError`. If given error is already `PowerAuthError` instance then returns this instance,
    /// otherwise `.unexpectedError` is returned.
    /// - Parameter error: Error object to wrap into `PowerAuthError`
    /// - Returns: The same instance if `error` is already instance of `PowerAuthError`, or `.unexpectedError`
    internal static func wrap(_ error: Error) -> PowerAuthError {
        error.asPowerAuthError(or: .unexpectedFailure(reason: error))
    }
}


public extension Error {
    /// Returns the instance cast as a `PowerAuthError`
    var asPowerAuthError: PowerAuthError? {
        self as? PowerAuthError
    }

    /// Returns the instance cast as a `PowerAuthError`. If casting fails, a `fatalError` with the specified `message` is thrown.
    func asPowerAuthError(orFailWith message: @autoclosure () -> String, file: StaticString = #file, line: UInt = #line) -> PowerAuthError {
        guard let paError = self.asPowerAuthError else {
            D.fatalError(message(), file: file, line: line)
        }
        return paError
    }
    
    /// Cast the instance as `PowerAuthError` or returns `defaultPowerAuthError`
    func asPowerAuthError(or defaultPowerAuthError: @autoclosure () -> PowerAuthError) -> PowerAuthError {
        asPowerAuthError ?? defaultPowerAuthError()
    }
}
