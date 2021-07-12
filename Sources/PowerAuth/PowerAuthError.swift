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
        /// `PowerAuthConfiguration` contains missing or invalid data.
        case invalidInstanceConfiguration
        
        /// `KeychainConfiguration` contains missing or invalid data.
        case invalidKeychainConfiguration
        
        /// `HttpClientConfiguration` contains missing or invalid data.
        case invalidHttpClientConfiguration
    }
    
    /// The provided configuration is not valid. You can check the debug log for more details.
    case invalidConfiguration(reason: ConfigurationFailureReason)
    
    /// The provided parameter to function is not valid. Please check the debug log for more details.
    case invalidParameter
    
    
    /// The underlying reason the `.invalidActivationState` error occured.
    public enum ActivationStateFailureReason {
        
        /// `PowerAuth` instance has already a valid activation.
        case activationIsPresent
        
        /// `PowerAuth` instance has already pending an activation process.
        case pendingActivation
        
        /// `PowerAuth` instance has no activation.
        case missingActivation
        
        /// TODO: Temporary reason for errors reported from PowerAuthCore.
        ///       We should enhance error codes from core to better match wrong states.
        case other
        
        /// `PowerAuth` instance already has a biometry factor key configured.
        case biometryFactorAlreadySet
    }
    
    /// The operation was requested in wrong `PowerAuth` activation state.
    case invalidActivationState(reason: ActivationStateFailureReason)
    
    
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
        /// Provided additional activation OTP contains an empty string.
        case emptyOtp
        /// Identity attributes provided for a custom attributes is empty.
        case emptyIdentityAttributes
    }
    
    /// Data provided to `Activation` structure are invalid.
    case invalidActivationData(reason: ActivationDataFailureReason)
    
    
    // Authentication
    
    /// The underlying reason the `.invalidAuthenticationData` error occured.
    public enum AuthenticationDataFailureReason {
        /// `Authentication` structure you have provided is created for data signing instead for activation commit.
        case authenticationForCommitIsRequired
        /// `Authentication` structure you have provided is created for activation signing instead for data signing.
        case authenticationForSigningIsRequired
        /// `Authentication` doesn't contain `LAContext` object or custom biometric key.
        case localAuthenticationContextIsMissing
        /// `Authentication` structure contains too short password.
        case passwordIsTooShort
        /// `Authentication` structure contains
        case requiredFactorIsMissing
    }
    
    /// Data provided to `Authentication` structure are invalid
    case invalidAuthenticationData(reason: AuthenticationDataFailureReason)
    
    
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
