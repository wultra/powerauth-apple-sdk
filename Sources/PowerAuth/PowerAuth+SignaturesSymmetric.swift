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

public extension PowerAuth {
    
    /// Compute the HTTP signature header for GET HTTP method, URI identifier and HTTP query parameters using provided authentication information.
    ///
    /// This method may block calling thread if `Authentication` contains biometric authentication. Make sure to dispatch it asynchronously.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` object configured for data signing.
    ///   - uriId: URI identifier.
    ///   - parameters: HTTP query params.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///   - `PowerAuthError.invalidAuthenticationData` - if authentication structure is not configured for data signing.
    ///   - `PowerAuthError.invalidParameter` in case dictionary somehow contains non-string key or value (if created in old Objective-C code).
    /// - Returns: `AuthorizationHttpHeader` structure with proper heaeder name and value.
    func calculateHttpGetRequestSignature(with authentication: Authentication, uriId: String, parameters: [String:String]) throws -> AuthorizationHttpHeader {
        guard let normalizedParameters = try? session.prepareKeyValueDictionary(forDataSigning: parameters) else {
            D.error("Get parameters dictionary contains non-String key or value.")
            throw PowerAuthError.invalidParameter
        }
        return try calculateHttpRequestSignature(with: authentication, method: "GET", uriId: uriId, body: normalizedParameters)
    }
    
    /// Compute the HTTP signature header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
    ///
    /// This method may block calling thread if `Authentication` contains biometric authentication. Make sure to dispatch it asynchronously.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` object configured for data signing.
    ///   - method: HTTP method used for the signature computation.
    ///   - uriId: URI identifier.
    ///   - body: HTTP request body.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///   - `PowerAuthError.invalidAuthenticationData` - if authentication structure is not configured for data signing.
    /// - Returns: `AuthorizationHttpHeader` computed for given data.
    func calculateHttpRequestSignature(with authentication: Authentication, method: String, uriId: String, body: Data?) throws -> AuthorizationHttpHeader {
        let requestData = HTTPRequestData(method: method, uri: uriId)
        requestData.body = body
        let signature = try calculatePowerAuthSignature(with: authentication, for: requestData)
        return .authorizationHeader(with: signature.authHeaderValue)
    }
    
    /// Compute the offline signature for given HTTP method, URI identifier and HTTP request body using provided authentication information.
    ///
    /// This method may block calling thread if `Authentication` contains biometric authentication. Make sure to dispatch it asynchronously.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` object configured for data signing.
    ///   - uriId: URI identifier.
    ///   - body: Data to sign
    ///   - nonce: Nonce in Base64 format.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///   - `PowerAuthError.invalidAuthenticationData` - if authentication structure is not configured for data signing.
    ///   - `PowerAuthError.invalidParameter` in case that nonce is not Base64 encoded string.
    /// - Returns: String representing a calculated signature for all involved factors.
    func calculateOfflineSignature(with authentication: Authentication, uriId: String, body: Data?, nonce: String) throws -> String {
        guard Data(base64Encoded: nonce) != nil else {
            throw PowerAuthError.invalidParameter
        }
        let requestData = HTTPRequestData(method: "POST", uri: uriId)
        requestData.body = body
        requestData.offlineNonce = nonce
        return try calculatePowerAuthSignature(with: authentication, for: requestData).signature
    }
    
    /// Compute PowerAuth signature for given parameters.
    ///
    /// This internal method properly handles all possible errors that may happen during the signature calculation and returns
    /// `PowerAuthCore` object with computed signature. Also be aware that method may block calling thread if `Authentication`
    ///  contains biometric authentication.
    ///
    /// - Parameters:
    ///   - authentication: `Authentication` object configured for data signing.
    ///   - requestData: `PowerAuthCore.HTTPRequestData` object with data to sign.
    /// - Throws:
    ///   - `PowerAuthError.invalidActivationState` in case that instance has no activation.
    ///   - `PowerAuthError.invalidAuthenticationData` - if authentication structure is not configured for data signing.
    /// - Returns: `PowerAuthCore.HTTPRequestDataSignature` with calculated signature.
    internal func calculatePowerAuthSignature(with authentication: Authentication, for requestData: PowerAuthCore.HTTPRequestData) throws -> PowerAuthCore.HTTPRequestDataSignature {
        try authentication.validate(factorsForCommit: false)
        let keys = try authentication.getSignatureFactorKeys(with: dataProvider)
        do {
            return try session.signHttpRequest(request: requestData, keys: keys)
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
}
