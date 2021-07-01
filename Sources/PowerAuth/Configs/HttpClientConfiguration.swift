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

/// The `TlsPinningProvider` protocol defines interface for custom TLS pinning validation.
public protocol TlsPinningProvider {
    /// The method is called when an underlying `URLSession` first establishes a connection to a remote
    /// server that uses TLS, to allow your app to verify the server’s certificate chain. The challenge
    /// parameter is already tested for `URLAuthenticationMethodServerTrust`.
    ///
    /// - Parameter challenge: Challenge to validate.
    /// - Returns: `true` if connection to remote server is trusted.
    func validate(challenge: URLAuthenticationChallenge) -> Bool
}

/// Defines how TLS connections are validated.
public enum TlsValidationStrategy {
    /// Use the default `URLSession` behavior.
    case `default`
    /// Accept all incoming connections, so you can connect to testing servers with self-signed, or invalid
    /// certificates.
    case noValidation
    /// Validate server certificate with a custom TLS pinning provider.
    case pinning(provider: TlsPinningProvider)
}


/// The `PowerAuthHttpRequestInterceptor` protocol defines interface for modifying HTTP requests
/// before their execution.
///
/// **WARNING**
///
/// This protocol allows you to tweak the requests created by the `PowerAuth` instance, but
/// also gives you an opportunity to break the things. So, rather than create your own interceptor,
/// try to contact us and describe what's your problem with the networking in the PowerAuth SDK.
///
/// Also note, that this interface may change in the future. We can guarantee the API stability of
/// public classes implementing this interface, but not the stability of interface itself.
public protocol HttpRequestInterceptor {
    /// Method is called by the internal HTTP client, before the request is executed.
    /// The implementation must count with that method is called from other than UI thread.
    ///
    /// - Parameter request: URL request to be modified.
    func process(request: inout URLRequest)
}


/// Structure that is used to provide RESTful API client configuration.
public struct HttpClientConfiguration {
    
    /// Specifies the HTTP client request timeout. The default value is 20.0 (seconds).
    public let requestTimeout: TimeInterval
    
    /// Specifies the TSL validation strategy applied by the client. The default `URLSession`
    /// validation is performed if not altered.
    public let tlsValidationStrategy: TlsValidationStrategy
    
    /// List of request interceptors used by the client before the request is executed.
    public let requestInterceptors: [HttpRequestInterceptor]
    
    /// Default `HttpClientConfiguration`
    public static let `default` = HttpClientConfiguration(
        requestTimeout: Constants.Http.defaultConnectionTimeout,
        tlsValidationStrategy: .default,
        requestInterceptors: []
    )
}

public extension HttpClientConfiguration {
    
    /// Class that builds `HttpClientConfiguration`.
    final class Builder {
        
        var requestTimeout: TimeInterval = Constants.Http.defaultConnectionTimeout
        var tlsValidationStrategy: TlsValidationStrategy = .default
        var requestInterceptors =  [HttpRequestInterceptor]()
        
        /// Construct builder with default parameters.
        public init() {
        }
        
        /// Builds `HttpClientConfiguration` from collected paramters.
        /// - Throws: `PowerAuthError.invalidConfiguration` in case of failure.
        /// - Returns: `HttpClientConfiguration` structure.
        public func build() throws -> HttpClientConfiguration {
            guard requestTimeout >= 1.0 else {
                D.error("HttpClientConfiguration contains too short request timeout.")
                throw PowerAuthError.invalidConfiguration(reason: .invalidHttpClientConfiguration)
            }
            return HttpClientConfiguration(
                requestTimeout: requestTimeout,
                tlsValidationStrategy: tlsValidationStrategy,
                requestInterceptors: requestInterceptors)
        }
        
        /// Change the request timeout
        /// - Parameter requestTimeout: New request timeout.
        /// - Returns: `Builder` instance.
        public func set(requestTimeout: TimeInterval) -> Builder {
            self.requestTimeout = requestTimeout
            return self
        }
        
        /// Change TLS validation strategy.
        /// - Parameter tlsValidationStrategy: New TLS validation strategy.
        /// - Returns: `Builder` instance.
        public func set(tlsValidationStrategy: TlsValidationStrategy) -> Builder {
            self.tlsValidationStrategy = tlsValidationStrategy
            return self
        }
        
        /// Add request interceptor. The order of exeuction later follows order of how multiple interceptors
        /// were added to this `Builder`.
        /// 
        /// - Parameter requestInterceptor: New request interceptor.
        /// - Returns: `Builder` instance.
        public func add(requestInterceptor: HttpRequestInterceptor) -> Builder {
            self.requestInterceptors.append(requestInterceptor)
            return self
        }
    }
}
