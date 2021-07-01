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


final class HttpClientConfigurationTests: XCTestCase {
    
    class Interceptor1: HttpRequestInterceptor {
        func process(request: inout URLRequest) {
        }
    }
    
    class Interceptor2: HttpRequestInterceptor {
        func process(request: inout URLRequest) {
        }
    }
    
    class PinningProvider: TlsPinningProvider {
        func validate(challenge: URLAuthenticationChallenge) -> Bool {
            return true
        }
    }

    func testConfigurationBuilder() throws {
        // Default config
        let def = HttpClientConfiguration.default
        var config = try HttpClientConfiguration.Builder().build()
        XCTAssertEqual(def.requestTimeout, config.requestTimeout)
        XCTAssertEqual(0, config.requestInterceptors.count)
        guard case TlsValidationStrategy.default = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        // Custom interceptors
        config = try HttpClientConfiguration.Builder()
            .set(requestTimeout: 10)
            .set(tlsValidationStrategy: .noValidation)
            .add(requestInterceptor: Interceptor1())
            .add(requestInterceptor: Interceptor2())
            .build()
        XCTAssertEqual(10, config.requestTimeout)
        XCTAssertEqual(2, config.requestInterceptors.count)
        XCTAssertTrue(config.requestInterceptors[0] is Interceptor1)
        XCTAssertTrue(config.requestInterceptors[1] is Interceptor2)
        guard case TlsValidationStrategy.noValidation = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        
        // Pinning
        config = try HttpClientConfiguration.Builder()
            .set(tlsValidationStrategy: .pinning(provider: PinningProvider()))
            .build()
        guard case let TlsValidationStrategy.pinning(pinningProvider) = config.tlsValidationStrategy else {
            XCTFail()
            return
        }
        XCTAssertTrue(pinningProvider is PinningProvider)
    }
    
    func testConfigurationBuilderFailures() throws {
        try [
            HttpClientConfiguration.Builder()
                .set(requestTimeout: 0)
        ].forEach { builder in
            do {
                _ = try builder.build()
                XCTFail()
            } catch PowerAuthError.invalidConfiguration(let reason) {
                XCTAssertEqual(.invalidHttpClientConfiguration, reason)
            }
        }
    }
}
