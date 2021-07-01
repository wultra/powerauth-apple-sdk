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

final class PrivateConfigurationTests: XCTestCase {

    func testDefaultValues() throws {
        let keychainConf = KeychainConfiguration.default
        XCTAssertEqual(Constants.KeychainNames.biometry, keychainConf.biometryKeychainName)
        XCTAssertEqual(Constants.KeychainNames.status, keychainConf.statusKeychainName)
        XCTAssertEqual(Constants.KeychainNames.possession, keychainConf.possessionKeychainName)
        XCTAssertEqual(Constants.KeychainNames.tokenStore, keychainConf.tokenStoreKeychainName)
        XCTAssertEqual(Constants.KeychainNames.possessionKeyName, keychainConf.possessionKeyName)
        
        let biometryConf = BiometryConfiguration.default
        XCTAssertEqual(false, biometryConf.linkBiometricItemsToCurrentSet)
        XCTAssertEqual(false, biometryConf.allowBiometricAuthenticationFallbackToDevicePasscode)
        
        let clientConf = HttpClientConfiguration.default
        XCTAssertEqual(Constants.Http.defaultConnectionTimeout, clientConf.requestTimeout)
        XCTAssertEqual(0, clientConf.requestInterceptors.count)
        guard case TlsValidationStrategy.default = clientConf.tlsValidationStrategy else {
            XCTFail()
            return
        }
    }    
}
