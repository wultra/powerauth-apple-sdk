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

enum Constants {
    
    enum KeySizes {
        /// Expected length of data encoded in `Configuration.applicationKey` paramterer
        static let APP_KEY_SIZE = 16
        /// Expected length of data encoded in `Configuration.applicationSecret` paramterer
        static let APP_SECRET_SIZE = 16
        /// External encryption key's size.
        static let EEK_SIZE = 16
    }
    
    enum KeychainNames {
        /// Name of status keychain service.
        static let status       = "io.getlime.PowerAuthKeychain.StatusKeychain"
        /// Name of possession keychain service.
        static let possession   = "io.getlime.PowerAuthKeychain.PossessionKeychain"
        /// Name of biometry keychain service.
        static let biometry     = "io.getlime.PowerAuthKeychain.BiometryKeychain"
        /// Name of tokenstore keychain service.
        static let tokenStore   = "io.getlime.PowerAuthKeychain.TokenStore"
        
        /// Key to `UserDefaults` containing boolean that Keychain is initialized.
        static let keychainInitializedKey = "io.getlime.PowerAuthKeychain.Initialized"

        /// Key to possession keychain, containing a shared possession factor key.
        static let possessionKeyName = "PA2KeychainKey_Possession"
    }
    
    enum Http {
        /// Defines default connection timeout used by internal HTTP client.
        static let defaultConnectionTimeout: TimeInterval = 20.0
    }
}