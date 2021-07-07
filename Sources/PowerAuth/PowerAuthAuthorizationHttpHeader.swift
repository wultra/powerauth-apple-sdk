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

/// Structure representing authorization HTTP header with the PowerAuth-Authorization
/// or PowerAuth-Token signature.
public struct PowerAuthAuthorizationHttpHeader {
    
    /// Property representing PowerAuth HTTP Authorization Header. The current implementation
    /// contains value "X-PowerAuth-Authorization" for standard authorization and "X-PowerAuth-Token"
    /// for token-based authorization.
    let name: String
    
    /// Computed value of the PowerAuth HTTP Authorization Header, to be used in HTTP requests "as is".
    let value: String
}

extension PowerAuthAuthorizationHttpHeader {
    
    /// Create a new header structure created for standard authorization header.
    /// - Parameter value: Calculated header's value.
    /// - Returns: `PowerAuthAuthorizationHttpHeader` for standard PowerAuth authorization.
    static func authorizationHeader(with value: String) -> PowerAuthAuthorizationHttpHeader {
        PowerAuthAuthorizationHttpHeader(name: Constants.Http.authorizationHeaderName, value: value)
    }
    
    /// Create a new header structure for toke based authorization header.
    /// - Parameter value: Calculated header's value.
    /// - Returns: `PowerAuthAuthorizationHttpHeader` for token based authorization.
    static func tokenHeader(with value: String) -> PowerAuthAuthorizationHttpHeader {
        PowerAuthAuthorizationHttpHeader(name: Constants.Http.tokenHeaderName, value: value)
    }
}
