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

public final class PowerAuth {
    
    /// Internal structure wrapping all public configuration structures.
    struct PrivateConfiguration {
        let instance: Configuration
        let keychain: KeychainConfiguration
        let biometry: BiometryConfiguration
        let httpClient: HttpClientConfiguration
    }
    
    /// Configurations
    let conf: PrivateConfiguration
    
    /// Data provider instance.
    let dataProvider: DataProvider
    
    /// HTTP client instance.
    let httpClient: HttpClient
    
    /// Initialize `PowerAuth` class instance with all required configuration objects.
    /// The constructor is internal, so you have to use `PowerAuth.Builder` class to
    /// create an instance of `PowerAuth` class.
    /// 
    /// - Parameters:
    ///   - configuration: Structure wrapping all configuration structures.
    ///   - dataProvider: `DataProvider` implementation
    ///   - httpClient: `HttpClient` implementation
    init(
        configuration: PrivateConfiguration,
        dataProvider: DataProvider,
        httpClient: HttpClient) {
        self.conf = configuration
        self.dataProvider = dataProvider
        self.httpClient = httpClient
    }
    
    
    /// Contains `Configuration` structure used to construct this `PowerAuth` instance.
    public var configuration: Configuration {
        conf.instance
    }
    
    /// Contains `KeychainConfiguration` structure used to construct this `PowerAuth` instance.
    public var keychainConfiguration: KeychainConfiguration {
        conf.keychain
    }
    
    /// Contains `BiometryConfiguration` structure used to construct this `PowerAuth` instance.
    public var biometryConfiguration: BiometryConfiguration {
        conf.biometry
    }
    
    /// Contains `HttpClientConfiguration` structure used to construct this `PowerAuth` instance.
    public var httpClientConfiguration: HttpClientConfiguration {
        conf.httpClient
    }
}
