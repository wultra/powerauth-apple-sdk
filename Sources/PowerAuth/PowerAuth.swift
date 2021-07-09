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
import PowerAuthShared

public final class PowerAuth {
    
    /// Contains `PowerAuthConfiguration` structure used to construct this `PowerAuth` instance.
    public let configuration: PowerAuthConfiguration
        
    /// Internal `PowerAuthCore.Session` object.
    let session: PowerAuthCore.Session
    
    /// Data provider instance.
    let dataProvider: DataProvider
    
    /// HTTP client instance.
    let httpClient: HttpClient
    
    /// Thread synchronization primitive.
    let lock: Lock = Lock()
    
    /// Contains last fetched activation status.
    /// Use `lastFetchedActivationStatus` to access it internally.
    var lastActivationStatus: ActivationStatus?
    
    /// Initialize `PowerAuth` class instance with all required configuration objects.
    /// The constructor is internal and available only for testing purposes.
    /// 
    /// - Parameters:
    ///   - configuration: `PowerAuthConfiguration` structure
    ///   - dataProvider: `DataProvider` implementation
    ///   - httpClient: `HttpClient` implementation
    /// - Throws:
    ///   - `PowerAuthError.invalidConfiguration` in case that some configuration parameter is invalid.
    ///   - `PowerAuthError` for all othher failures.
    internal init(
        configuration: PowerAuthConfiguration,
        dataProvider: DataProvider,
        httpClient: HttpClient) throws {
        self.session = Session(setup: configuration.powerAuthCoreSessionSetup)
        self.configuration = configuration
        self.dataProvider = dataProvider
        self.httpClient = httpClient
        
        try restoreSessionState()
    }
    
    /// Construct `PowerAuth` class instance with provided `PowerAuthConfiguration` structure.
    /// - Parameter configuration: `PowerAuthConfiguration` structure.
    /// - Throws:
    ///   - `PowerAuthError.invalidConfiguration` in case that some configuration parameter is invalid.
    ///   - `PowerAuthError` for all othher failures.
    public convenience init(configuration: PowerAuthConfiguration) throws {
        try self.init(
            configuration: configuration,
            dataProvider: try DefaultDataProvider(with: configuration),
            httpClient: DefaultHttpClient(with: configuration.httpClient)
        )
    }
    
    /// Restore internal Session's state.
    /// - Throws:
    ///   - `PowerAuthError.invalidConfiguration` in case that some configuration parameter is invalid.
    ///   - `PowerAuthError` for all othher failures.
    func restoreSessionState() throws {
        guard session.hasValidSetup else {
            D.error("PowerAuthCore.Session has invalid setup.")
            throw PowerAuthError.invalidConfiguration(reason: .invalidInstanceConfiguration)
        }
        do {
            if let stateData = try dataProvider.activationState() {
                D.print("Loading initial session state for PowerAuth instance.")
                try session.deserialize(state: stateData)
            } else {
                D.print("There's no initial session state for PowerAuth instance.")
            }
        } catch {
            throw PowerAuthError.wrap(error)
        }
    }
}
