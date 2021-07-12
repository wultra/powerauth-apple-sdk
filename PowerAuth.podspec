Pod::Spec.new do |s|
    # General information
    s.name              = 'PowerAuth'
    s.version           = '0.0.1'
    s.summary           = 'PowerAuth client SDK written in Swift'
    s.homepage          = 'https://github.com/wultra/powerauth-apple-sdk'
    s.social_media_url  = 'https://twitter.com/wultra'
    s.documentation_url = 'https://github.com/wultra/powerauth-apple-sdk/blob/develop/docs/Readme.md'
    s.author            = { 
        'Wultra s.r.o.' => 'support@wultra.com'
    }
    s.license = { 
        :type => 'Apache License, Version 2.0', 
        :file => 'LICENSE' 
    }    
    # Repository
    s.source = { 
        :git => 'https://github.com/wultra/powerauth-apple-sdk.git',
        :tag => "#{s.version}"
    }
    
    # Deployment targets
    s.swift_version = '5.3'
    s.ios.deployment_target  = '9.0'
    s.tvos.deployment_target = '9.0'
    s.osx.deployment_target = '10.15'
    
    # Sources
    s.source_files          = 'Sources/PowerAuth/**/*.swift'
    
    # Dependencies
    s.dependency 'PowerAuthShared', '~> 0.0.2'
    
    # Tests
    #s.test_spec do |ts|
    #  ts.source_files = 'Tests/PowerAuth/**/*.swift'
    #end
end
