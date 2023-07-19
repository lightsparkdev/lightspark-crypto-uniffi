Pod::Spec.new do |s|
  s.name             = 'LightsparkCryptoFFI'
  s.version          = '0.1.0'
  s.summary          = 'Lightspark Crypto FFI'
  s.homepage         = 'https://www.lightspark.com/'
  s.license          = { :type => 'Apache License, Version 2.0' }
  s.author           = { 'Lightspark Group, Inc.' => 'info@lightspark.com' }
  s.source           = { :http => 'https://github.com/lightsparkdev/lightspark-crypto-uniffi/releases/download/0.1.0/lightspark-cryptoFFI.xcframework.zip' }
  s.ios.deployment_target = '13.0'
  s.swift_version = '5.5'
  s.vendored_frameworks = 'lightspark-crypto-swift/lightspark_cryptoFFI.xcframework'
end
