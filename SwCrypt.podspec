Pod::Spec.new do |spec|
  spec.name = "SwCrypt"
  spec.version = "5.1.4"
  spec.summary = "RSA public/private key generation, RSA, AES encryption/decryption, RSA sign/verify in Swift with CommonCrypto in iOS and OS X"
  spec.homepage = "https://github.com/soyersoyer/SwCrypt"
  spec.license = { :type => 'MIT' }
  spec.authors = { "soyersoyer" => 'soyer@irl.hu' }
  spec.swift_version = "5.0"
  spec.ios.deployment_target = "8.0"
  spec.osx.deployment_target = "10.12"
  spec.watchos.deployment_target = "3.0"
  spec.tvos.deployment_target = "11.0"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/soyersoyer/SwCrypt.git", :tag => spec.version }
  spec.source_files = "SwCrypt/**/*.{h,swift}"
end
