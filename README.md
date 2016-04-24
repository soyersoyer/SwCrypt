SwCrypt
=========

### Create public and private keys in DER format
```
let (privateKey, publicKey) = try! CC.RSA.generateKeyPair(2048)
```
### Convert them to PEM format
```
let privateKeyPEM = try SwKeyConvert.PrivateKey.derToPKCS1PEM(privateKey)
let publicKeyPEM = SwKeyConvert.PublicKey.derToPKCS8PEM(publicKey)
```
### Or read them from strings with PEM data
```
let privateKeyDER = SwKeyConvert.PrivateKey.pemToPKCS1DER(privateKeyPEM)
let publicKeyDER = SwKeyConvert.PublicKey.pemToPKCS1DER(publicKeyPEM)
```
### Or encrypt, decrypt the private key (OpenSSL compatible)
```
try SwKeyConvert.PrivateKey.encryptPEM(privateKeyPEM, passphrase: "longpassword", mode: .AES256CBC)
try SwKeyConvert.PrivateKey.decryptPEM(privEncrypted, passphrase: "longpassword")
```
### Encrypt, decrypt data with RSA
```
try CC.RSA.encrypt(data, derKey: publicKey, tag: tag, padding: .OAEP, digest: .SHA1)
try CC.RSA.decrypt(data, derKey: privateKey, tag: tag, padding: .OAEP, digest: .SHA1)
```
### Elliptic curve functions
```
let keys = try? CC.EC.generateKeyPair(384)
let signed = try? CC.EC.signHash(keys!.0, hash: hash)
let verified = try? CC.EC.verifyHash(keys!.1, hash: hash, signedData: signed!)
let shared = try? CC.EC.computeSharedSecret(keys!.0, publicKey: keys!.1)
```
### Encrypt, decrypt data with symmetric ciphers
```
try CC.crypt(.encrypt, blockMode: .CBC, algorithm: .AES, padding: .PKCS7Padding, data: data, key: aesKey, iv: iv)
try CC.crypt(.decrypt, blockMode: .CFB, algorithm: .AES, padding: .PKCS7Padding, data: data, key: aesKey, iv: iv)
```
### Encrypt, decrypt data with symmetric authenticating ciphers
```
try CC.cryptAuth(.encrypt, blockMode: .GCM, algorithm: .AES, data: data, aData: aData, key: aesKey, iv: iv, tagLength: tagLength)
try CC.cryptAuth(.decrypt, blockMode: .CCM, algorithm: .AES, data: data, aData: aData, key: aesKey, iv: iv, tagLength: tagLength)
```
### Digest functions
```
CC.digest(data, alg: .MD5)
CC.digest(data, alg: .SHA256)
CC.digest(data, alg: .SHA512)
```
### HMAC function
```
CC.HMAC(data, alg: .SHA512, key: key)
```
### KeyDerivation
```
CC.KeyDerivation.PBKDF2(password, salt: salt, prf: .SHA256, rounds: 4096)
```
### Symmetric Key Wrapping
```
try CC.KeyWrap.SymmetricKeyWrap(CC.KeyWrap.rfc3394_iv, kek: kek, rawKey: rawKey)
try CC.KeyWrap.SymmetricKeyUnwrap(CC.KeyWrap.rfc3394_iv, kek: kek, wrappedKey: wrappedKey)
```
### Upsert, get, delete keys from KeyStore
```
try SwKeyStore.upsertKey(privateKeyPEM, keyTag: "priv", options: [kSecAttrAccessible:kSecAttrAccessibleWhenUnlockedThisDeviceOnly])
try SwKeyStore.getKey("priv")
try SwKeyStore.delKey("priv")
```

### Encrypt/decrypt message in SEM (Simple Encrypted Message) format
(works with OpenSSL PEM formatted keys too)
```
//public enum AESMode : UInt8 {case AES128, AES192, AES256}
//public enum BlockMode : UInt8 {case CBC_SHA256, GCM}

let mode = SEM.Mode(aes:.AES256, block:.CBC_SHA256)
try SEM.encryptMessage(testMessage, pemKey: publicKey, mode: mode)
try SEM.decryptMessage(encMessage, pemKey: privateKey)
try SEM.encryptData(testData, pemKey: publicKey, mode: mode)
try SEM.decryptData(encData, pemKey: privateKey)
```

### Sign, verify messages with SMSV (Simple Message Sign and Verify)
```
let sign = try? SMSV.sign(testMessage, pemKey: priv)
let verified = try? SMSV.verify(testMessage, pemKey: pub, sign: sign!)
```

-----

SEM (Simple Encrypted Message) format
-------------------------------------

When encrypting using a public key:

- Convert message to NSData using UTF8 encoding
- Create message header :
  - Version indicator 1 byte (current: 0)
  - AES mode 1 byte
  - Cipher mode 1 byte
  - AES key (depends on aes mode - 16, 24, 32 byte)
  - IV (depends on cipher mode - 16, 12 byte)
- Encrypt message header with the public key with OAEP padding (size = RSA key size)
- Encrypt message with the chosen aes and cipher mode (calculate message auth tag with aData: encrypted header, and append to the encrypted message)
- Append encrypted header and messsage
- Base64 encode

When decrypting using a private key:

- Base64 decode
- Decrypt the first block (RSA key size)
- Read the message header (Version, AES mode, Cipher mode), AES key, IV
- Decrypt message (check message auth with aData: encrypted header)
- Convert NSData to string with UTF8 decoding

Simple Message Sign and Verify
------------------------------

Sign:

- Convert message to NSData using UTF8 encoding
- Calculate the NSData's SHA512 digest
- Sign with the private key using OAEP padding with SHA512 digest
- Base64 encode the sign

Verify:

- Base64 decode the sign
- Convert message to NSData using UTF8 encoding
- Calculate the NSData's SHA512 digest
- Verify with the public key using OAEP padding with SHA512 digest

-----

Check availability
---------------------

SwCrypt uses dlopen and dlsym to load the CommonCrypto's functions, because not all of them are available in public header files. You have to check the availability before using them.

```
let digestAvailable : Bool = CC.digestAvailable()
let ramdomAvailable : Bool = CC.randomAvailable(()
let hmacAvailable : Bool = CC.hmacAvailable()
let cryptorAvailable : Bool = CC.cryptorAvailable
let keyDerivationAvailable : Bool = CC.KeyDerivation.available()
let keyWrapAvailable : Bool = CC.KeyWrap.available()
let rsaAvailable : Bool = CC.RSA.available()
let ecAvailable : Bool = CC.EC.available()
let gcmAvailable : Bool = CC.GCM.available()
let ccmAvailable : Bool = CC.CCM.available()

or all in one turn:
let ccAvailable : Bool = CC.available()
```

Install
-------
Just copy `SwCrypt.swift` to your project.

Inspired from
-------------

 - <http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/>
 - <https://github.com/lancy/RSADemo>
 - <https://github.com/TakeScoop/SwiftyRSA>
 - <https://github.com/henrinormak/Heimdall>
 - <https://github.com/btnguyen2k/swift-rsautils>

License
-------

This project is copyrighted under the MIT license.
