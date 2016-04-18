SwCrypt
=========

### Create public and private keys in DER format
```
let (privateKey, publicKey) = try! CC.RSA.generateKeyPair(2048)
```
### Convert them to PEM format
```
let privateKeyPEM = try SWPrivateKey.derToPKCS1PEM(privateKey)
let publicKeyPEM = SwPublicKey.derToPKCS8PEM(publicKey)
```
### Or read them from strings with PEM data
```
let privateKeyDER = SwPrivateKey.pemToPKCS1DER(privateKeyPEM)
let publicKeyDER = SwPulbicKey.pemToPKCS1DER(publicKeyPEM)
```
### Or encrypt, decrypt the private key (OpenSSL compatible)
```
try SwEncryptedPrivateKey.encryptPEM(privateKeyPEM, passphrase: "longpassword", mode: .AES256CBC)
try SwEncryptedPrivateKey.decryptPEM(privEncrypted, passphrase: "longpassword")
```
### Encrypt/decrypt data with RSA or symmetric ciphers
```
try CC.RSA.encrypt(data, derKey: publicKey, padding: .OAEP, digest: .SHA1)
try CC.RSA.decrypt(data, derKey: privateKey, padding: .OAEP, digest: .SHA1)
try CC.crypt(.encrypt, blockMode: .CBC, algorithm: .AES, padding: .PKCS7Padding, data: data, key: aesKey, iv: iv)
try CC.crypt(.decrypt, blockMode: .GCM, algorithm: .AES, padding: .PKCS7Padding, data: data, key: aesKey, iv: iv)
```
### HMAC and HASH functions
```
CC.md5(data)
CC.sha256(data)
CC.sha512(data)
CC.HMAC(data, alg: .SHA512, key: key)
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
//public enum BlockMode : UInt8 {case CBC, GCM}
//public enum HMACMode : UInt8 {case None, SHA256, SHA512}

let mode = SEM.Mode(aes:.AES256, block:.CBC, hmac:.SHA512)
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
  - HMAC mode 1 byte
  - AES key (depends on aes mode - 16, 24, 32 byte)
  - IV (depends on cipher mode - 16, 12 byte)
- Encrypt message header with the public key with OAEP padding (size = RSA key size)
- Encrypt message with the chosen aes and cipher mode
- Append encrypted header and messsage
- Calculate HMAC for them with the chosen algorithm
- Append HMAC to the previously appended data
- Base64 encode

When decrypting using a private key:

- Base64 decode
- Decrypt the first block (RSA key size)
- Read the message header (Version, AES mode, Cipher mode, HMAC mode), AES key, IV
- Check the HMAC
- Decrypt message
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
let rsaAvailable : Bool = CC.RSA.available()
let gcmAvailable : Bool = CC.GCM.available()

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
