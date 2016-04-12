SwCrypt
=========

### Create public and private keys in PEM format
```
let (privateKey, publicKey) = try! SwKeyStore.generateRSAKeyPair(2048)
```
### Upsert, get, delete keys from KeyStore
```
try SwKeyStore.upsertKey(privateKey, keyTag: "priv")
try SwKeyStore.getKey("priv")
try SwKeyStore.delKey("priv")
```
### Encrypt/decrypt private key (OpenSSL compatible)
```
public enum Mode {case AES128CBC, AES256CBC}

try SwEncryptedPrivateKey.encryptPEM(priv, passphrase: "longpassword", mode: .AES256CBC)
try SwEncryptedPrivateKey.decryptPEM(privEncrypted, passphrase: "longpassword")
```

### Encrypt/Decrypt message in SEM (Simple Encrypted Message) format
(works with OpenSSL PEM formatted keys too)
```
public enum AesMode : UInt8 {case AES128, AES192, AES256}
public enum BlockMode : UInt8 {case CBC, GCM}
public enum HMACMode : UInt8 {case None, SHA256, SHA512}

let mode = SEM.Mode(aes:.AES256, block:.CBC, hmac:.SHA512)
try SEM.encryptMessage(testMessage, pemKey: publicKey, mode: mode)
try SEM.decryptMessage(encMessage, pemKey: privateKey)
try SEM.encryptData(testData, pemKey: publicKey, mode: mode)
try SEM.decryptData(encData, pemKey: privateKey)
```

-----

SEM (Simple Encrypted Message) format
-------------------------------------

When encrypting using a public key:

- Convert clear text to NSData using UTF8
- Create message header :
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

- Convert encrypted text to NSData from base64 string
- Decrypt the first block (RSA key size)
- Read the message header (AES mode, Cipher mode, HMAC mode), AES key, IV
- Check the HMAC
- Decrypt message
- Convert NSData to UTF8 strint


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
