SwCrypt
=========

### Create public and private keys in DER format, convert to PEM, encrypt/decrypt it (OpenSSL compatible)
```
let (privateKey, publicKey) = try! CCRSA.generateKeyPair(2048)
let privateKeyPEM = try SWPrivateKey.derToPKCS1PEM(privateKey)
let publicKeyPEM = SwPublicKey.derToPKCS8PEM(publicKey)

try SwEncryptedPrivateKey.encryptPEM(privateKeyPEM, passphrase: "longpassword", mode: .AES256CBC)
try SwEncryptedPrivateKey.decryptPEM(privEncrypted, passphrase: "longpassword")
```
### Encrypt/decrypt data with RSA or symmetric ciphers
```
try CCRSA.encrypt(data, derKey: publicKey, padding: .OAEP, digest: .SHA1)
try CCRSA.decrypt(data, derKey: privateKey, padding: .OAEP, digest: .SHA1)
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

Install
-------
Just copy `SwCrypt.swift`, `CommonRSACryptor.h`, `CommonGCMCryptor.h` to your project.
SwCrypt uses `CommonCrypto`, so please create a new build phase for the following script, and put it before the compilation.

```bash
modulesDirectory=$DERIVED_FILES_DIR/modules
modulesMap=$modulesDirectory/module.modulemap
modulesMapTemp=$modulesDirectory/module.modulemap.tmp

mkdir -p "$modulesDirectory"

cat > "$modulesMapTemp" << MAP
module CommonCrypto [system] {
    header "$SDKROOT/usr/include/CommonCrypto/CommonCrypto.h"
    header "$SDKROOT/usr/include/CommonCrypto/CommonRandom.h"
    export *
}
module CommonRSACryptor [system] {
    header "$SRCROOT/CommonRSACryptor.h"
    export *
}
module CommonGCMCryptor [system] {
    header "$SRCROOT/CommonGCMCryptor.h"
    export *
}
MAP

diff "$modulesMapTemp" "$modulesMap" >/dev/null 2>/dev/null
if [[ $? != 0 ]] ; then
mv "$modulesMapTemp" "$modulesMap"
else
rm "$modulesMapTemp"
fi
```

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
