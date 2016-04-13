import XCTest
import SwCrypt

let keyPair = try? CCRSA.generateKeyPair(2048)

class SwCryptTest: XCTestCase {
	
    override func setUp() {
        super.setUp()
		self.continueAfterFailure = false
    }
    
    override func tearDown() {
        super.tearDown()
    }

    func testCreateKeyPair() {
		XCTAssert(keyPair != nil)
	}
	
	func testUpsert() {
		let (priv, _) = keyPair!
		XCTAssertNotNil(try? SwKeyStore.upsertKey(priv, keyTag: "priv", options: [kSecAttrAccessible:kSecAttrAccessibleWhenUnlockedThisDeviceOnly]))
		XCTAssertNotNil(try? SwKeyStore.upsertKey(priv, keyTag: "priv"))
		XCTAssert(try SwKeyStore.getKey("priv") == priv)
	}
	
	func testDel() throws {
		let tag = "priv"
		let (priv, _) = keyPair!
		XCTAssertNotNil(try? SwKeyStore.upsertKey(priv, keyTag: tag))
		XCTAssertNotNil(try? SwKeyStore.getKey(tag))
		XCTAssertNotNil(try? SwKeyStore.delKey(tag))
		XCTAssertNil(try? SwKeyStore.getKey(tag))
	}

	func encryptKey(enc: SwEncryptedPrivateKey.Mode) {
		let pass = "hello"
		let (priv, _) = keyPair!
		let privEncrypted = try? SwEncryptedPrivateKey.encryptPEM(priv, passphrase: pass, mode: enc)
		XCTAssert(privEncrypted != nil)
		let privDecrypted = try? SwEncryptedPrivateKey.decryptPEM(privEncrypted!, passphrase: pass)
		XCTAssert(privDecrypted != nil)
		XCTAssert(privDecrypted == priv)
	}
	
	func testEncryptKey() {
		encryptKey(.AES128CBC)
		encryptKey(.AES256CBC)
	}
	
	func decryptOpenSSLKeys(type: String) {
		let bundle = NSBundle(forClass: self.dynamicType)
		let encPEM = bundle.objectForInfoDictionaryKey("testPrivEncryptedPEMAES"+type) as! String
		let decPEM = bundle.objectForInfoDictionaryKey("testPrivDecryptedPEM") as! String
		let d = try? SwEncryptedPrivateKey.decryptPEM(encPEM, passphrase: "hello")
		XCTAssert(d != nil)
		XCTAssert(d! == decPEM)
	}
	
	func testOpenSSLKeys() {
		decryptOpenSSLKeys("128")
		decryptOpenSSLKeys("256")
	}
	
	func encryptDecrypt(privKey: String, pubKey: String, mode: SEM.Mode) {
		let testMessage = "This is a test string"
		let encMessage = try? SEM.encryptMessage(testMessage, pemKey: pubKey, mode: mode)
		XCTAssert(encMessage != nil)
		let decMessage = try? SEM.decryptMessage(encMessage!, pemKey: privKey)
		XCTAssert(decMessage != nil)
		XCTAssert(testMessage == decMessage!)
	}
	
	func encryptDecrypt(privKey: String, pubKey: String) {
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.CBC, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.CBC, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.CBC, hmac:.SHA512))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.GCM, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.GCM, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.GCM, hmac:.SHA512))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.CBC, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.CBC, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.CBC, hmac:.SHA512))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.GCM, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.GCM, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.GCM, hmac:.SHA512))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.CBC, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.CBC, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.CBC, hmac:.SHA512))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.GCM, hmac:.None))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.GCM, hmac:.SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.GCM, hmac:.SHA512))
	}
	
	func testEncryptGeneratedKeyPair() {
		let (priv, pub) = keyPair!
		encryptDecrypt(priv, pubKey: pub)
	}
	
	func testEncryptOpenSSLKeyPair() {
		let bundle = NSBundle(forClass: self.dynamicType)
		let priv = bundle.objectForInfoDictionaryKey("testPrivPEM") as! String
		let pub = bundle.objectForInfoDictionaryKey("testPubPEM") as! String
		encryptDecrypt(priv, pubKey: pub)
	}
}
