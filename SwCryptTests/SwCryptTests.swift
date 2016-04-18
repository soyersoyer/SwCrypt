import XCTest
import SwCrypt

let keyPair = try? SwCryptTest.createKeyPair(2048)

class SwCryptTest: XCTestCase {
	
    override func setUp() {
        super.setUp()
		self.continueAfterFailure = false
    }
    
    override func tearDown() {
        super.tearDown()
    }

	static func createKeyPair(size: Int) throws -> (String, String) {
		let keyPair = try CC.RSA.generateKeyPair(size)
		let privKey = SwPrivateKey.derToPKCS1PEM(keyPair.0)
		let pubKey = SwPublicKey.derToPKCS1PEM(keyPair.1)
		return (privKey, pubKey)
	}
	
	func testAvailable() {
		XCTAssert(CC.digestAvailable())
		XCTAssert(CC.randomAvailable())
		XCTAssert(CC.hmacAvailable())
		XCTAssert(CC.cryptorAvailable())
		XCTAssert(CC.RSA.available())
		XCTAssert(CC.GCM.available())
		XCTAssert(CC.available())
	}
	
	func testDigest() {
		XCTAssert(CC.digestAvailable())
		let testData = "rokafogtacsuka".dataUsingEncoding(NSUTF8StringEncoding)!
		let sha1 = "9e421ffa8b2c83ac23e96bc9f9302f4a16311037".dataFromHexadecimalString()!
		let sha256 = "ae6ab1cf65971f88b9cd92c2f334d6a99beaf5b40240d4b440fdb4a1231db0f0".dataFromHexadecimalString()!
		let sha384 = "acf011a346e96364091bd21415a2437273c7f3c84060b21ac19f2eafa1c6cde76467b0b0aba99626b18aa3da83e442db".dataFromHexadecimalString()!
		let sha512 = "016748fad47ddfba4fcd19aacc67ee031dfef40f5e9692c84f8846e520f2a827a4ea5035af8a66686c60796a362c30e6c473cfdbb9d86f43312001fc0b660734".dataFromHexadecimalString()!
		let sha224 = "ec92519bb9e82a79097b0dd0618927b3262a70d6f02bd667c413009e".dataFromHexadecimalString()!
		let md5 = "9b43f853613732cfc8531ed6bcbf6d68".dataFromHexadecimalString()!
		XCTAssert(CC.sha1(testData) == sha1)
		XCTAssert(CC.sha256(testData) == sha256)
		XCTAssert(CC.sha384(testData) == sha384)
		XCTAssert(CC.sha512(testData) == sha512)
		XCTAssert(CC.sha224(testData) == sha224)
		XCTAssert(CC.md5(testData) == md5)
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
	
	func testSimpleSignVerify() {
		let (priv, pub) = keyPair!
		let testMessage = "rirararom_vagy_rararirom"
		
		let sign = try? SMSV.sign(testMessage, pemKey: priv)
		XCTAssert(sign != nil)
		let verified = try? SMSV.verify(testMessage, pemKey: pub, sign: sign!)
		XCTAssert(verified == true)
	}
	
}
