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
		XCTAssert(CC.digest(testData, alg: .SHA1) == sha1)
		XCTAssert(CC.digest(testData, alg: .SHA256) == sha256)
		XCTAssert(CC.digest(testData, alg: .SHA384) == sha384)
		XCTAssert(CC.digest(testData, alg: .SHA512) == sha512)
		XCTAssert(CC.digest(testData, alg: .SHA224) == sha224)
		XCTAssert(CC.digest(testData, alg: .MD5) == md5)
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
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.CBC_SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES128, block:.GCM))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.CBC_SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES192, block:.GCM))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.CBC_SHA256))
		encryptDecrypt(privKey, pubKey: pubKey, mode: SEM.Mode(aes:.AES256, block:.GCM))
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
	
	func testCCM() {
		let data = "hello".dataUsingEncoding(NSUTF8StringEncoding)!
		let key = "8B142BB0FA0043C32821BB90A3453884".dataFromHexadecimalString()!
		let iv = "B5863BD2ABBED31DC26C4EDB5A".dataFromHexadecimalString()!
		let aData = "hello".dataUsingEncoding(NSUTF8StringEncoding)!
		let tagLength = 16
		XCTAssert(CC.CCM.available())
		
		let enc = try? CC.CCM.crypt(.encrypt, algorithm: .AES, data: data, key: key, iv: iv, aData: aData, tagLength: tagLength)
		XCTAssert(enc != nil)
		let dec = try? CC.CCM.crypt(.decrypt, algorithm: .AES, data: enc!.0, key: key, iv: iv, aData: aData, tagLength: tagLength)
		XCTAssert(dec != nil)
		XCTAssert(enc!.1 == dec!.1)
		XCTAssert(dec!.0 == data)
	}
	
	func testCCMSJCL() {
		let data = "hello".dataUsingEncoding(NSUTF8StringEncoding)!
		let key = "8B142BB0FA0043C32821BB90A3453884".dataFromHexadecimalString()!
		let iv = "B5863BD2ABBED31DC26C4EDB5A".dataFromHexadecimalString()!
		let aData = "hello".dataUsingEncoding(NSUTF8StringEncoding)!
		let tagLength = 16
		let sjclCipher = NSData(base64EncodedString: "VqAna25S22M+yOZz57wCllx7Itql", options: [])!
		XCTAssert(CC.CCM.available())
		
		let enc = try? CC.cryptAuth(.encrypt, blockMode: .CCM, algorithm: .AES, data: data, aData: aData, key: key, iv: iv, tagLength: tagLength)
		XCTAssert(enc != nil)
		XCTAssert(enc! == sjclCipher)
		
		let dec = try? CC.cryptAuth(.decrypt, blockMode: .CCM, algorithm: .AES, data: sjclCipher, aData: aData, key: key, iv: iv, tagLength: tagLength)
		XCTAssert(dec != nil)
		XCTAssert(dec! == data)
	}

	func test_pbkdf2() {
		let password = "password"
		let salt = "salt".dataUsingEncoding(NSUTF8StringEncoding)!
		
		XCTAssert(CC.KeyDerivation.available())
		let stretched = try? CC.KeyDerivation.PBKDF2(password, salt: salt, prf: .SHA256, rounds: 4096)
		XCTAssert(stretched != nil)
		let t = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a".dataFromHexadecimalString()
		XCTAssert(t == stretched!)
	}
	
	func test_keyWrap() {
		let kek = "000102030405060708090A0B0C0D0E0F".dataFromHexadecimalString()!
		let tkey = "00112233445566778899AABBCCDDEEFF".dataFromHexadecimalString()!
		let wrappedKey = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5".dataFromHexadecimalString()!
		
		XCTAssert(CC.KeyWrap.available())
		let cipher = try? CC.KeyWrap.SymmetricKeyWrap(CC.KeyWrap.rfc3394_iv, kek: kek, rawKey: tkey)
		XCTAssert(cipher != nil)
		XCTAssert(cipher! == wrappedKey)
		
		let key = try? CC.KeyWrap.SymmetricKeyUnwrap(CC.KeyWrap.rfc3394_iv, kek: kek, wrappedKey: cipher!)
		XCTAssert(key != nil)
		XCTAssert(key! == tkey)

	}
}
