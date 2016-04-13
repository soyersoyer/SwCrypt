import Foundation
import CommonCrypto
import CommonRSACryptor

func error(desc: String, from: String = #function) -> SwError {
	let msg = "SwCrypt.\(from): " + desc
	print(msg)
	return SwError.Error(desc: msg)
}

extension SwError : CustomStringConvertible {
	var description: String {
		switch self {
		case .Error(let desc):
			return desc
		}
	}
}

enum SwError : ErrorType {
	case Error(desc: String)
}
	
public class SwKeyStore {

	static public func upsertKey(pemKey: String, keyTag: String, options: [NSString : AnyObject] = [:]) throws {
		let pemKeyAsData = pemKey.dataUsingEncoding(NSUTF8StringEncoding)!
		
		var parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrIsPermanent: true,
			kSecAttrApplicationTag: keyTag,
			kSecValueData: pemKeyAsData
		]
		options.forEach({k, v in parameters[k] = v})
		
		var status = SecItemAdd(parameters, nil)
		if status == errSecDuplicateItem {
			try delKey(keyTag)
			status = SecItemAdd(parameters, nil)
		}
		guard status == errSecSuccess else {
			throw error("SwKeyStore: keyTag: \(keyTag) failed: \(status)")
		}
	}
	
	static public func getKey(keyTag: String) throws -> String {
		let parameters: [NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag : keyTag,
			kSecReturnData : true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters, &data)
		guard status == errSecSuccess else {
			throw error("SwKeyStore: keyTag: \(keyTag) SecItemCopyMatching failed: \(status)")
		}
		guard let pemKeyAsData = data as? NSData else {
			throw error("SwKeyStore: keyTag: \(keyTag) decoding failed")
		}
		return String(data: pemKeyAsData, encoding: NSUTF8StringEncoding)!
	}
	
	static public func delKey(keyTag: String) throws {
		let parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrApplicationTag: keyTag,
			]
		let status = SecItemDelete(parameters)
		guard status == errSecSuccess else {
			throw error("SwKeyStore: SecItemDelete failed: \(status)")
		}
	}
}

public class SwPrivateKey {
	
	static public func getKeyDataFromPEM(pemKey: String) throws -> NSData {
		let strippedKey = try stripPEMHeader(pemKey)
		guard let data = NSData(base64EncodedString: strippedKey, options: [.IgnoreUnknownCharacters]) else {
			throw error("SwPrivateKey: base64decode failed")
		}
		return try stripX509Header(data)
	}
	
	static public func getPEMFromKeyData(keyData: NSData) -> String {
		return addPEMRSAPreSuffix(keyData.base64EncodedStringWithOptions(
			[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed]))
	}
	
	static private let PEMPrefix = "-----BEGIN PRIVATE KEY-----\n"
	static private let PEMSuffix = "\n-----END PRIVATE KEY-----"
	static private let PEMRSAPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
	static private let PEMRSASuffix = "\n-----END RSA PRIVATE KEY-----"
	
	static private func addPEMPreSuffix(base64: String) -> String {
		return PEMPrefix + base64 + PEMSuffix
	}
	
	static private func addPEMRSAPreSuffix(base64: String) -> String {
		return PEMRSAPrefix + base64 + PEMRSASuffix
	}
	
	static private func stripPEMHeader(pemKey: String) throws -> String {
		if pemKey.hasPrefix(PEMPrefix) {
			guard let r = pemKey.rangeOfString(PEMSuffix) else {
				throw error("SwPrivateKey: found prefix header but not suffix")
			}
			return pemKey.substringWithRange(PEMPrefix.endIndex..<r.startIndex)
		}
		if pemKey.hasPrefix(PEMRSAPrefix) {
			guard let r = pemKey.rangeOfString(PEMRSASuffix) else {
				throw error("SwPrivateKey: found prefix header but not suffix")
			}
			return pemKey.substringWithRange(PEMRSAPrefix.endIndex..<r.startIndex)
		}
		throw error("SwPrivateKey: prefix header hasn't found")
	}
	
	//https://lapo.it/asn1js/
	static private func stripX509Header(keyData: NSData) throws -> NSData {
		var bytes = keyData.arrayOfBytes()
		
		var offset = 0
		guard bytes[offset] == 0x30 else {
			throw error("SwPrivateKey: ASN1 parse failed")
		}
		offset += 1
			
		if bytes[offset] > 0x80 {
			offset += Int(bytes[offset]) - 0x80
		}
		offset += 1
		
		guard bytes[offset] == 0x02 else {
			throw error("SwPrivateKey: ASN1 parse failed")
		}
		offset += 3
		
		//without header
		if bytes[offset] == 0x02 {
			return keyData
		}
		
		let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
							0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
		let slice: [UInt8] = Array(bytes[offset..<(offset + OID.count)])
		
		guard slice == OID else {
			throw error("SwPrivateKey: ASN1 parse failed")
		}
		
		offset += OID.count
		guard bytes[offset] == 0x04 else {
			throw error("SwPrivateKey: ASN1 parse failed")
		}
		
		offset += 1
		if bytes[offset] > 0x80 {
			offset += Int(bytes[offset]) - 0x80
		}
		offset += 1
		
		guard bytes[offset] == 0x30 else {
			throw error("SwPrivateKey: ASN1 parse failed")
		}
		
		return keyData.subdataWithRange(NSRange(location: offset, length: keyData.length - offset))
	}

}

public class SwEncryptedPrivateKey {
	public enum Mode {
		case AES128CBC, AES256CBC
	}
	
	static public func encryptPEM(pemKey: String, passphrase: String, mode: Mode) throws -> String {
		let keyData = try SwPrivateKey.getKeyDataFromPEM(pemKey)
		return getPEMFromKeyData(keyData, passphrase: passphrase, mode: mode)
	}
	
	static public func decryptPEM(pemKey: String, passphrase: String) throws -> String {
		let keyData = try getKeyDataFromPEM(pemKey, passphrase: passphrase)
		return SwPrivateKey.getPEMFromKeyData(keyData)
	}
	
	static public func getPEMFromKeyData(keyData: NSData, passphrase: String, mode: Mode) -> String {
		return SwPrivateKey.addPEMRSAPreSuffix(encryptKeyData(keyData, passphrase: passphrase, mode: mode))
	}
	
	static public func getKeyDataFromPEM(pemKey: String, passphrase: String) throws -> NSData {
		let strippedKey = try SwPrivateKey.stripPEMHeader(pemKey)
		return try decryptPEM(strippedKey, passphrase: passphrase)
	}
	
	static private let AES128CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,"
	static private let AES256CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
	static private let AESInfoLength = AES128CBCInfo.characters.count
	static private let AESIVInHexLength = 32
	static private let AESHeaderLength = AESInfoLength + AESIVInHexLength
	
	static private func getIV(strippedKey: String) -> NSData? {
		let iv = strippedKey.substringWithRange(strippedKey.startIndex+AESInfoLength..<strippedKey.startIndex+AESHeaderLength)
		return iv.dataFromHexadecimalString()
	}
	
	static private func getAESKeyAndIV(strippedKey: String, passphrase: String) -> (NSData, NSData)? {
		if strippedKey.hasPrefix(AES128CBCInfo) {
			guard let iv = getIV(strippedKey) else {
				return nil
			}
			let aesKey = getAES128Key(passphrase, iv: iv)
			return (aesKey, iv)
		}
		if strippedKey.hasPrefix(AES256CBCInfo) {
			guard let iv = getIV(strippedKey) else {
				return nil
			}
			let aesKey = getAES256Key(passphrase, iv: iv)
			return (aesKey, iv)
		}
		return nil
	}
	
	static private func decryptPEM(strippedKey: String, passphrase: String) throws -> NSData {
		guard let (aesKey,iv) = getAESKeyAndIV(strippedKey, passphrase: passphrase) else {
			throw error("EncryptedPrivateKey: can't parse encrypted header")
		}
		let base64Data = strippedKey.substringFromIndex(strippedKey.startIndex+AESHeaderLength)
		guard let data = NSData(base64EncodedString: base64Data, options: [.IgnoreUnknownCharacters]) else {
			throw error("EncryptedPrivateKey: can't base64 decode PEM data")
		}
		let decrypted = try CC.AESDecrypt(data, key: aesKey, iv: iv, blockMode: .CBC)
		return decrypted
	}
	
	static private func getAES128Key(passphrase: String, iv: NSData) -> NSData {
		//128bit_Key = MD5(Passphrase + Salt)
		let pass = NSData(data: passphrase.dataUsingEncoding(NSUTF8StringEncoding)!)
		let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
		
		let key = NSMutableData(data: pass)
		key.appendData(salt)
		return CC.md5(key)
	}
	
	static private func getAES256Key(passphrase: String, iv:NSData) -> NSData {
		//128bit_Key = MD5(Passphrase + Salt)
		//256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)
		let pass = NSMutableData(data: passphrase.dataUsingEncoding(NSUTF8StringEncoding)!)
		let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
		
		let first = NSMutableData(data: pass)
		first.appendData(salt)
		let aes128Key = CC.md5(first)
		
		let sec = NSMutableData(data: aes128Key)
		sec.appendData(pass)
		sec.appendData(salt)
		
		let aes256Key = NSMutableData(data: aes128Key)
		aes256Key.appendData(CC.md5(sec))
		return aes256Key
	}
	
	static private func encryptPrivateKeyAES128CBC(keyData: NSData, passphrase: String) -> String {
		let iv = CC.generateRandom(16)
		let aesKey = getAES128Key(passphrase, iv: iv)
		let encrypted = try! CC.AESEncrypt(keyData, key: aesKey, iv: iv, blockMode: .CBC)
		return AES128CBCInfo + iv.hexadecimalString() + "\n\n" +
			encrypted.base64EncodedStringWithOptions(
				[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
	}
	
	static private func encryptPrivateKeyAES256CBC(keyData: NSData, passphrase: String) -> String {
		let iv = CC.generateRandom(16)
		let aesKey = getAES256Key(passphrase, iv: iv)
		let encrypted = try! CC.AESEncrypt(keyData, key: aesKey, iv: iv, blockMode: .CBC)
		return AES256CBCInfo + iv.hexadecimalString() + "\n\n" +
			encrypted.base64EncodedStringWithOptions(
				[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
	}
	
	static private func encryptKeyData(keyData: NSData, passphrase: String, mode: Mode) -> String {
		switch mode {
		case .AES128CBC: return encryptPrivateKeyAES128CBC(keyData, passphrase: passphrase)
		case .AES256CBC: return encryptPrivateKeyAES256CBC(keyData, passphrase: passphrase)
		}
	}
	
}

public class SwPublicKey {
	
	static public func getPEMFromKeyData(keyData: NSData) -> String {
		let keyDataWithHeader = addX509Header(keyData)
		return addPEMPreSuffix(keyDataWithHeader.base64EncodedStringWithOptions(
			[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed]))
	}
	
	static public func getKeyDataFromPEM(pemKey: String) throws -> NSData {
		let base64key = try stripPEMHeader(pemKey)
		guard let x509Data = NSData(base64EncodedString: base64key, options: [.IgnoreUnknownCharacters]) else {
			throw error("PublicKey: can't base64 decode PEM data")
		}
		return try stripX509Header(x509Data)
	}
	
	static private let PEMPrefix = "-----BEGIN PUBLIC KEY-----\n"
	static private let PEMSuffix = "\n-----END PUBLIC KEY-----"
	
	static private func stripPEMHeader(pemKey: String) throws -> String {
		if pemKey.hasPrefix(PEMPrefix) {
			guard let r = pemKey.rangeOfString(PEMSuffix) else {
				throw error("PublicKey: found prefix header but not suffix")
			}
			return pemKey.substringWithRange(PEMPrefix.endIndex..<r.startIndex)
		}
		throw error("PublicKey: prefix header hasn't found")
	}
		
	static private func addPEMPreSuffix(base64: String) -> String {
		return PEMPrefix + base64 + PEMSuffix
	}
	
	static private func addX509Header(keyData: NSData) -> NSData {
		let result = NSMutableData()
		
		let encodingLength: Int = encodedOctets(keyData.length + 1).count
		let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
							0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
		
		var builder: [UInt8] = []
		
		// ASN.1 SEQUENCE
		builder.append(0x30)
		
		// Overall size, made of OID + bitstring encoding + actual key
		let size = OID.count + 2 + encodingLength + keyData.length
		let encodedSize = encodedOctets(size)
		builder.appendContentsOf(encodedSize)
		result.appendBytes(builder, length: builder.count)
		result.appendBytes(OID, length: OID.count)
		builder.removeAll(keepCapacity: false)
		
		builder.append(0x03)
		builder.appendContentsOf(encodedOctets(keyData.length + 1))
		builder.append(0x00)
		result.appendBytes(builder, length: builder.count)
		
		// Actual key bytes
		result.appendData(keyData)
		
		return result as NSData
	}
	
	//https://lapo.it/asn1js/
	static private func stripX509Header(keyData: NSData) throws -> NSData {
		var bytes = keyData.arrayOfBytes()
		
		var offset = 0
		guard bytes[offset] == 0x30 else {
			throw error("PublicKey: ASN1 parse failed")
		}
		
		offset += 1
			
		if bytes[offset] > 0x80 {
			offset += Int(bytes[offset]) - 0x80
		}
		offset += 1
		
		//without header
		if bytes[offset] == 0x02 {
			return keyData
		}
		
		let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
							0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
		let slice: [UInt8] = Array(bytes[offset..<(offset + OID.count)])
			
		guard slice == OID else {
			throw error("PublicKey: ASN1 parse failed")
		}
			
		offset += OID.count
				
		// Type
		guard bytes[offset] == 0x03 else {
			throw error("PublicKey: ASN1 parse failed")
		}
				
		offset += 1
				
		if bytes[offset] > 0x80 {
			offset += Int(bytes[offset]) - 0x80
		}
		offset += 1
				
		// Contents should be separated by a null from the header
		guard bytes[offset] == 0x00 else {
			throw error("PublicKey: ASN1 parse failed")
		}
				
		offset += 1
		return keyData.subdataWithRange(NSRange(location: offset, length: keyData.length - offset))
	}

	static private func encodedOctets(int: Int) -> [UInt8] {
		// Short form
		if int < 128 {
			return [UInt8(int)];
		}
		
		// Long form
		let i = (int / 256) + 1
		var len = int
		var result: [UInt8] = [UInt8(i + 0x80)]
		
		for _ in 0..<i {
			result.insert(UInt8(len & 0xFF), atIndex: 1)
			len = len >> 8
		}
		
		return result
	}
}


//Simple Encrypted Message
public class SEM {
	
	public enum AesMode : UInt8 {
		case AES128, AES192, AES256
		
		var keySize: Int {
			switch self {
			case .AES128: return 16
			case .AES192: return 24
			case .AES256: return 32
			}
		}
	}
	
	public enum BlockMode : UInt8 {
		case CBC, GCM
		
		var ivSize: Int {
			switch self {
			case .CBC: return 16
			case .GCM: return 12
			}
		}
		var cc: CC.BlockMode {
			switch self {
			case .CBC: return .CBC
			case .GCM: return .GCM
			}
		}
	}
	
	public enum HMACMode : UInt8 {
		case None, SHA256, SHA512
		
		var cc: CC.HMACAlg?  {
			switch self {
			case .None: return nil
			case .SHA256: return .SHA256
			case .SHA512: return .SHA512
			}
		}
		var digestLength: Int {
			switch self {
			case .None: return 0
			default: return self.cc!.digestLength
			}
		}

	}
	
	public struct Mode {
		let aes: AesMode
		let block: BlockMode
		let hmac: HMACMode
		public init() {
			aes = .AES256
			block = .CBC
			hmac = .SHA256
		}
		public init(aes: AesMode, block: BlockMode, hmac: HMACMode) {
			self.aes = aes
			self.block = block
			self.hmac = hmac
		}
	}
	
	static public func encryptMessage(message: String, pemKey: String, mode: Mode) throws -> String {
		guard let data = message.dataUsingEncoding(NSUTF8StringEncoding) else {
			throw error("SEM: can't get UTF8 from the message")
		}
		let encryptedData = try encryptData(data, pemKey: pemKey, mode: mode)
		return encryptedData.base64EncodedStringWithOptions([])
	}
	
	static public func decryptMessage(message: String, pemKey: String) throws -> String {
		guard let data = NSData(base64EncodedString: message, options: []) else {
			throw error("SEM: can't decode base64 string")
		}
		let decryptedData = try decryptData(data, pemKey: pemKey)
		guard let decryptedString = String(data: decryptedData, encoding: NSUTF8StringEncoding) else {
			throw error("SEM: can't get UTF8 from the message")
		}
		return decryptedString
	}
	
	static public func encryptData(data: NSData, pemKey: String, mode: Mode) throws -> NSData {
		let aesKey = CC.generateRandom(mode.aes.keySize)
		let IV = CC.generateRandom(mode.block.ivSize)
		let header = getMessageHeader(mode, aesKey: aesKey, IV: IV)
		let encryptedHeader = try CCRSA.encrypt(header, pemKey: pemKey, padding: .OAEP, digest: .SHA1)
		let encryptedData = try CC.AESEncrypt(data, key: aesKey, iv: IV, blockMode: mode.block.cc)
		
		let result = NSMutableData()
		result.appendData(encryptedHeader)
		result.appendData(encryptedData)
		if mode.hmac != .None {
			result.appendData(CC.HMAC(result, alg: mode.hmac.cc!, key: aesKey))
		}
		return result
	}
	
	
	static public func decryptData(data: NSData, pemKey: String) throws -> NSData {
		let (header, tail) = try CCRSA.decrypt(data, pemKey: pemKey, padding: .OAEP, digest: .SHA1)
		let (mode, aesKey, iv) = try parseMessageHeader(header)
		
		try checkHMAC(data, aesKey: aesKey, mode: mode.hmac)
		let aesData = tail.subdataWithRange(NSRange(location: 0, length: tail.length - mode.hmac.digestLength))
		return try CC.AESDecrypt(aesData, key: aesKey, iv: iv, blockMode: mode.block.cc)
	}
	
	static private func checkHMAC(data: NSData, aesKey: NSData, mode: SEM.HMACMode) throws {
		if mode != .None {
			let hmaccedData = data.subdataWithRange(NSRange(location: 0, length: data.length - mode.digestLength))
			let hmac = data.subdataWithRange(NSRange(location: data.length - mode.digestLength, length: mode.digestLength))
			guard CC.HMAC(hmaccedData, alg: mode.cc!, key: aesKey) == hmac else {
				throw error("SEM: invalid message (HMAC)")
			}
		}
	}
	
	static private func getMessageHeader(mode: Mode, aesKey: NSData, IV: NSData) -> NSData {
		let header : [UInt8] = [mode.aes.rawValue, mode.block.rawValue, mode.hmac.rawValue]
		let message = NSMutableData(bytes: header, length: 3)
		message.appendData(aesKey)
		message.appendData(IV)
		return message
	}
	
	static private func parseMessageHeader(header: NSData) throws -> (Mode, NSData, NSData) {
		guard header.length > 3 else {
			throw error("SEM: invalid header length: \(header.length)")
		}
		let bytes = header.arrayOfBytes()
		guard let aes = AesMode(rawValue: bytes[0]) else {
			throw error("SEM: invalid aes mode: \(bytes[0])")
		}
		guard let block = BlockMode(rawValue: bytes[1]) else {
			throw error("SEM: invalid block mode: \(bytes[1])")
		}
		guard let hmac = HMACMode(rawValue: bytes[2]) else {
			throw error("SEM: invalid hmac mode: \(bytes[2])")
		}
		let keySize = aes.keySize
		let ivSize = block.ivSize
		guard header.length == 3 + keySize + ivSize else {
			throw error("SEM: invalid header length: \(header.length)")
		}
		let key = header.subdataWithRange(NSRange(location: 3, length: keySize))
		let iv = header.subdataWithRange(NSRange(location: 3 + keySize, length: ivSize))
		
		return (Mode(aes: aes, block: block, hmac: hmac), key, iv)
	}	
}

public class CCRSA {
	public enum AsymmetricPadding {
		case PKCS1, OAEP
		
		var cc : CCAsymmetricPadding {
			switch self {
			case .PKCS1: return CCAsymmetricPadding(ccPKCS1Padding)
			case .OAEP: return CCAsymmetricPadding(ccOAEPPadding)
			}
		}
	}
	
	public enum DigestAlgorithm {
		case None, SHA1, SHA224, SHA256, SHA384, SHA512
		
		var cc: CCDigestAlgorithm {
			switch self {
			case .None: return CCDigestAlgorithm(kCCDigestNone)
			case .SHA1: return CCDigestAlgorithm(kCCDigestSHA1)
			case .SHA224: return CCDigestAlgorithm(kCCDigestSHA224)
			case .SHA256: return CCDigestAlgorithm(kCCDigestSHA256)
			case .SHA384: return CCDigestAlgorithm(kCCDigestSHA384)
			case .SHA512: return CCDigestAlgorithm(kCCDigestSHA512)
			}
		}
	}
	
	static public func generateKeyPair(keySize: Int = 4096) throws -> (String, String) {
		var privateKey: CCRSACryptorRef = nil
		var publicKey: CCRSACryptorRef = nil
		var status = CCRSACryptorGeneratePair(keySize, 65537, &publicKey, &privateKey)
		guard status == noErr else {
			throw error("CCRSACryptorGeneratePair failed \(status)")
		}
		defer {	CCRSACryptorRelease(privateKey) }
		defer { CCRSACryptorRelease(publicKey) }
		
		var privKeyDataLength = 8192
		let privKeyData = NSMutableData(length: privKeyDataLength)!
		var pubKeyDataLength = 8192
		let pubKeyData = NSMutableData(length: pubKeyDataLength)!
		
		status = CCRSACryptorExport(privateKey, privKeyData.mutableBytes, &privKeyDataLength)
		guard status == noErr else {
			throw error("CCRSACryptorExport privateKey failed \(status)")
		}
		status = CCRSACryptorExport(publicKey, pubKeyData.mutableBytes, &pubKeyDataLength)
		guard status == noErr else {
			throw error("CCRSACryptorExport publicKey failed \(status)")
		}
		
		privKeyData.length = privKeyDataLength
		pubKeyData.length = pubKeyDataLength
		
		let privPEM = SwPrivateKey.getPEMFromKeyData(privKeyData)
		let pubPEM = SwPublicKey.getPEMFromKeyData(pubKeyData)
		return (privPEM, pubPEM)
	}
	
	static public func encrypt(data: NSData, pemKey: String, padding: AsymmetricPadding, digest: DigestAlgorithm) throws -> NSData {
		let keyData = try SwPublicKey.getKeyDataFromPEM(pemKey)
		let key = try getRSAKeyFromKeyData(keyData)
		defer { CCRSACryptorRelease(key) }
		
		var bufferSize = Int(CCRSAGetKeySize(key)/8)
		let buffer = NSMutableData(length: bufferSize)!
		
		let status = CCRSACryptorEncrypt(key, padding.cc, data.bytes, data.length, buffer.mutableBytes, &bufferSize, nil, 0, digest.cc)
		guard status == noErr else {
			throw error("CCRSACryptorEncrypt failed \(status)")
		}
		return buffer
	}
	
	static public func decrypt(data: NSData, pemKey: String, padding: AsymmetricPadding, digest: DigestAlgorithm) throws -> (NSData, NSData) {
		let keyData = try SwPrivateKey.getKeyDataFromPEM(pemKey)
		let key = try getRSAKeyFromKeyData(keyData)
		defer { CCRSACryptorRelease(key) }
		
		let blockSize = Int(CCRSAGetKeySize(key) / 8)
		var bufferSize = blockSize
		let buffer = NSMutableData(length: bufferSize)!
		
		let status = CCRSACryptorDecrypt(key, padding.cc, data.bytes, bufferSize, buffer.mutableBytes, &bufferSize, nil, 0, digest.cc)
		guard status == noErr else {
			throw error("CCRSACryptorDecrypt failed \(status)")
		}
		buffer.length = bufferSize
		let tail = data.subdataWithRange(NSRange(location: blockSize, length: data.length - blockSize))
		return (buffer, tail)
	}

	static private func getRSAKeyFromKeyData(keyData: NSData) throws -> CCRSACryptorRef {
		var key : CCRSACryptorRef = nil
		let status = CCRSACryptorImport(keyData.bytes, keyData.length, &key)
		guard status == noErr else {
			throw error("CCRSACryptorImport failed \(status)")
		}
		return key
	}
}

public class CC {
	
	static public func AESEncrypt(data: NSData, key: NSData, iv: NSData, blockMode: BlockMode) throws -> NSData {
		return try AESCrypt(.encrypt, data: data, key: key, iv: iv, blockMode: blockMode)
	}
	
	static public func AESDecrypt(data: NSData, key: NSData, iv: NSData, blockMode: BlockMode) throws -> NSData {
		return try AESCrypt(.decrypt, data: data, key: key, iv: iv, blockMode: blockMode)
	}
	
	
	static public func generateRandom(size: Int) -> NSData {
		let data = NSMutableData(length: size)!
		CCRandomCopyBytes(kCCRandomDefault, data.mutableBytes, size)
		return data
	}
	
	static public func sha1(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH))!
		CC_SHA1(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	static public func sha256(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
		CC_SHA256(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	static public func sha384(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_SHA384_DIGEST_LENGTH))!
		CC_SHA384(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	static public func sha512(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_SHA512_DIGEST_LENGTH))!
		CC_SHA512(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	static public func sha224(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_SHA224_DIGEST_LENGTH))!
		CC_SHA224(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	static public func md5(data: NSData) -> NSData {
		let result = NSMutableData(length: Int(CC_MD5_DIGEST_LENGTH))!
		CC_MD5(data.bytes, CC_LONG(data.length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return result
	}
	
	public enum HMACAlg {
		case SHA1, MD5, SHA256, SHA384, SHA512, SHA224
		
		var cc: CCHmacAlgorithm {
			switch self {
			case .SHA1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
			case .MD5: return CCHmacAlgorithm(kCCHmacAlgMD5)
			case .SHA256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
			case .SHA384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
			case .SHA512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
			case .SHA224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
			}
		}
		var digestLength: Int {
			switch self {
			case .SHA1: return Int(CC_SHA1_DIGEST_LENGTH)
			case .MD5: return Int(CC_MD5_DIGEST_LENGTH)
			case .SHA256: return Int(CC_SHA256_DIGEST_LENGTH)
			case .SHA384: return Int(CC_SHA384_DIGEST_LENGTH)
			case .SHA512: return Int(CC_SHA512_DIGEST_LENGTH)
			case .SHA224: return Int(CC_SHA224_DIGEST_LENGTH)
			}
		}
	}

	
	static public func HMAC(data: NSData, alg: HMACAlg, key: NSData) -> NSData {
		let buffer = NSMutableData(length: alg.digestLength)!
		CCHmac(alg.cc, key.bytes, key.length, data.bytes, data.length, buffer.mutableBytes)
		return buffer
	}
	
	private enum OpMode {
		case encrypt, decrypt
		
		var cc: CCOperation {
			switch self {
			case .encrypt: return CCOperation(kCCEncrypt)
			case .decrypt: return CCOperation(kCCDecrypt)
			}
		}
	}
	
	public enum BlockMode {
		case ECB, CBC, CFB, CTR, OFB, XTS, RC4, CFB8, GCM
		
		var cc: CCMode {
			switch self {
			case .ECB: return CCMode(kCCModeECB)
			case .CBC: return CCMode(kCCModeCBC)
			case .CFB: return CCMode(kCCModeCFB)
			case .CTR: return CCMode(kCCModeCTR)
			case .OFB: return CCMode(kCCModeOFB)
			case .XTS: return CCMode(kCCModeXTS)
			case .RC4: return CCMode(kCCModeRC4)
			case .CFB8: return CCMode(kCCModeCFB8)
			case .GCM: return CCMode(11/*kCCModeGCM*/)
			}
		}
	}
	
	static private func AESCrypt(opMode: OpMode, data: NSData, key: NSData, iv: NSData, blockMode: BlockMode) throws -> NSData {
		var cryptor : CCCryptorRef = nil
		var status = CCCryptorCreateWithMode(
			opMode.cc, blockMode.cc,
			CCAlgorithm(kCCAlgorithmAES), CCPadding(ccPKCS7Padding),
			iv.bytes, key.bytes, key.length, nil, 0, 0,	CCModeOptions(), &cryptor)
		guard status == noErr else {
			throw error("CCCryptorCreateWithMode failed: \(status)")
		}
		defer { CCCryptorRelease(cryptor) }
		
		let needed = CCCryptorGetOutputLength(cryptor, data.length, true)
		let result = NSMutableData(length: needed)!
		var updateLen: size_t = 0
		status = CCCryptorUpdate(cryptor, data.bytes, data.length,
		                         result.mutableBytes, result.length, &updateLen)
		guard status == noErr else {
			throw error("CCCryptorUpdate failed: \(status)")
		}
		
		var finalLen: size_t = 0
		status = CCCryptorFinal(cryptor, result.mutableBytes + updateLen,
		                        result.length - updateLen, &finalLen)
		guard status == noErr else {
			throw error("CCCryptorFinal failed: \(status)")
		}
		
		result.length = updateLen + finalLen
		return result
	}
}

extension NSData {
	/// Create hexadecimal string representation of NSData object.
	///
	/// - returns: String representation of this NSData object.
	
	func hexadecimalString() -> String {
		var hexstr = String()
		for i in UnsafeBufferPointer<UInt8>(start: UnsafeMutablePointer<UInt8>(bytes), count: length) {
			hexstr += String(format: "%02X", i)
		}
		return hexstr
	}
	
	public func arrayOfBytes() -> [UInt8] {
		let count = self.length / sizeof(UInt8)
		var bytesArray = [UInt8](count: count, repeatedValue: 0)
		self.getBytes(&bytesArray, length:count * sizeof(UInt8))
		return bytesArray
	}
}

extension String.CharacterView.Index : Strideable { }
extension String {
	
	/// Create NSData from hexadecimal string representation
	///
	/// This takes a hexadecimal representation and creates a NSData object. Note, if the string has any spaces, those are removed. Also if the string started with a '<' or ended with a '>', those are removed, too. This does no validation of the string to ensure it's a valid hexadecimal string
	///
	/// The use of `strtoul` inspired by Martin R at http://stackoverflow.com/a/26284562/1271826
	///
	/// - returns: NSData represented by this hexadecimal string. Returns nil if string contains characters outside the 0-9 and a-f range.
	
	func dataFromHexadecimalString() -> NSData? {
		let trimmedString = self.stringByTrimmingCharactersInSet(NSCharacterSet(charactersInString: "<> ")).stringByReplacingOccurrencesOfString(" ", withString: "")
		
		// make sure the cleaned up string consists solely of hex digits, and that we have even number of them
		
		let regex = try! NSRegularExpression(pattern: "^[0-9a-f]*$", options: .CaseInsensitive)
		
		let found = regex.firstMatchInString(trimmedString, options: [], range: NSMakeRange(0, trimmedString.characters.count))
		guard found != nil &&
			found?.range.location != NSNotFound &&
			trimmedString.characters.count % 2 == 0 else {
				return nil
		}
		
		// everything ok, so now let's build NSData
		
		let data = NSMutableData(capacity: trimmedString.characters.count / 2)
		
		for index in trimmedString.startIndex.stride(to:trimmedString.endIndex,by:2) {
			let byteString = trimmedString.substringWithRange(index..<index.successor().successor())
			let num = UInt8(byteString.withCString { strtoul($0, nil, 16) })
			data?.appendBytes([num] as [UInt8], length: 1)
		}
		
		return data
	}
}

