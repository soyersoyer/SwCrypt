import Foundation
import CommonCrypto

func error(desc: String, from: String = #function) -> SwError {
	return SwError.Error(desc: "SwCrypt.\(from): " + desc)
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

	static public func generateRSAKeyPair(keySize: Int = 4096) throws -> (String, String) {
		let (priv, pub) = try generateRSASecKeyPair(keySize)
		let privKeyData = try getKeyDataFromSecKey(priv)
		let pubKeyData = try getKeyDataFromSecKey(pub)
		let privPEM = SwPrivateKey.getPEMFromKeyData(privKeyData)
		let pubPEM = SwPublicKey.getPEMFromKeyData(pubKeyData)
		return (privPEM, pubPEM)
	}
	
	static public func upsertKey(pemKey: String, keyTag: String) throws {
		let pemKeyAsData = pemKey.dataUsingEncoding(NSUTF8StringEncoding)!
		
		let parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrIsPermanent: true,
			kSecAttrApplicationTag: keyTag,
			kSecValueData: pemKeyAsData
		]
		var status = SecItemAdd(parameters, nil)
		if status == errSecDuplicateItem {
			try delKey(keyTag)
			status = SecItemAdd(parameters, nil)
		}
		guard status == errSecSuccess else {
			throw error("SwKeyStore: keyTag: \(keyTag)) failed: \(status)")
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
	
	static private func generateRSASecKeyPair(keySize: Int) throws -> (SecKey,SecKey)  {
		let parameters: [NSString: AnyObject] = [
			kSecAttrKeyType: kSecAttrKeyTypeRSA,
			kSecAttrKeySizeInBits: keySize,
			]
		
		var publicKey: SecKey?
		var privateKey: SecKey?
		let status = SecKeyGeneratePair(parameters, &publicKey, &privateKey)
		
		guard status == errSecSuccess else {
			throw error("SwKeyStore: SecKeyGeneratePair failed \(status)")
		}
		return (privateKey!,publicKey!)
	}
	
	static private func delSecKey(key: SecKey) throws {
		let parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecValueRef: key,
			]
		let status = SecItemDelete(parameters)
		guard status == errSecSuccess else {
			throw error("SwKeyStore: SecItemDelete failed: \(status)")
		}
	}
	
	static private func getKeyDataFromSecKey(key: SecKey) throws -> NSData {
		let parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecValueRef: key,
			kSecReturnData: true
		]
		var data : AnyObject?
		let status = SecItemAdd(parameters, &data)
		guard status == errSecSuccess else {
			throw error("SwKeyStore: SecItemAdd failed \(status)")
		}
		try delSecKey(key)
		
		return data as! NSData
	}
	
	static private func getSecKeyFromKeyData(keyData: NSData, isPublic: Bool) throws -> SecKey {
		let parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
			kSecValueData: keyData,
			kSecReturnRef: true
		]
		var key : AnyObject?
		let add_status = SecItemAdd(parameters, &key)
		guard add_status == errSecSuccess else {
			throw error("SwKeyStore: parse failed, SecItemAdd failed: \(add_status)")
		}
		let del_status = SecItemDelete(parameters)
		guard del_status == errSecSuccess else {
			throw error("SwKeyStore: SecItemDelete failed: \(del_status)")
		}
		guard let secKey = key as! SecKey? else {
			throw error("SwKeyStore: invalid format (nil key returned)")
		}
		return secKey
	}
	
	static private func getPublicSecKeyFromPEM(pemKey: String) throws -> SecKey {
		let keyData = try SwPublicKey.getKeyDataFromPEM(pemKey)
		return try getSecKeyFromKeyData(keyData, isPublic: true)
	}
	
	static private func getPrivateSecKeyFromPEM(pemKey: String) throws -> SecKey {
		let keyData = try SwPrivateKey.getKeyDataFromPEM(pemKey)
		return try getSecKeyFromKeyData(keyData, isPublic: false)
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
	static private let AESIVInHexSize = 32
	static private let AESHeaderLength = AESInfoLength + AESIVInHexSize
	
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
		guard let decrypted = data.decryptAES(aesKey, iv: iv, blockMode: .CBC) else {
			throw error("EncryptedPrivateKey: can't decrypt data")
		}
		return decrypted
	}
	
	static private func getAES128Key(passphrase: String, iv: NSData) -> NSData {
		//128bit_Key = MD5(Passphrase + Salt)
		let pass = NSData(data: passphrase.dataUsingEncoding(NSUTF8StringEncoding)!)
		let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
		
		let key = NSMutableData(data: pass)
		key.appendData(salt)
		return key.md5()
	}
	
	static private func getAES256Key(passphrase: String, iv:NSData) -> NSData {
		//128bit_Key = MD5(Passphrase + Salt)
		//256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)
		let pass = NSMutableData(data: passphrase.dataUsingEncoding(NSUTF8StringEncoding)!)
		let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
		
		let first = NSMutableData(data: pass)
		first.appendData(salt)
		let aes128Key = first.md5()
		
		let sec = NSMutableData(data: aes128Key)
		sec.appendData(pass)
		sec.appendData(salt)
		
		let aes256Key = NSMutableData(data: aes128Key)
		aes256Key.appendData(sec.md5())
		return aes256Key
	}
	
	static private func encryptPrivateKeyAES128CBC(keyData: NSData, passphrase: String) -> String {
		let iv = SwCC.generateRandom(16)
		let aesKey = getAES128Key(passphrase, iv: iv)
		let encrypted = keyData.encryptAES(aesKey, iv:iv, blockMode: .CBC)!
		return AES128CBCInfo + iv.hexadecimalString() + "\n\n" +
			encrypted.base64EncodedStringWithOptions(
				[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
	}
	
	static private func encryptPrivateKeyAES256CBC(keyData: NSData, passphrase: String) -> String {
		let iv = SwCC.generateRandom(16)
		let aesKey = getAES256Key(passphrase, iv: iv)
		let encrypted = keyData.encryptAES(aesKey, iv:iv, blockMode: .CBC)!
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
		var cc: CCMode {
			let kCCModeGCM : Int = 11
			switch self {
			case .CBC: return CCMode(kCCModeCBC)
			case .GCM: return CCMode(kCCModeGCM)
			}
		}
	}
	
	public enum HMACMode : UInt8 {
		case None, SHA256, SHA512
		
		var cc: CCHmacAlgorithm {
			switch self {
			case .None: return CCHmacAlgorithm(0)
			case .SHA256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
			case .SHA512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
			}
		}
		var digestSize: Int {
			switch self {
			case .None: return 0
			case .SHA256: return Int(CC_SHA256_DIGEST_LENGTH)
			case .SHA512: return Int(CC_SHA512_DIGEST_LENGTH)
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
		let key = try SwKeyStore.getPublicSecKeyFromPEM(pemKey)
		return try encrypt(data, publicKey: key, mode: mode)
	}
	
	static public func decryptData(data: NSData, pemKey: String) throws -> NSData {
		let key = try SwKeyStore.getPrivateSecKeyFromPEM(pemKey)
		return try decrypt(data, privateKey: key)
	}
	
	static private func encrypt(data: NSData, publicKey: SecKey, mode: Mode) throws -> NSData {
		var bufferSize = SecKeyGetBlockSize(publicKey)
		var buffer = [UInt8](count: bufferSize, repeatedValue: 0)
		
		let aesKey = SwCC.generateRandom(mode.aes.keySize)
		let IV = SwCC.generateRandom(mode.block.ivSize)
		let message = getMessageHeader(mode, aesKey: aesKey, IV: IV)
		
		let status = SecKeyEncrypt(publicKey, .OAEP, UnsafePointer<UInt8>(message.bytes), message.length, &buffer, &bufferSize)
		guard status == noErr else {
			throw error("SEM: SecKeyEncrypt failed \(status)")
		}
		
		guard let encrypted = data.encryptAES(aesKey, iv: IV, blockMode: mode.block) else {
			throw error("SEM: encryptAES failed")
		}
		
		let result = NSMutableData(bytes: buffer, length: bufferSize)
		result.appendData(encrypted)
		let hmac = result.hmac(mode.hmac, key: aesKey)
		result.appendData(hmac)
		return result
	}
	
	static private func decrypt(data: NSData, privateKey: SecKey) throws -> NSData {
		let blockSize = SecKeyGetBlockSize(privateKey)
		var bufferSize = blockSize
		var buffer = [UInt8](count: bufferSize, repeatedValue: 0)
		
		let status = SecKeyDecrypt(privateKey, .OAEP, UnsafePointer<UInt8>(data.bytes), bufferSize, &buffer, &bufferSize)
		
		guard status == noErr else {
			throw error("SEM: SecKeyDecrypt failed \(status)")
		}
		guard let (mode, aesKey, iv) = parseMessageHeader(Array(buffer.prefix(bufferSize))) else {
			throw error("SEM: can't parse message header")
		}
		let hmacData = data.subdataWithRange(NSRange(location: 0, length: data.length - mode.hmac.digestSize))
		let aesData = data.subdataWithRange(NSRange(location: blockSize, length: data.length - blockSize - mode.hmac.digestSize))
		let hmac = data.subdataWithRange(NSRange(location: data.length - mode.hmac.digestSize, length:  mode.hmac.digestSize))
		guard hmacData.hmac(mode.hmac, key: aesKey) == hmac else {
			throw error("SEM: invalid message (hmac)")
		}
		guard let decrypted = aesData.decryptAES(aesKey, iv: iv, blockMode: mode.block) else {
			throw error("SEM: decryptAES failed")
		}
		return decrypted
	}
	
	static private func getMessageHeader(mode: Mode, aesKey: NSData, IV: NSData) -> NSData {
		let header : [UInt8] = [mode.aes.rawValue, mode.block.rawValue, mode.hmac.rawValue]
		let message = NSMutableData(bytes: header, length: 3)
		message.appendData(aesKey)
		message.appendData(IV)
		return message
	}
	
	static private func parseMessageHeader(bytes: [UInt8]) -> (Mode, NSData, NSData)? {
		guard bytes.count > 3 else {
			return nil
		}
		guard let aes = AesMode(rawValue:bytes[0]),
			block = BlockMode(rawValue: bytes[1]),
			hmac = HMACMode(rawValue: bytes[2]) else {
				return nil
		}
		let keySize = aes.keySize
		let ivSize = block.ivSize
		guard bytes.count == 3 + keySize + ivSize else {
			return nil
		}
		let key = NSData(bytes: Array(bytes[3..<3+keySize]), length: keySize)
		let iv = NSData(bytes: Array(bytes[3+keySize..<3+keySize+ivSize]), length: ivSize)
			
		return (Mode(aes: aes, block: block, hmac: hmac), key, iv)
	}	
}

public class SwCC {
	public enum OpMode {
		case encrypt, decrypt
		
		var cc: CCOperation {
			switch self {
			case .encrypt: return CCOperation(kCCEncrypt)
			case .decrypt: return CCOperation(kCCDecrypt)
			}
		}
	}
	
	static public func crypt(opMode: OpMode, key: NSData, iv: NSData, blockMode: SEM.BlockMode, data: NSData) -> NSData? {
		var cryptor : CCCryptorRef = nil
		guard kCCSuccess == Int(CCCryptorCreateWithMode(
			opMode.cc, blockMode.cc,
			CCAlgorithm(kCCAlgorithmAES), CCPadding(ccPKCS7Padding),
			iv.bytes, key.bytes, key.length, nil, 0, 0,	CCModeOptions(), &cryptor)) else {
				return nil
		}
		defer {
			CCCryptorRelease(cryptor)
		}
		
		let needed = CCCryptorGetOutputLength(cryptor, data.length, true)
		guard let result = NSMutableData(length: needed) else {
			return nil
		}
		
		var updateLen: size_t = 0
		guard kCCSuccess == Int(CCCryptorUpdate(cryptor, data.bytes, data.length,
			result.mutableBytes, result.length, &updateLen)) else {
				return nil
		}
		
		var finalLen: size_t = 0
		guard kCCSuccess == Int(CCCryptorFinal(cryptor, result.mutableBytes + updateLen,
			result.length - updateLen, &finalLen)) else {
				return nil
		}
		
		result.length = updateLen + finalLen
		return result
	}
	
	static public func generateRandom(size: Int) -> NSData {
		var result = [UInt8](count: size, repeatedValue: 0)
		SecRandomCopyBytes(kSecRandomDefault, size, &result)
		return NSData(bytes: result, length: size)
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
	
	func md5() -> NSData {
		let result = NSMutableData(length: Int(CC_MD5_DIGEST_LENGTH))!
		CC_MD5(bytes, CC_LONG(length), UnsafeMutablePointer<UInt8>(result.mutableBytes))
		return NSData(data: result)
	}
	
	func hmac(algorithm: SEM.HMACMode, key: NSData) -> NSData {
		if algorithm == .None {
			return NSData()
		}
		
		var buffer = [UInt8](count: algorithm.digestSize, repeatedValue: 0)
		CCHmac(algorithm.cc, key.bytes, key.length, self.bytes, self.length, &buffer)
		return NSData(bytes: buffer, length: algorithm.digestSize)
	}

	func encryptAES(key: NSData, iv: NSData, blockMode: SEM.BlockMode) -> NSData? {
		return SwCC.crypt(.encrypt, key: key, iv: iv, blockMode: blockMode, data: self)
	}
	
	func decryptAES(key: NSData, iv: NSData, blockMode: SEM.BlockMode) -> NSData? {
		return SwCC.crypt(.decrypt, key: key, iv: iv, blockMode: blockMode, data: self)
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

