import Foundation

public class SwKeyStore {

	enum SecError : OSStatus, ErrorType {
		case Unimplemented = -4
		case Param = -50
		case Allocate = -108
		case NotAvailable = -25291
		case AuthFailed = -25293
		case DuplicateItem = -25299
		case ItemNotFound = -25300
		case InteractionNotAllowed = -25308
		case Decode = -26275
		init(_ status: OSStatus, function: String = #function, file: String = #file, line: Int = #line) {
			self = SecError(rawValue: status)!
			print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
		}
		init(_ type: SecError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
		}
	}
	
	public static func upsertKey(pemKey: String, keyTag: String,
	                             options: [NSString : AnyObject] = [:]) throws {
		let pemKeyAsData = pemKey.dataUsingEncoding(NSUTF8StringEncoding)!
		
		var parameters :[NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrIsPermanent: true,
			kSecAttrApplicationTag: keyTag,
			kSecValueData: pemKeyAsData
		]
		options.forEach { k, v in
			parameters[k] = v
		}
		
		var status = SecItemAdd(parameters, nil)
		if status == errSecDuplicateItem {
			try delKey(keyTag)
			status = SecItemAdd(parameters, nil)
		}
		guard status == errSecSuccess else { throw SecError(status) }
	}
	
	public static func getKey(keyTag: String) throws -> String {
		let parameters: [NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag : keyTag,
			kSecReturnData : true
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters, &data)
		guard status == errSecSuccess else { throw SecError(status) }
		
		guard let pemKeyAsData = data as? NSData else {
			throw SecError(.Decode)
		}
		guard let result = String(data: pemKeyAsData, encoding: NSUTF8StringEncoding) else {
			throw SecError(.Decode)
		}
		return result
	}
	
	public static func delKey(keyTag: String) throws {
		let parameters: [NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrApplicationTag: keyTag
		]
		let status = SecItemDelete(parameters)
		guard status == errSecSuccess else { throw SecError(status) }
	}
}

public class SwKeyConvert {
	
	public enum Error : ErrorType {
		case InvalidKey
		case BadPassphrase
		init(_ type: Error, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self)")
		}
	}
	
	public class PrivateKey {
	
		public static func pemToPKCS1DER(pemKey: String) throws -> NSData {
			do {
				let derKey = try PEM.PrivateKey.toDER(pemKey)
				return try PKCS8.PrivateKey.stripHeaderIfAny(derKey)
			}
			catch { throw Error(.InvalidKey) }
		}
		
		public static func derToPKCS1PEM(derKey: NSData) -> String {
			return PEM.PrivateKey.toPEM(derKey)
		}
		
		public typealias EncMode = PEM.EncryptedPrivateKey.EncMode
		
		public static func encryptPEM(pemKey: String, passphrase: String, mode: EncMode) throws -> String {
			do {
				let derKey = try PEM.PrivateKey.toDER(pemKey)
				return PEM.EncryptedPrivateKey.toPEM(derKey, passphrase: passphrase, mode: mode)
			}
			catch { throw Error(.InvalidKey) }
		}
		
		public static func decryptPEM(pemKey: String, passphrase: String) throws -> String {
			do {
				let derKey = try PEM.EncryptedPrivateKey.toDER(pemKey, passphrase: passphrase)
				return PEM.PrivateKey.toPEM(derKey)
			}
			catch PEM.Error.BadPassphrase { throw Error(.BadPassphrase) }
			catch { throw Error(.InvalidKey) }
		}
	}

	public class PublicKey {
	
		public static func pemToPKCS1DER(pemKey: String) throws -> NSData {
			do {
				let derKey = try PEM.PublicKey.toDER(pemKey)
				return try PKCS8.PublicKey.stripHeaderIfAny(derKey)
			}
			catch { throw Error(.InvalidKey) }
		}
	
		public static func derToPKCS1PEM(derKey: NSData) -> String {
			return PEM.PublicKey.toPEM(derKey)
		}
		
		public static func derToPKCS8PEM(derKey: NSData) -> String {
			let pkcs8Key = PKCS8.PublicKey.addHeader(derKey)
			return PEM.PublicKey.toPEM(pkcs8Key)
		}
		
	}

}

public class PKCS8 {
	
	public enum Error : ErrorType {
		case ASN1Parse
		case OIDMismatch
		init(_ type: Error, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self)")
		}
	}
	
	public class PrivateKey {
		
		//https://lapo.it/asn1js/
		public static func stripHeaderIfAny(derKey: NSData) throws -> NSData {
			let bytes = derKey.arrayOfBytes()
			
			var offset = 0
			guard bytes[offset] == 0x30 else {
				throw Error(.ASN1Parse)
			}
			offset += 1
			
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1
			
			guard bytes[offset] == 0x02 else {
				throw Error(.ASN1Parse)
			}
			offset += 3
			
			//without PKCS8 header
			if bytes[offset] == 0x02 {
				return derKey
			}
			
			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
			let slice: [UInt8] = Array(bytes[offset..<(offset + OID.count)])
			
			guard slice == OID else {
				throw Error(.OIDMismatch)
			}
			
			offset += OID.count
			guard bytes[offset] == 0x04 else {
				throw Error(.ASN1Parse)
			}
			
			offset += 1
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1
			
			guard bytes[offset] == 0x30 else {
				throw Error(.ASN1Parse)
			}
			
			return derKey.subdataWithRange(NSRange(location: offset, length: derKey.length - offset))
		}
		
		public static func hasCorrectHeader(derKey: NSData) -> Bool {
			return (try? stripHeaderIfAny(derKey)) != nil
		}
	}
	
	public class PublicKey {
		
		public static func addHeader(derKey: NSData) -> NSData {
			let result = NSMutableData()
			
			let encodingLength: Int = encodedOctets(derKey.length + 1).count
			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
			
			var builder: [UInt8] = []
			
			// ASN.1 SEQUENCE
			builder.append(0x30)
			
			// Overall size, made of OID + bitstring encoding + actual key
			let size = OID.count + 2 + encodingLength + derKey.length
			let encodedSize = encodedOctets(size)
			builder.appendContentsOf(encodedSize)
			result.appendBytes(builder, length: builder.count)
			result.appendBytes(OID, length: OID.count)
			builder.removeAll(keepCapacity: false)
			
			builder.append(0x03)
			builder.appendContentsOf(encodedOctets(derKey.length + 1))
			builder.append(0x00)
			result.appendBytes(builder, length: builder.count)
			
			// Actual key bytes
			result.appendData(derKey)
			
			return result as NSData
		}
		
		//https://lapo.it/asn1js/
		public static func stripHeaderIfAny(derKey: NSData) throws -> NSData {
			let bytes = derKey.arrayOfBytes()
			
			var offset = 0
			guard bytes[offset] == 0x30 else {
				throw Error(.ASN1Parse)
			}
			
			offset += 1
			
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1
			
			//without PKCS8 header
			if bytes[offset] == 0x02 {
				return derKey
			}
			
			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
			let slice: [UInt8] = Array(bytes[offset..<(offset + OID.count)])
			
			guard slice == OID else {
				throw Error(.OIDMismatch)
			}
			
			offset += OID.count
			
			// Type
			guard bytes[offset] == 0x03 else {
				throw Error(.ASN1Parse)
			}
			
			offset += 1
			
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1
			
			// Contents should be separated by a null from the header
			guard bytes[offset] == 0x00 else {
				throw Error(.ASN1Parse)
			}
			
			offset += 1
			return derKey.subdataWithRange(NSRange(location: offset, length: derKey.length - offset))
		}
		
		public static func hasCorrectHeader(derKey: NSData) -> Bool {
			return (try? stripHeaderIfAny(derKey)) != nil
		}
		
		private static func encodedOctets(int: Int) -> [UInt8] {
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
}

public class PEM {
	
	public enum Error : ErrorType {
		case HeaderParse
		case Base64Decode
		case EncModeParse
		case IVParse
		case BadPassphrase
		init(_ type: Error, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self)")
		}
	}
	
	public class PrivateKey {
		
		public static func toDER(pemKey: String) throws -> NSData {
			guard let strippedKey = stripHeader(pemKey) else {
				throw Error(.HeaderParse)
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw Error(.Base64Decode)
			}
			return data
		}
		
		public static func toPEM(derKey: NSData) -> String {
			let base64 = derKey.base64EncodedStringWithOptions(
				[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
			return addRSAHeader(base64)
		}
		
		private static let Prefix = "-----BEGIN PRIVATE KEY-----\n"
		private static let Suffix = "\n-----END PRIVATE KEY-----"
		private static let RSAPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
		private static let RSASuffix = "\n-----END RSA PRIVATE KEY-----"
		
		private static func addHeader(base64: String) -> String {
			return Prefix + base64 + Suffix
		}
		
		private static func addRSAHeader(base64: String) -> String {
			return RSAPrefix + base64 + RSASuffix
		}
		
		private static func stripHeader(pemKey: String) -> String? {
			return PEM.stripHeaderFooter(pemKey, header: Prefix, footer: Suffix) ??
				PEM.stripHeaderFooter(pemKey, header: RSAPrefix, footer: RSASuffix)
		}
	}
	
	public class PublicKey {
		
		public static func toDER(pemKey: String) throws -> NSData {
			guard let strippedKey = stripHeader(pemKey) else {
				throw Error(.HeaderParse)
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw Error(.Base64Decode)
			}
			return data
		}
		
		public static func toPEM(derKey: NSData) -> String {
			let base64 = derKey.base64EncodedStringWithOptions(
				[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
			return addHeader(base64)
		}
		
		private static let PEMPrefix = "-----BEGIN PUBLIC KEY-----\n"
		private static let PEMSuffix = "\n-----END PUBLIC KEY-----"
		
		private static func addHeader(base64: String) -> String {
			return PEMPrefix + base64 + PEMSuffix
		}
		
		private static func stripHeader(pemKey: String) -> String? {
			return PEM.stripHeaderFooter(pemKey, header: PEMPrefix, footer: PEMSuffix)
		}
	}
	
	public class EncryptedPrivateKey {

		public enum EncMode {
			case AES128CBC, AES256CBC
		}
		
		public static func toDER(pemKey: String, passphrase: String) throws -> NSData {
			guard let strippedKey = PrivateKey.stripHeader(pemKey) else {
				throw Error(.HeaderParse)
			}
			guard let mode = getEncMode(strippedKey) else {
				throw Error(.EncModeParse)
			}
			guard let iv = getIV(strippedKey) else {
				throw Error(.IVParse)
			}
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
			let base64Data = strippedKey.substringFromIndex(strippedKey.startIndex + AESHeaderLength)
			guard let data = PEM.base64Decode(base64Data) else {
				throw Error(.Base64Decode)
			}
			guard let decrypted = decryptKey(data, key: aesKey, iv: iv) else {
				throw Error(.BadPassphrase)
			}
			guard PKCS8.PrivateKey.hasCorrectHeader(decrypted) else {
				throw Error(.BadPassphrase)
			}
			return decrypted
		}
		
		public static func toPEM(derKey: NSData, passphrase: String, mode: EncMode) -> String {
			let iv = CC.generateRandom(16)
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
			let encrypted = encryptKey(derKey, key: aesKey, iv: iv)
			let encryptedDERKey = addEncryptHeader(encrypted, iv: iv, mode: mode)
			return PrivateKey.addRSAHeader(encryptedDERKey)
		}
		
		private static let AES128CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,"
		private static let AES256CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
		private static let AESInfoLength = AES128CBCInfo.characters.count
		private static let AESIVInHexLength = 32
		private static let AESHeaderLength = AESInfoLength + AESIVInHexLength
	
		private static func addEncryptHeader(key: NSData, iv: NSData, mode: EncMode) -> String {
			return getHeader(mode) + iv.hexadecimalString() + "\n\n" +
				key.base64EncodedStringWithOptions(
					[.Encoding64CharacterLineLength,.EncodingEndLineWithLineFeed])
		}
		
		private static func getHeader(mode: EncMode) -> String {
			switch mode {
			case .AES128CBC: return AES128CBCInfo
			case .AES256CBC: return AES256CBCInfo
			}
		}
		
		private static func getEncMode(strippedKey: String) -> EncMode? {
			if strippedKey.hasPrefix(AES128CBCInfo) {
				return .AES128CBC
			}
			if strippedKey.hasPrefix(AES256CBCInfo) {
				return .AES256CBC
			}
			return nil
		}
		
		private static func getIV(strippedKey: String) -> NSData? {
			let ivInHex = strippedKey.substringWithRange(strippedKey.startIndex+AESInfoLength..<strippedKey.startIndex+AESHeaderLength)
			return  ivInHex.dataFromHexadecimalString()
		}
		
		private static func getAESKey(mode: EncMode, passphrase: String, iv: NSData) -> NSData {
			switch(mode) {
			case .AES128CBC: return getAES128Key(passphrase, iv: iv)
			case .AES256CBC: return getAES256Key(passphrase, iv: iv)
			}
		}
		
		private static func getAES128Key(passphrase: String, iv: NSData) -> NSData {
			//128bit_Key = MD5(Passphrase + Salt)
			let pass = passphrase.dataUsingEncoding(NSUTF8StringEncoding)!
			let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
			
			let key = NSMutableData(data: pass)
			key.appendData(salt)
			return CC.digest(key, alg: .MD5)
		}
		
		private static func getAES256Key(passphrase: String, iv: NSData) -> NSData {
			//128bit_Key = MD5(Passphrase + Salt)
			//256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)
			let pass = passphrase.dataUsingEncoding(NSUTF8StringEncoding)!
			let salt = iv.subdataWithRange(NSRange(location: 0, length: 8))
			
			let first = NSMutableData(data: pass)
			first.appendData(salt)
			let aes128Key = CC.digest(first, alg: .MD5)
			
			let sec = NSMutableData(data: aes128Key)
			sec.appendData(pass)
			sec.appendData(salt)
			
			let aes256Key = NSMutableData(data: aes128Key)
			aes256Key.appendData(CC.digest(sec, alg: .MD5))
			return aes256Key
		}
		
		private static func encryptKey(data: NSData, key: NSData, iv:NSData) -> NSData {
			return try! CC.crypt(
				.encrypt, blockMode: .CBC, algorithm: .AES, padding: .PKCS7Padding,
				data: data, key: key, iv: iv)
		}
		
		private static func decryptKey(data: NSData, key: NSData, iv: NSData) -> NSData? {
			return try? CC.crypt(.decrypt, blockMode: .CBC, algorithm: .AES, padding: .PKCS7Padding,
			                     data: data, key: key, iv: iv)
		}
		
	}
	
	private static func stripHeaderFooter(data: String, header: String, footer: String) -> String? {
		guard data.hasPrefix(header) else {
			return nil
		}
		guard let r = data.rangeOfString(footer) else {
			return nil
		}
		return data.substringWithRange(header.endIndex..<r.startIndex)
	}
	
	private static func base64Decode(base64Data: String) -> NSData? {
		return NSData(base64EncodedString: base64Data, options: [.IgnoreUnknownCharacters])
	}
	
}

//Simple Encrypted Message
public class SEM {
	
	public enum Error : ErrorType {
		case Parse
		case UnsupportedVersion
		case InvalidKey
		case Decode
		init(_ type: Error, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self)")
		}
	}
	
	public enum AESMode : UInt8 {
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
		case CBC_SHA256, GCM
		
		var ivSize: Int {
			switch self {
			case .CBC_SHA256: return 16
			case .GCM: return 12
			}
		}
	}
	
	public struct Mode {
		let version : UInt8 = 0
		let aes: AESMode
		let block: BlockMode
		public init() {
			aes = .AES256
			block = .CBC_SHA256
		}
		public init(aes: AESMode, block: BlockMode) {
			self.aes = aes
			self.block = block
		}
	}
	
	public static func encryptMessage(message: String, pemKey: String, mode: Mode) throws -> String {
		let data = message.dataUsingEncoding(NSUTF8StringEncoding)!
		let encryptedData = try encryptData(data, pemKey: pemKey, mode: mode)
		return encryptedData.base64EncodedStringWithOptions([])
	}
	
	public static func decryptMessage(message: String, pemKey: String) throws -> String {
		guard let data = NSData(base64EncodedString: message, options: []) else {
			throw Error(.Parse)
		}
		let decryptedData = try decryptData(data, pemKey: pemKey)
		guard let decryptedString = String(data: decryptedData, encoding: NSUTF8StringEncoding) else {
			throw Error(.Parse)
		}
		return decryptedString
	}
	
	public static func encryptData(data: NSData, pemKey: String, mode: Mode) throws -> NSData {
		let aesKey = CC.generateRandom(mode.aes.keySize)
		let iv = CC.generateRandom(mode.block.ivSize)
		let header = getMessageHeader(mode, aesKey: aesKey, iv: iv)
		let derKey = try publicPEMToDER(pemKey)
		
		let encryptedHeader = encryptHeader(header, derKey: derKey)
		let encryptedData = try! cryptAuth(.encrypt, blockMode: mode.block, data: data, aData: encryptedHeader, key: aesKey, iv: iv)
		
		let result = NSMutableData(data: encryptedHeader)
		result.appendData(encryptedData)
		return result
	}
	
	
	public static func decryptData(data: NSData, pemKey: String) throws -> NSData {
		let derKey = try privatePEMToDER(pemKey)
		let (header, tail) =  try decryptHeader(data, derKey: derKey)
		let (mode, aesKey, iv) = try parseMessageHeader(header)
		
		let encryptedHeader = data.subdataWithRange(
			NSRange(location:0, length: data.length - tail.length))
		let encryptedData = tail
		return try cryptAuth(.decrypt, blockMode: mode.block, data: encryptedData, aData: encryptedHeader, key: aesKey, iv: iv)
	}
	
	private static func encryptHeader(data: NSData, derKey: NSData) -> NSData {
		return try! CC.RSA.encrypt(data, derKey: derKey, tag: NSData(), padding: .OAEP, digest: .SHA1)
	}
	
	private static func decryptHeader(data: NSData, derKey: NSData) throws -> (NSData, NSData) {
		do {
			let (header, blockSize) = try CC.RSA.decrypt(data, derKey: derKey,
			                                             tag: NSData(), padding: .OAEP, digest: .SHA1)
			
			let tail = data.subdataWithRange(NSRange(location: blockSize, length: data.length - blockSize))
			
			return (header, tail)
		}
		catch _ as CC.CCError { throw Error(.Decode) }
	}
	
	private static func cryptAuth(opMode: CC.OpMode, blockMode: BlockMode, data: NSData, aData: NSData,
	                      key: NSData, iv: NSData) throws -> NSData {
		do {
			if blockMode == .CBC_SHA256 {
				return try cryptAuth(opMode, blockMode: .CBC, hmacAlg: .SHA256,
				                     data: data, aData: aData, key: key, iv:iv)
			}
			else /* GCM */ {
				return try CC.cryptAuth(opMode, blockMode: .GCM, algorithm: .AES,
				                        data: data, aData: aData,
				                        key: key, iv: iv, tagLength: 16)
			}
		}
		catch _ as CC.CCError { throw Error(.Decode) }
	}
	
	private static func cryptAuth(opMode: CC.OpMode, blockMode: CC.BlockMode, hmacAlg: CC.HMACAlg,
	                      data: NSData, aData: NSData, key: NSData, iv:NSData) throws -> NSData {
		if opMode == .encrypt {
			//encrypt then mac
			let encryptedData = try! CC.crypt(.encrypt, blockMode: blockMode,
			                                 algorithm: .AES, padding: .PKCS7Padding,
			                                 data: data, key: key, iv: iv)
			let macData = NSMutableData(data: aData)
			macData.appendData(encryptedData)
			let hmac = CC.HMAC(macData, alg: hmacAlg, key: key)
			let result = NSMutableData(data: encryptedData)
			result.appendData(hmac)
			return result
		}
		else {
			let encryptedData = data.subdataWithRange(NSRange(location:0, length: data.length - hmacAlg.digestLength))
			let macData = NSMutableData(data: aData)
			macData.appendData(encryptedData)
			
			let hmac = data.subdataWithRange(NSRange(location: data.length - hmacAlg.digestLength, length: hmacAlg.digestLength))
			
			guard CC.HMAC(macData, alg: hmacAlg, key: key) == hmac else {
				throw CC.CCError(.DecodeError)
			}
			return try CC.crypt(.decrypt, blockMode: blockMode,
			                                 algorithm: .AES, padding: .PKCS7Padding,
			                                 data: encryptedData, key: key, iv: iv)
		}
	}
	
	private static func getMessageHeader(mode: Mode, aesKey: NSData, iv: NSData) -> NSData {
		let header : [UInt8] = [mode.version, mode.aes.rawValue, mode.block.rawValue]
		let message = NSMutableData(bytes: header, length: 3)
		message.appendData(aesKey)
		message.appendData(iv)
		return message
	}
	
	private static func parseMessageHeader(header: NSData) throws -> (Mode, NSData, NSData) {
		guard header.length > 3 else {
			throw Error(.Parse)
		}
		let bytes = header.arrayOfBytes()
		let version = bytes[0]
		guard version == 0 else {
			throw Error(.UnsupportedVersion)
		}
		guard let aes = AESMode(rawValue: bytes[1]) else {
			throw Error(.Parse)
		}
		guard let block = BlockMode(rawValue: bytes[2]) else {
			throw Error(.Parse)
		}
		let keySize = aes.keySize
		let ivSize = block.ivSize
		guard header.length == 3 + keySize + ivSize else {
			throw Error(.Parse)
		}
		let key = header.subdataWithRange(NSRange(location: 3, length: keySize))
		let iv = header.subdataWithRange(NSRange(location: 3 + keySize, length: ivSize))
		
		return (Mode(aes: aes, block: block), key, iv)
	}
	
	private static func privatePEMToDER(pemKey: String) throws -> NSData {
		do { return try SwKeyConvert.PrivateKey.pemToPKCS1DER(pemKey) }
		catch { throw Error(.InvalidKey) }
	}
	
	private static func publicPEMToDER(pemKey: String) throws -> NSData {
		do { return try SwKeyConvert.PublicKey.pemToPKCS1DER(pemKey) }
		catch { throw Error(.InvalidKey) }
	}
	
}

//Simple Message Sign and Verify
public class SMSV {
	
	public enum Error : ErrorType {
		case InvalidKey
		case ParseMessage
		init(_ type: Error, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self)")
		}
	}
	
	public static func sign(message: String, pemKey: String) throws -> String {
		let data = message.dataUsingEncoding(NSUTF8StringEncoding)!
		let signedData = try signData(data, pemKey: pemKey)
		return signedData.base64EncodedStringWithOptions([])
	}
	
	public static func signData(data: NSData, pemKey: String) throws -> NSData {
		let derKey = try privatePEMToDER(pemKey)
		let hash = CC.digest(data, alg: .SHA512)
		return try! CC.RSA.sign(hash, derKey: derKey, padding: .OAEP, digest: .SHA512)
	}
	
	public static func verify(message: String, pemKey: String, sign: String) throws -> Bool {
		let data = message.dataUsingEncoding(NSUTF8StringEncoding)!
		guard let signData = NSData(base64EncodedString: sign, options: []) else {
			throw Error(.ParseMessage)
		}
		return try verifyData(data, pemKey: pemKey, signData: signData)
	}
	
	public static func verifyData(data: NSData, pemKey: String, signData: NSData) throws -> Bool {
		let derKey = try publicPEMToDER(pemKey)
		let hash = CC.digest(data, alg: .SHA512)
		return try! CC.RSA.verify(
			hash, derKey: derKey, padding: .OAEP, digest: .SHA512, signedData: signData)
	}
	
	private static func privatePEMToDER(pemKey: String) throws -> NSData {
		do { return try SwKeyConvert.PrivateKey.pemToPKCS1DER(pemKey) }
		catch { throw Error(.InvalidKey) }
	}
	
	private static func publicPEMToDER(pemKey: String) throws -> NSData {
		do { return try SwKeyConvert.PublicKey.pemToPKCS1DER(pemKey) }
		catch { throw Error(.InvalidKey) }
	}
}


public class CC {

	public typealias CCCryptorStatus = Int32;
	public enum CCError : CCCryptorStatus, ErrorType {
		case ParamError = -4300
		case BufferTooSmall = -4301
		case MemoryFailure = -4302
		case AlignmentError = -4303
		case DecodeError = -4304
		case Unimplemented = -4305
		case Overflow = -4306
		case RNGFailure = -4307
		init(_ status: CCCryptorStatus, function: String = #function,
		       file: String = #file, line: Int = #line) {
			self = CCError(rawValue: status)!
			print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
		}
		init(_ type: CCError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
		}
	}
	
	public static func generateRandom(size: Int) -> NSData {
		let data = NSMutableData(length: size)!
		CCRandomGenerateBytes!(bytes: data.mutableBytes, count: size)
		return data
	}
	
	public typealias CCDigestAlgorithm = UInt32
	public enum DigestAlgorithm : CCDigestAlgorithm {
		case None = 0
		case MD5 = 3
		case RMD128 = 4, RMD160 = 5, RMD256 = 6, RMD320 = 7
		case SHA1 = 8
		case SHA224 = 9, SHA256 = 10, SHA384 = 11, SHA512 = 12
	}
	
	public static func digest(data: NSData, alg: DigestAlgorithm) -> NSData {
		let output = NSMutableData(length: CCDigestGetOutputSize!(algorithm: alg.rawValue))!
		CCDigest!(algorithm: alg.rawValue,
		          data: data.bytes,
		          dataLen: data.length,
		          output: output.mutableBytes)
		return output
	}
	
	public typealias CCHmacAlgorithm = UInt32
	public enum HMACAlg : CCHmacAlgorithm {
		case SHA1, MD5, SHA256, SHA384, SHA512, SHA224
		
		var digestLength: Int {
			switch self {
			case .SHA1: return 20
			case .MD5: return 16
			case .SHA256: return 32
			case .SHA384: return 48
			case .SHA512: return 64
			case .SHA224: return 28
			}
		}
	}

	public static func HMAC(data: NSData, alg: HMACAlg, key: NSData) -> NSData {
		let buffer = NSMutableData(length: alg.digestLength)!
		CCHmac!(algorithm: alg.rawValue,
		       key: key.bytes, keyLength: key.length,
		       data: data.bytes, dataLength: data.length,
		       macOut: buffer.mutableBytes)
		return buffer
	}
	
	public typealias CCOperation = UInt32
	public enum OpMode : CCOperation{
		case encrypt = 0, decrypt
	}
	
	public typealias CCMode = UInt32
	public enum BlockMode : CCMode {
		case ECB = 1, CBC, CFB, CTR, F8, LRW, OFB, XTS, RC4, CFB8
	}
	
	public enum AuthBlockMode : CCMode {
		case GCM = 11, CCM
	}
	
	public typealias CCAlgorithm = UInt32
	public enum Algorithm : CCAlgorithm {
		case AES = 0, mDES, _3DES, CAST, RC4, RC2, Blowfish
	}
	
	public typealias CCPadding = UInt32
	public enum Padding : CCPadding {
		case NoPadding = 0, PKCS7Padding
	}
	
	public static func crypt(opMode: OpMode, blockMode: BlockMode,
	                            algorithm: Algorithm, padding: Padding,
	                            data: NSData, key: NSData, iv: NSData) throws -> NSData {
		var cryptor : CCCryptorRef = nil
		var status = CCCryptorCreateWithMode!(
			op: opMode.rawValue, mode: blockMode.rawValue,
			alg: algorithm.rawValue, padding: padding.rawValue,
			iv: iv.bytes, key: key.bytes, keyLength: key.length,
			tweak: nil, tweakLength: 0, numRounds: 0,
			options: CCModeOptions(), cryptorRef: &cryptor)
		guard status == noErr else { throw CCError(status) }

		defer { CCCryptorRelease!(cryptorRef: cryptor) }
		
		let needed = CCCryptorGetOutputLength!(cryptorRef: cryptor, inputLength: data.length, final: true)
		let result = NSMutableData(length: needed)!
		var updateLen: size_t = 0
		status = CCCryptorUpdate!(
			cryptorRef: cryptor,
			dataIn: data.bytes, dataInLength: data.length,
			dataOut: result.mutableBytes, dataOutAvailable: result.length,
			dataOutMoved: &updateLen)
		guard status == noErr else { throw CCError(status) }

		
		var finalLen: size_t = 0
		status = CCCryptorFinal!(
			cryptorRef: cryptor,
			dataOut: result.mutableBytes + updateLen,
			dataOutAvailable: result.length - updateLen,
			dataOutMoved: &finalLen)
		guard status == noErr else { throw CCError(status) }

		
		result.length = updateLen + finalLen
		return result
	}
	
	//The same behaviour as in the CCM pdf
	//http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
	public static func cryptAuth(opMode: OpMode, blockMode: AuthBlockMode, algorithm: Algorithm,
	                             data: NSData, aData: NSData,
	                             key: NSData, iv: NSData, tagLength: Int) throws -> NSData {
		let cryptFun = blockMode == .GCM ? GCM.crypt : CCM.crypt
		if opMode == .encrypt {
			let (cipher, tag) = try cryptFun(opMode, algorithm: algorithm, data: data, key: key, iv: iv, aData: aData, tagLength: tagLength)
			let result = NSMutableData(data: cipher)
			result.appendData(tag)
			return result
		}
		else {
			let cipher = data.subdataWithRange(NSRange(location:0, length:data.length - tagLength))
			let tag = data.subdataWithRange(
				NSRange(location:data.length - tagLength, length: tagLength))
			let (plain, vTag) = try cryptFun(opMode, algorithm: algorithm, data: cipher, key: key, iv: iv, aData: aData, tagLength: tagLength)
			guard tag == vTag else {
				throw CCError(.DecodeError)
			}
			return plain
		}
	}
	
	public static func digestAvailable() -> Bool {
		return CCDigest != nil &&
			CCDigestGetOutputSize != nil
	}

	public static func randomAvailable() -> Bool {
		return CCRandomGenerateBytes != nil
	}
	
	public static func hmacAvailable() -> Bool {
		return CCHmac != nil
	}
	
	public static func cryptorAvailable() -> Bool {
		return CCCryptorCreateWithMode != nil &&
			CCCryptorGetOutputLength != nil &&
			CCCryptorUpdate != nil &&
			CCCryptorFinal != nil &&
			CCCryptorRelease != nil
	}
	
	public static func available() -> Bool {
		return digestAvailable() &&
			randomAvailable() &&
			hmacAvailable() &&
			cryptorAvailable() &&
			KeyDerivation.available() &&
			KeyWrap.available() &&
			RSA.available() &&
			DH.available() &&
			EC.available() &&
			GCM.available() &&
			CCM.available()
	}
	
	private typealias CCCryptorRef = UnsafePointer<Void>
	private typealias CCRNGStatus = CCCryptorStatus
	private typealias CC_LONG = UInt32
	private typealias CCModeOptions = UInt32
	
	private typealias CCRandomGenerateBytesT = @convention(c) (
		bytes: UnsafeMutablePointer<Void>,
		count: size_t) -> CCRNGStatus
	private typealias CCDigestGetOutputSizeT = @convention(c) (
		algorithm: CCDigestAlgorithm) -> size_t
	private typealias CCDigestT = @convention(c) (
		algorithm: CCDigestAlgorithm,
		data: UnsafePointer<Void>,
		dataLen: size_t,
		output: UnsafeMutablePointer<Void>) -> CInt

	private typealias CCHmacT = @convention(c) (
		algorithm: CCHmacAlgorithm,
		key: UnsafePointer<Void>,
		keyLength: Int,
		data: UnsafePointer<Void>,
		dataLength: Int,
		macOut: UnsafeMutablePointer<Void>) -> Void
	private typealias CCCryptorCreateWithModeT = @convention(c)(
		op: CCOperation,
		mode: CCMode,
		alg: CCAlgorithm,
		padding: CCPadding,
		iv: UnsafePointer<Void>,
		key: UnsafePointer<Void>, keyLength: Int,
		tweak: UnsafePointer<Void>, tweakLength: Int,
		numRounds: Int32, options: CCModeOptions,
		cryptorRef: UnsafeMutablePointer<CCCryptorRef>) -> CCCryptorStatus
	private typealias CCCryptorGetOutputLengthT = @convention(c)(
		cryptorRef: CCCryptorRef,
		inputLength: size_t,
		final: Bool) -> size_t
	private typealias CCCryptorUpdateT = @convention(c)(
		cryptorRef: CCCryptorRef,
		dataIn: UnsafePointer<Void>,
		dataInLength: Int,
		dataOut: UnsafeMutablePointer<Void>,
		dataOutAvailable: Int,
		dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	private typealias CCCryptorFinalT = @convention(c)(
		cryptorRef: CCCryptorRef,
		dataOut: UnsafeMutablePointer<Void>,
		dataOutAvailable: Int,
		dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	private typealias CCCryptorReleaseT = @convention(c)
		(cryptorRef: CCCryptorRef) -> CCCryptorStatus

	
	private static let dl = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW)
	private static let CCRandomGenerateBytes : CCRandomGenerateBytesT? =
		getFunc(dl, f: "CCRandomGenerateBytes")
	private static let CCDigestGetOutputSize : CCDigestGetOutputSizeT? =
		getFunc(dl, f: "CCDigestGetOutputSize")
	private static let CCDigest : CCDigestT? = getFunc(dl, f: "CCDigest")
	private static let CCHmac : CCHmacT? = getFunc(dl, f: "CCHmac")
	private static let CCCryptorCreateWithMode : CCCryptorCreateWithModeT? =
		getFunc(dl, f: "CCCryptorCreateWithMode")
	private static let CCCryptorGetOutputLength : CCCryptorGetOutputLengthT? =
		getFunc(dl, f: "CCCryptorGetOutputLength")
	private static let CCCryptorUpdate : CCCryptorUpdateT? =
		getFunc(dl, f: "CCCryptorUpdate")
	private static let CCCryptorFinal : CCCryptorFinalT? =
		getFunc(dl, f: "CCCryptorFinal")
	private static let CCCryptorRelease : CCCryptorReleaseT? =
		getFunc(dl, f: "CCCryptorRelease")
	
	public class GCM {
		
		public static func crypt(opMode: OpMode, algorithm: Algorithm, data: NSData,
		                         key: NSData, iv: NSData,
		                         aData: NSData, tagLength: Int) throws -> (NSData, NSData) {
			let result = NSMutableData(length: data.length)!
			var tagLength_ = tagLength
			let tag = NSMutableData(length: tagLength)!
			let status = CCCryptorGCM!(op: opMode.rawValue, alg: algorithm.rawValue,
				key: key.bytes, keyLength: key.length, iv: iv.bytes, ivLen: iv.length,
				aData: aData.bytes, aDataLen: aData.length,
				dataIn: data.bytes, dataInLength: data.length,
				dataOut: result.mutableBytes, tag: tag.bytes, tagLength: &tagLength_)
			guard status == noErr else { throw CCError(status) }

			tag.length = tagLength_
			return (result, tag)
		}
		
		public static func available() -> Bool {
			if CCCryptorGCM != nil {
				return true
			}
			return false
		}
		
		private typealias CCCryptorGCMT = @convention(c) (op: CCOperation, alg: CCAlgorithm, key: UnsafePointer<Void>, keyLength: Int, iv: UnsafePointer<Void>, ivLen: Int, aData: UnsafePointer<Void>, aDataLen: Int, dataIn: UnsafePointer<Void>, dataInLength: Int, dataOut: UnsafeMutablePointer<Void>, tag: UnsafePointer<Void>, tagLength: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		private static let CCCryptorGCM : CCCryptorGCMT? = getFunc(dl, f: "CCCryptorGCM")
		
	}
	
	public class CCM {
		
		public static func crypt(opMode: OpMode, algorithm: Algorithm, data: NSData,
		                         key: NSData, iv: NSData,
		                         aData: NSData, tagLength: Int) throws -> (NSData, NSData) {
			var cryptor : CCCryptorRef = nil
			var status = CCCryptorCreateWithMode!(
				op: opMode.rawValue, mode: AuthBlockMode.CCM.rawValue,
				alg: algorithm.rawValue, padding: Padding.NoPadding.rawValue,
				iv: nil, key: key.bytes, keyLength: key.length,
				tweak: nil, tweakLength: 0, numRounds: 0,
				options: CCModeOptions(), cryptorRef: &cryptor)
			guard status == noErr else { throw CCError(status) }
			defer { CCCryptorRelease!(cryptorRef: cryptor) }

			status = CCCryptorAddParameter!(cryptorRef: cryptor,
				parameter: Parameter.dataSize.rawValue,
				data: nil, dataLength: data.length)
			guard status == noErr else { throw CCError(status) }


			status = CCCryptorAddParameter!(cryptorRef: cryptor,
				parameter: Parameter.macSize.rawValue,
				data: nil, dataLength: tagLength)
			guard status == noErr else { throw CCError(status) }

			
			status = CCCryptorAddParameter!(cryptorRef: cryptor,
				parameter: Parameter.iv.rawValue,
				data: iv.bytes, dataLength: iv.length)
			guard status == noErr else { throw CCError(status) }

			
			status = CCCryptorAddParameter!(cryptorRef: cryptor,
				parameter: Parameter.authData.rawValue,
				data: aData.bytes, dataLength: aData.length)
			guard status == noErr else { throw CCError(status) }


			let result = NSMutableData(length: data.length)!

			var updateLen: size_t = 0
			status = CCCryptorUpdate!(
				cryptorRef: cryptor,
				dataIn: data.bytes, dataInLength: data.length,
				dataOut: result.mutableBytes, dataOutAvailable: result.length,
				dataOutMoved: &updateLen)
			guard status == noErr else { throw CCError(status) }

			var finalLen: size_t = 0
			status = CCCryptorFinal!(
				cryptorRef: cryptor,
				dataOut: result.mutableBytes + updateLen,
				dataOutAvailable: result.length - updateLen,
				dataOutMoved: &finalLen)
			guard status == noErr else { throw CCError(status) }

			result.length = updateLen + finalLen
			
			var tagLength_ = tagLength
			let tag = NSMutableData(length: tagLength)!
			status = CCCryptorGetParameter!(cryptorRef: cryptor,
				parameter: Parameter.authTag.rawValue,
				data: tag.bytes, dataLength: &tagLength_)
			guard status == noErr else { throw CCError(status) }

			tag.length = tagLength_
			
			return (result, tag)
		}
		
		public static func available() -> Bool {
			if CCCryptorAddParameter != nil &&
				CCCryptorGetParameter != nil {
				return true
			}
			return false
		}
		
		private typealias CCParameter = UInt32
		private enum Parameter : CCParameter {
			case iv, authData, macSize, dataSize, authTag
		}
		private typealias CCCryptorAddParameterT = @convention(c) (cryptorRef: CCCryptorRef, parameter: CCParameter, data: UnsafePointer<Void>, dataLength: size_t) -> CCCryptorStatus
		private static let CCCryptorAddParameter : CCCryptorAddParameterT? =
			getFunc(dl, f: "CCCryptorAddParameter")
		
		private typealias CCCryptorGetParameterT = @convention(c) (cryptorRef: CCCryptorRef, parameter: CCParameter, data: UnsafePointer<Void>, dataLength: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		private static let CCCryptorGetParameter : CCCryptorGetParameterT? =
			getFunc(dl, f: "CCCryptorGetParameter")
	}
	
	public class RSA {
		
		public typealias CCAsymmetricPadding = UInt32
		
		public enum AsymmetricPadding : CCAsymmetricPadding {
			case PKCS1 = 1001
			case OAEP = 1002
		}
		
		public static func generateKeyPair(keySize: Int = 4096) throws -> (NSData, NSData) {
			var privateKey: CCRSACryptorRef = nil
			var publicKey: CCRSACryptorRef = nil
			let status = CCRSACryptorGeneratePair!(
				keySize: keySize,
				e: 65537,
				publicKey: &publicKey,
				privateKey: &privateKey)
			guard status == noErr else { throw CCError(status) }
			
			defer {
				CCRSACryptorRelease!(privateKey)
				CCRSACryptorRelease!(publicKey)
			}
			
			let privDERKey = try exportToDERKey(privateKey)
			let pubDERKey = try exportToDERKey(publicKey)
			
			return (privDERKey, pubDERKey)
		}
		
		public static func encrypt(data: NSData, derKey: NSData, tag: NSData, padding: AsymmetricPadding,
		                           digest: DigestAlgorithm) throws -> NSData {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			
			var bufferSize = getKeySize(key)
			let buffer = NSMutableData(length: bufferSize)!
			
			let status = CCRSACryptorEncrypt!(
				publicKey: key,
				padding: padding.rawValue,
				plainText: data.bytes,
				plainTextLen: data.length,
				cipherText: buffer.mutableBytes,
				cipherTextLen: &bufferSize,
				tagData: tag.bytes, tagDataLen: tag.length,
				digestType: digest.rawValue)
			guard status == noErr else { throw CCError(status) }


			buffer.length = bufferSize
			
			return buffer
		}
		
		public static func decrypt(data: NSData, derKey: NSData, tag: NSData, padding: AsymmetricPadding,
		                           digest: DigestAlgorithm) throws -> (NSData, Int) {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			
			let blockSize = getKeySize(key)
			
			var bufferSize = blockSize
			let buffer = NSMutableData(length: bufferSize)!
			
			let status = CCRSACryptorDecrypt!(
				privateKey: key,
				padding: padding.rawValue,
				cipherText: data.bytes,
				cipherTextLen: bufferSize,
				plainText: buffer.mutableBytes,
				plainTextLen: &bufferSize,
				tagData: tag.bytes, tagDataLen: tag.length,
				digestType: digest.rawValue)
			guard status == noErr else { throw CCError(status) }
			buffer.length = bufferSize
			
			return (buffer, blockSize)
		}
		
		private static func importFromDERKey(derKey: NSData) throws -> CCRSACryptorRef {
			var key : CCRSACryptorRef = nil
			let status = CCRSACryptorImport!(
				keyPackage: derKey.bytes,
				keyPackageLen: derKey.length,
				key: &key)
			guard status == noErr else { throw CCError(status) }

			return key
		}
		
		private static func exportToDERKey(key: CCRSACryptorRef) throws -> NSData {
			var derKeyLength = 8192
			let derKey = NSMutableData(length: derKeyLength)!
			let status = CCRSACryptorExport!(
				key: key,
				out: derKey.mutableBytes,
				outLen: &derKeyLength)
			guard status == noErr else { throw CCError(status) }

			derKey.length = derKeyLength
			return derKey
		}
		
		private static func getKeySize(key: CCRSACryptorRef) -> Int {
			return Int(CCRSAGetKeySize!(key)/8)
		}
		
		public static func sign(hash: NSData, derKey: NSData, padding: AsymmetricPadding,
		                        digest: DigestAlgorithm) throws -> NSData {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			
			let keySize = getKeySize(key)
			var signedDataLength = keySize
			let signedData = NSMutableData(length:signedDataLength)!
			
			//ccrsa_oaep_encode_parameter bug
			if padding == .OAEP &&
				hash.length > keySize - 2 * CCDigestGetOutputSize!(algorithm: digest.rawValue) - 2 {
				assertionFailure("corecrypto: sign with OAEP is buggy in this configuration")
			}
			
			if padding == .OAEP && hash.length != CCDigestGetOutputSize!(algorithm: digest.rawValue) {
				assertionFailure("corecrypto: sign with OAEP is buggy in this configuration")
			}
			
			let status = CCRSACryptorSign!(
				privateKey: key,
				padding: padding.rawValue,
				hashToSign: hash.bytes, hashSignLen: hash.length,
				digestType: digest.rawValue, saltLen: 0 /*unused*/,
				signedData: signedData.mutableBytes, signedDataLen: &signedDataLength)
			guard status == noErr else { throw CCError(status) }

			signedData.length = signedDataLength
			return signedData
		}
		
		public static func verify(hash: NSData, derKey: NSData, padding: AsymmetricPadding,
		                          digest: DigestAlgorithm, signedData: NSData) throws -> Bool {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			
			if padding == .OAEP && hash.length != CCDigestGetOutputSize!(algorithm: digest.rawValue) {
				assertionFailure("corecrypto: verify with OAEP is buggy in this configuration")
			}
			
			let status = CCRSACryptorVerify!(
				publicKey: key,
				padding: padding.rawValue,
				hash: hash.bytes, hashLen: hash.length,
				digestType: digest.rawValue, saltLen: 0 /*unused*/,
				signedData: signedData.bytes, signedDataLen:signedData.length)
			let kCCNotVerified : CCCryptorStatus = -4306
			if status == kCCNotVerified {
				return false
			}
			guard status == noErr else { throw CCError(status) }

			return true
		}
		
		public static func available() -> Bool {
			return CCRSACryptorGeneratePair != nil &&
				CCRSACryptorRelease != nil &&
				CCRSAGetKeySize != nil &&
				CCRSACryptorEncrypt != nil &&
				CCRSACryptorDecrypt != nil &&
				CCRSACryptorExport != nil &&
				CCRSACryptorImport != nil &&
				CCRSACryptorSign != nil &&
				CCRSACryptorVerify != nil
		}
		
		private typealias CCRSACryptorRef = UnsafePointer<Void>
		private typealias CCRSACryptorGeneratePairT = @convention(c) (
			keySize: Int,
			e: UInt32,
			publicKey: UnsafeMutablePointer<CCRSACryptorRef>,
			privateKey: UnsafeMutablePointer<CCRSACryptorRef>) -> CCCryptorStatus
		private static let CCRSACryptorGeneratePair : CCRSACryptorGeneratePairT? =
			getFunc(CC.dl, f: "CCRSACryptorGeneratePair")
		
		private typealias CCRSACryptorReleaseT = @convention(c) (CCRSACryptorRef) -> Void
		private static let CCRSACryptorRelease : CCRSACryptorReleaseT? = getFunc(dl, f: "CCRSACryptorRelease")
		
		private typealias CCRSAGetKeySizeT = @convention(c) (CCRSACryptorRef) -> Int32
		private static let CCRSAGetKeySize : CCRSAGetKeySizeT? = getFunc(dl, f: "CCRSAGetKeySize")
		
		private typealias CCRSACryptorEncryptT = @convention(c) (
			publicKey: CCRSACryptorRef,
			padding: CCAsymmetricPadding,
			plainText: UnsafePointer<Void>,
			plainTextLen: Int,
			cipherText: UnsafeMutablePointer<Void>,
			cipherTextLen: UnsafeMutablePointer<Int>,
			tagData: UnsafePointer<Void>,
			tagDataLen: Int,
			digestType: CCDigestAlgorithm) -> CCCryptorStatus
		private static let CCRSACryptorEncrypt : CCRSACryptorEncryptT? = getFunc(dl, f: "CCRSACryptorEncrypt")
		
		private typealias CCRSACryptorDecryptT = @convention (c) (
			privateKey: CCRSACryptorRef,
			padding: CCAsymmetricPadding,
			cipherText: UnsafePointer<Void>,
			cipherTextLen: Int,
			plainText: UnsafeMutablePointer<Void>,
			plainTextLen: UnsafeMutablePointer<Int>,
			tagData: UnsafePointer<Void>,
			tagDataLen: Int,
			digestType: CCDigestAlgorithm) -> CCCryptorStatus
		private static let CCRSACryptorDecrypt : CCRSACryptorDecryptT? = getFunc(dl, f: "CCRSACryptorDecrypt")
		
		private typealias CCRSACryptorExportT = @convention(c) (
			key: CCRSACryptorRef,
			out: UnsafeMutablePointer<Void>,
			outLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		private static let CCRSACryptorExport : CCRSACryptorExportT? = getFunc(dl, f: "CCRSACryptorExport")
		
		private typealias CCRSACryptorImportT = @convention(c) (
			keyPackage: UnsafePointer<Void>,
			keyPackageLen: Int,
			key: UnsafeMutablePointer<CCRSACryptorRef>) -> CCCryptorStatus
		private static let CCRSACryptorImport : CCRSACryptorImportT? = getFunc(dl, f: "CCRSACryptorImport")
		
		private typealias CCRSACryptorSignT = @convention(c) (
			privateKey: CCRSACryptorRef,
			padding: CCAsymmetricPadding,
			hashToSign: UnsafePointer<Void>,
			hashSignLen: size_t,
			digestType: CCDigestAlgorithm,
			saltLen: size_t,
			signedData: UnsafeMutablePointer<Void>,
			signedDataLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		private static let CCRSACryptorSign : CCRSACryptorSignT? = getFunc(dl, f: "CCRSACryptorSign")
		
		private typealias CCRSACryptorVerifyT = @convention(c) (
			publicKey: CCRSACryptorRef,
			padding: CCAsymmetricPadding,
			hash: UnsafePointer<Void>,
			hashLen: size_t,
			digestType: CCDigestAlgorithm,
			saltLen: size_t,
			signedData: UnsafePointer<Void>,
			signedDataLen: size_t) -> CCCryptorStatus
		private static let CCRSACryptorVerify : CCRSACryptorVerifyT? = getFunc(dl, f: "CCRSACryptorVerify")

	}
	
	public class DH {
		
		public enum DHParam {
			case rfc3526Group5
		}
		
		//this is stateful in CommonCrypto too, sry
		public class DH {
			private var ref: CCDHRef = nil
			
			public init(dhParam: DHParam) throws {
				ref = CCDHCreate!(dhParameter: kCCDHRFC3526Group5!)
				guard ref != nil else {
					throw CCError(.ParamError)
				}
			}
			
			public func generateKey() throws -> NSData {
				var outputLength = 8192
				let output = NSMutableData(length: outputLength)!
				let status = CCDHGenerateKey!(
					ref: ref,
					output: output.mutableBytes, outputLength: &outputLength)
				output.length = outputLength
				guard status != -1 else {
					throw CCError(.ParamError)
				}
				return output
			}
			
			public func computeKey(peerKey: NSData) throws -> NSData {
				var sharedKeyLength = 8192
				let sharedKey = NSMutableData(length: sharedKeyLength)!
				let status = CCDHComputeKey!(
					sharedKey: sharedKey.mutableBytes, sharedKeyLen: &sharedKeyLength,
					peerPubKey: peerKey.bytes, peerPubKeyLen: peerKey.length,
					ref: ref)
				sharedKey.length = sharedKeyLength
				guard status == 0 else {
					throw CCError(.ParamError)
				}
				return sharedKey
			}
			
			deinit {
				if ref != nil {
					CCDHRelease!(ref: ref)
				}
			}
		}
		
		
		public static func available() -> Bool {
			return CCDHCreate != nil &&
				CCDHRelease != nil &&
				CCDHGenerateKey != nil &&
				CCDHComputeKey != nil
		}
		
		private typealias CCDHParameters = UnsafePointer<Void>
		private typealias CCDHRef = UnsafePointer<Void>

		private typealias kCCDHRFC3526Group5TM = UnsafePointer<CCDHParameters>
		private static let kCCDHRFC3526Group5M : kCCDHRFC3526Group5TM? =
			getFunc(dl, f: "kCCDHRFC3526Group5")
		private static let kCCDHRFC3526Group5 = kCCDHRFC3526Group5M?.memory
		
		private typealias CCDHCreateT = @convention(c) (
			dhParameter: CCDHParameters) -> CCDHRef
		private static let CCDHCreate : CCDHCreateT? = getFunc(dl, f: "CCDHCreate")
		
		private typealias CCDHReleaseT = @convention(c) (
			ref: CCDHRef) -> Void
		private static let CCDHRelease : CCDHReleaseT? = getFunc(dl, f: "CCDHRelease")
		
		private typealias CCDHGenerateKeyT = @convention(c) (
			ref: CCDHRef,
			output: UnsafeMutablePointer<Void>, outputLength: UnsafeMutablePointer<size_t>) -> CInt
		private static let CCDHGenerateKey : CCDHGenerateKeyT? = getFunc(dl, f: "CCDHGenerateKey")

		private typealias CCDHComputeKeyT = @convention(c) (
			sharedKey: UnsafeMutablePointer<Void>, sharedKeyLen: UnsafeMutablePointer<size_t>,
			peerPubKey: UnsafePointer<Void>, peerPubKeyLen: size_t,
			ref: CCDHRef) -> CInt
		private static let CCDHComputeKey : CCDHComputeKeyT? = getFunc(dl, f: "CCDHComputeKey")
	}
	
	public class EC {
		
		public static func generateKeyPair(keySize: Int) throws -> (NSData, NSData) {
			var privKey : CCECCryptorRef = nil
			var pubKey : CCECCryptorRef = nil
			let status = CCECCryptorGeneratePair!(
				keySize: keySize,
				publicKey: &pubKey,
				privateKey: &privKey)
			guard status == noErr else { throw CCError(status) }

			defer {
				CCECCryptorRelease!(key: privKey)
				CCECCryptorRelease!(key: pubKey)
			}
			
			let privKeyDER = try exportKey(privKey, format: .ImportKeyBinary, type: .KeyPrivate)
			let pubKeyDER = try exportKey(pubKey, format: .ImportKeyBinary, type: .KeyPublic)
			return (privKeyDER, pubKeyDER)
		}
		
		public static func signHash(privateKey: NSData, hash: NSData) throws -> NSData {
			let privKey = try importKey(privateKey, format: .ImportKeyBinary, keyType: .KeyPrivate)
			defer { CCECCryptorRelease!(key: privKey) }
			
			var signedDataLength = 4096
			let signedData = NSMutableData(length:signedDataLength)!
			let status = CCECCryptorSignHash!(
				privateKey: privKey,
				hashToSign: hash.bytes, hashSignLen: hash.length,
				signedData: signedData.mutableBytes, signedDataLen: &signedDataLength)
			guard status == noErr else { throw CCError(status) }

			signedData.length = signedDataLength
			return signedData
		}
		
		public static func verifyHash(publicKey: NSData, hash: NSData, signedData: NSData) throws -> Bool {
			let pubKey = try importKey(publicKey, format: .ImportKeyBinary, keyType: .KeyPublic)
			defer { CCECCryptorRelease!(key: pubKey) }
			
			var valid : UInt32 = 0
			let status = CCECCryptorVerifyHash!(
				publicKey:pubKey,
				hash: hash.bytes, hashLen: hash.length,
				signedData: signedData.bytes, signedDataLen: signedData.length,
				valid: &valid)
			guard status == noErr else { throw CCError(status) }

			return valid != 0
		}
		
		public static func computeSharedSecret(privateKey: NSData, publicKey: NSData) throws -> NSData {
			let privKey = try importKey(privateKey, format: .ImportKeyBinary, keyType: .KeyPrivate)
			let pubKey = try importKey(publicKey, format: .ImportKeyBinary, keyType: .KeyPublic)
			defer {
				CCECCryptorRelease!(key: privKey)
				CCECCryptorRelease!(key: pubKey)
			}
			
			var outSize = 8192
			let result = NSMutableData(length:outSize)!
			let status = CCECCryptorComputeSharedSecret!(
				privateKey: privKey, publicKey: pubKey, out:result.mutableBytes, outLen:&outSize)
			guard status == noErr else { throw CCError(status) }

			result.length = outSize
			return result
		}

		private static func importKey(key: NSData, format: KeyExternalFormat,
		                      keyType: KeyType) throws -> CCECCryptorRef {
			var impKey : CCECCryptorRef = nil
			let status = CCECCryptorImportKey!(format: format.rawValue,
			                     keyPackage: key.bytes, keyPackageLen:key.length,
			                     keyType: keyType.rawValue, key: &impKey)
			guard status == noErr else { throw CCError(status) }

			return impKey
		}
		
		private static func exportKey(key: CCECCryptorRef, format: KeyExternalFormat,
		                      type: KeyType) throws -> NSData {
			var expKeyLength = 8192
			let expKey = NSMutableData(length:expKeyLength)!
			let status = CCECCryptorExportKey!(
				format: format.rawValue,
				keyPackage: expKey.mutableBytes,
				keyPackageLen: &expKeyLength,
				keyType: type.rawValue,
				key: key)
			guard status == noErr else { throw CCError(status) }

			expKey.length = expKeyLength
			return expKey
		}
		
		public static func available() -> Bool {
			return CCECCryptorGeneratePair != nil &&
				CCECCryptorImportKey != nil &&
				CCECCryptorExportKey != nil &&
				CCECCryptorRelease != nil &&
				CCECCryptorSignHash != nil &&
				CCECCryptorVerifyHash != nil &&
				CCECCryptorComputeSharedSecret != nil
		}
		
		private enum KeyType : CCECKeyType {
			case KeyPublic = 0, KeyPrivate
			case BlankPublicKey = 97, BlankPrivateKey
			case BadKey = 99
		}
		private typealias CCECKeyType = UInt32
		
		private typealias CCECKeyExternalFormat = UInt32
		private enum KeyExternalFormat : CCECKeyExternalFormat {
			case ImportKeyBinary = 0, ImportKeyDER
		}
		
		private typealias CCECCryptorRef = UnsafePointer<Void>
		private typealias CCECCryptorGeneratePairT = @convention(c) (
			keySize: size_t ,
			publicKey: UnsafeMutablePointer<CCECCryptorRef>,
			privateKey: UnsafeMutablePointer<CCECCryptorRef>) -> CCCryptorStatus
		private static let CCECCryptorGeneratePair : CCECCryptorGeneratePairT? =
			getFunc(dl, f: "CCECCryptorGeneratePair")
		
		private typealias CCECCryptorImportKeyT = @convention(c) (
			format: CCECKeyExternalFormat,
			keyPackage: UnsafePointer<Void>, keyPackageLen: size_t,
			keyType: CCECKeyType, key: UnsafeMutablePointer<CCECCryptorRef>) -> CCCryptorStatus
		private static let CCECCryptorImportKey : CCECCryptorImportKeyT? =
			getFunc(dl, f: "CCECCryptorImportKey")
		
		private typealias CCECCryptorExportKeyT = @convention(c) (
			format: CCECKeyExternalFormat,
			keyPackage: UnsafePointer<Void>,
			keyPackageLen: UnsafePointer<size_t>,
			keyType: CCECKeyType , key: CCECCryptorRef) -> CCCryptorStatus
		private static let CCECCryptorExportKey : CCECCryptorExportKeyT? =
			getFunc(dl, f: "CCECCryptorExportKey")
		
		private typealias CCECCryptorReleaseT = @convention(c) (
			key: CCECCryptorRef) -> Void
		private static let CCECCryptorRelease : CCECCryptorReleaseT? =
			getFunc(dl, f: "CCECCryptorRelease")
		
		private typealias CCECCryptorSignHashT = @convention(c)(
			privateKey: CCECCryptorRef,
			hashToSign: UnsafePointer<Void>,
			hashSignLen: size_t,
			signedData: UnsafeMutablePointer<Void>,
			signedDataLen: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		private static let CCECCryptorSignHash : CCECCryptorSignHashT? =
			getFunc(dl, f: "CCECCryptorSignHash")
		
		private typealias CCECCryptorVerifyHashT = @convention(c)(
			publicKey: CCECCryptorRef,
			hash: UnsafePointer<Void>, hashLen: size_t,
			signedData: UnsafePointer<Void>, signedDataLen: size_t,
			valid: UnsafeMutablePointer<UInt32>) -> CCCryptorStatus
		private static let CCECCryptorVerifyHash : CCECCryptorVerifyHashT? =
			getFunc(dl, f: "CCECCryptorVerifyHash")
		
		private typealias CCECCryptorComputeSharedSecretT = @convention(c)(
			privateKey: CCECCryptorRef,
			publicKey: CCECCryptorRef,
			out: UnsafeMutablePointer<Void>,
			outLen: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		private static let CCECCryptorComputeSharedSecret : CCECCryptorComputeSharedSecretT? =
			getFunc(dl, f: "CCECCryptorComputeSharedSecret")
	}
	
	public class KeyDerivation {
		
		public typealias CCPseudoRandomAlgorithm = UInt32
		public enum PRFAlg : CCPseudoRandomAlgorithm {
			case SHA1 = 1, SHA224, SHA256, SHA384, SHA512
			var cc : CC.HMACAlg {
				switch self {
				case .SHA1: return .SHA1
				case .SHA224: return .SHA224
				case .SHA256: return .SHA256
				case .SHA384: return .SHA384
				case .SHA512: return .SHA512
				}
			}
		}
		
		public static func PBKDF2(password: String, salt: NSData,
		                         prf: PRFAlg, rounds: UInt32) throws -> NSData {
			
			let result = NSMutableData(length:prf.cc.digestLength)!
			let passwData = password.dataUsingEncoding(NSUTF8StringEncoding)!
			let status = CCKeyDerivationPBKDF!(algorithm: PBKDFAlgorithm.PBKDF2.rawValue,
			                      password: passwData.bytes, passwordLen: passwData.length,
			                      salt: salt.bytes, saltLen: salt.length,
			                      prf: prf.rawValue, rounds: rounds,
			                      derivedKey: result.mutableBytes, derivedKeyLen: result.length)
			guard status == noErr else { throw CCError(status) }

			return result
		}
		
		public static func available() -> Bool {
			return CCKeyDerivationPBKDF != nil
		}
		
		private typealias CCPBKDFAlgorithm = UInt32
		private enum PBKDFAlgorithm : CCPBKDFAlgorithm {
			case PBKDF2 = 2
		}
		
		private typealias CCKeyDerivationPBKDFT = @convention(c) (
			algorithm: CCPBKDFAlgorithm,
			password: UnsafePointer<Void>, passwordLen: size_t,
			salt: UnsafePointer<Void>, saltLen: size_t,
			prf: CCPseudoRandomAlgorithm, rounds: uint,
			derivedKey: UnsafeMutablePointer<Void>, derivedKeyLen: size_t) -> CCCryptorStatus
		private static let CCKeyDerivationPBKDF : CCKeyDerivationPBKDFT? =
			getFunc(dl, f: "CCKeyDerivationPBKDF")

	}
	
	public class KeyWrap {
		
		private static let rfc3394_iv_a : [UInt8] = [0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6]
		public static let rfc3394_iv = NSData(bytes: rfc3394_iv_a, length:rfc3394_iv_a.count)
		
		public static func SymmetricKeyWrap(iv: NSData,
		                                    kek: NSData,
		                                    rawKey: NSData) throws -> NSData {
			let alg = WrapAlg.AES.rawValue
			var wrappedKeyLength = CCSymmetricWrappedSize!(algorithm: alg, rawKeyLen: rawKey.length)
			let wrappedKey = NSMutableData(length:wrappedKeyLength)!
			let status = CCSymmetricKeyWrap!(
				algorithm: alg,
				iv: iv.bytes, ivLen: iv.length,
				kek: kek.bytes, kekLen: kek.length,
				rawKey: rawKey.bytes, rawKeyLen: rawKey.length,
				wrappedKey: wrappedKey.mutableBytes, wrappedKeyLen:&wrappedKeyLength)
			guard status == noErr else { throw CCError(status) }

			wrappedKey.length = wrappedKeyLength
			return wrappedKey
		}
		
		public static func SymmetricKeyUnwrap(iv: NSData,
		                                      kek: NSData,
		                                      wrappedKey: NSData) throws -> NSData {
			let alg = WrapAlg.AES.rawValue
			var rawKeyLength = CCSymmetricUnwrappedSize!(algorithm: alg, wrappedKeyLen: wrappedKey.length)
			let rawKey = NSMutableData(length:rawKeyLength)!
			let status = CCSymmetricKeyUnwrap!(
				algorithm: alg,
				iv: iv.bytes, ivLen: iv.length,
				kek: kek.bytes, kekLen: kek.length,
				wrappedKey: wrappedKey.bytes, wrappedKeyLen: wrappedKey.length,
				rawKey: rawKey.mutableBytes, rawKeyLen:&rawKeyLength)
			guard status == noErr else { throw CCError(status) }

			rawKey.length = rawKeyLength
			return rawKey
		}
		
		public static func available() -> Bool {
			return CCSymmetricKeyWrap != nil &&
				CCSymmetricKeyUnwrap != nil &&
				CCSymmetricWrappedSize != nil &&
				CCSymmetricUnwrappedSize != nil
		}
		
		private enum WrapAlg : CCWrappingAlgorithm {
			case AES = 1
		}
		private typealias CCWrappingAlgorithm = UInt32;
		
		private typealias CCSymmetricKeyWrapT = @convention(c) (
			algorithm: CCWrappingAlgorithm,
			iv: UnsafePointer<Void>, ivLen: size_t,
			kek: UnsafePointer<Void>, kekLen: size_t,
			rawKey: UnsafePointer<Void>, rawKeyLen: size_t,
			wrappedKey: UnsafeMutablePointer<Void>,
			wrappedKeyLen: UnsafePointer<size_t>) -> CCCryptorStatus
		private static let CCSymmetricKeyWrap : CCSymmetricKeyWrapT? = getFunc(dl, f: "CCSymmetricKeyWrap")

		private typealias CCSymmetricKeyUnwrapT = @convention(c) (
			algorithm: CCWrappingAlgorithm,
			iv: UnsafePointer<Void>, ivLen: size_t,
			kek: UnsafePointer<Void>, kekLen: size_t,
			wrappedKey: UnsafePointer<Void>, wrappedKeyLen: size_t,
			rawKey: UnsafeMutablePointer<Void>,
			rawKeyLen: UnsafePointer<size_t>) -> CCCryptorStatus
		private static let CCSymmetricKeyUnwrap : CCSymmetricKeyUnwrapT? = getFunc(dl, f: "CCSymmetricKeyUnwrap")
		
		private typealias CCSymmetricWrappedSizeT = @convention(c) (
			algorithm: CCWrappingAlgorithm,
			rawKeyLen: size_t) -> size_t
		private static let CCSymmetricWrappedSize : CCSymmetricWrappedSizeT? =
			getFunc(dl, f: "CCSymmetricWrappedSize")

		private typealias CCSymmetricUnwrappedSizeT = @convention(c) (
			algorithm: CCWrappingAlgorithm,
			wrappedKeyLen: size_t) -> size_t
		private static let CCSymmetricUnwrappedSize : CCSymmetricUnwrappedSizeT? =
			getFunc(dl, f: "CCSymmetricUnwrappedSize")
		
	}
	
}

private func getFunc<T>(from: UnsafeMutablePointer<Void>, f: String) -> T? {
	let sym = dlsym(from, f)
	guard sym != nil else {
		return nil
	}
	return unsafeBitCast(sym, T.self)
}

extension NSData {
	/// Create hexadecimal string representation of NSData object.
	///
	/// - returns: String representation of this NSData object.
	
	public func hexadecimalString() -> String {
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
	
	public func dataFromHexadecimalString() -> NSData? {
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

