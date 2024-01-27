import UIKit

func saveEncryptedText(_ text: String) {
    let fileManager = FileManager.default
    let dir = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
    let fileURL = dir.appendingPathComponent("file.txt")
    do {
        let data = Data(text.utf8)
        try data.write(to: fileURL, options: .completeFileProtection)
    } catch {
        print("Error saving file: \(error.localizedDescription)")
    }
}

saveEncryptedText("Franz Hose, geb. 03.04.1984")

//-----------------------------------------------------------------------------------

import CryptoKit

func encryptText(_ text: String, using key: SymmetricKey) throws -> Data {
    let plaintextData = Data(text.utf8)
    let sealedBox = try AES.GCM.seal(plaintextData, using: key)
    return sealedBox.combined!
}

func decryptData(_ data: Data, using key: SymmetricKey) throws -> String {
    let sealedBox = try AES.GCM.SealedBox(combined: data)
    let decryptedData = try AES.GCM.open(sealedBox, using: key)
    guard let decryptedText = String(data: decryptedData, encoding: .utf8) else {
        throw NSError(domain: "DecryptionErrorDomain", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decryption failed"])
    }
    return decryptedText
}

do {
    let encryptionkey = SymmetricKey(size: .bits256)
    let originalText = "Dies ist ein geheimer Text."
    let encryptedData = try encryptText(originalText, using: encryptionkey)
    let encryptedData2 = try encryptText(originalText, using: encryptionkey)
    let decryptedText = try decryptData(encryptedData, using: encryptionkey)
    print( "Originaltext: \(originalText)")
    print( "Verschlüsselter Text: \(encryptedData.base64EncodedString())")
    print( "Verschlüsselter Text: \(encryptedData2.base64EncodedString())")
    print( "Entschlüsselter Text: \(decryptedText)")
} catch {
    print( "Fehler: \(error.localizedDescription)")
}

//-----------------------------------------------------------------------------------

import CommonCrypto

func pbkdf2(hash: CCPBKDFAlgorithm,
            password: String,
            salt: Data,
            keyByteCount: Int,
            rounds: Int) -> Data? {
    guard let passwordData = password.data(using: .utf8) else { return nil}

    var derivedKeyData = Data( repeating: 0, count: keyByteCount)
    let derivedCount = derivedKeyData.count

    let derivationStatus: OSStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        let derivedKeyRawBytes = derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress
        return salt.withUnsafeBytes { saltBytes in
            let rawBytes = saltBytes.bindMemory(to: UInt8.self).baseAddress
            return CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                        password,
                                        passwordData.count,
                                        rawBytes,
                                        salt.count,
                                        hash,
                                        UInt32(rounds),
                                        derivedKeyRawBytes,
                                        derivedCount)
        }
    }
    
    return derivationStatus == kCCSuccess ? derivedKeyData : nil

}

func deriveKey(fromPassword password: String, salt: Data) -> SymmetricKey {
    let passwordData = Data(password.utf8)
    let initialKey = SymmetricKey(data: passwordData)
    let derivedKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: initialKey,
                                            salt: salt, info: Data( "SymmetricKeyInfo".utf8), outputByteCount: 32)
    return SymmetricKey(data: derivedKey)
}

//let userPassword = "YouSh@llN0tPa$$_23;"
//let salt = Data("08247nr5suizrt8e4zrntgiuzerä+09457n938w74n3SRDtfgsdrgsdr_+dsrfg".utf8)
//let symmetrickey = deriveKey(fromPassword: userPassword, salt: salt)

//-----------------------------------------------------------------------------------

//let password = "YouSh@llNOtPa$$_23;"
//let hash = SHA256.hash(data: Data(password.utf8))
//print( "Hashed password: \(hash)")

//-----------------------------------------------------------------------------------

//func securePasswordHash(password: String, salt: String) -> String {
//    let saltedPassword = Data((salt + password).utf8)
//    return SHA256.hash(data: saltedPassword).description
//
//}
//
//let password = "123456"
//let salt = "7z/sdfghhsdri84ez7w5nisuhgfniusehfiuserdfhgisdfg*53487hfgsdrf"
//let hashedText = securePasswordHash(password: password, salt: salt)
//print(hashedText)

//-----------------------------------------------------------------------------------

let password = "b3f8ad0a03f8d67de7562c69988ca65f330d178234a828bcb1f996d94381b5c9".data(using: .utf8)!
let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: password), outputByteCount: 256)
let cleartext = "Der HMAC schützt die Integrität dieses Textes".data(using: .utf8)!
let hmac = HMAC<SHA256>.authenticationCode(for: cleartext, using: key)
print( hmac)

//-----------------------------------------------------------------------------------

import LocalAuthentication

let authContext = LAContext();
var error: Unmanaged<CFError>?
let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                             kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                             [.privateKeyUsage, .biometryCurrentSet],
                                             &error);
if let newkey = try? SecureEnclave.P256.Signing.PrivateKey(
    accessControl: access!,
    authenticationContext: authContext) {
    print(newkey.publicKey)
    // Store key
} else {
    // Show error
}

//-----------------------------------------------------------------------------------
