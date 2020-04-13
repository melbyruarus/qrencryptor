//
//  encrypt.swift
//  qrencryptor
//
//  Created by Melby Ruarus on 13/4/20.
//  Copyright © 2020 Melby Ruarus. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

// The result of an encryption operation.
struct EncryptionOutput {
    var cipherText: Data
    var iv: Data
    var salt: Data
}

// Encrypt the specified data using the provided password.
//
// A key is derived from the password using 10 million PBKDF2 iterations with
// SHA512 and a randomly generated salt.
//
// Encryption is performed using AES256 CBC.
func encrypt(data: String, password: String) -> EncryptionOutput? {
    let PBKDF2Iterations: UInt32 = 10000000

    func randomGenerateBytes(count: Int) -> Data? {
        let bytes = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 1)
        defer { bytes.deallocate() }
        let status = CCRandomGenerateBytes(bytes, count)
        guard status == kCCSuccess else { return nil }
        return Data(bytes: bytes, count: count)
    }

    func isZeros(_ data: Data) -> Bool {
        return data.allSatisfy { (byte: UInt8) -> Bool in
            byte == 0
        }
    }


    var error: Unmanaged<CFError>? = nil
    defer { error?.release() }


    let passwordData = password.data(using: .utf8)!
    let saltData = randomGenerateBytes(count: 16)!
    let ivData = randomGenerateBytes(count: 16)!


    // Derive key from password.
    let keySize = kCCKeySizeAES256
    var keyData = Data(count: kCCKeySizeAES256)
    let keyResult = keyData.withUnsafeMutableBytes{ (keyBytes: UnsafeMutableRawBufferPointer) in
        passwordData.withUnsafeBytes { (passwordBytes: UnsafeRawBufferPointer) in
            saltData.withUnsafeBytes { (saltBytes: UnsafeRawBufferPointer) in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                     passwordBytes.bindMemory(to: Int8.self).baseAddress,
                                     passwordData.count,
                                     saltBytes.bindMemory(to: UInt8.self).baseAddress,
                                     saltData.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                                     PBKDF2Iterations,
                                     keyBytes.bindMemory(to: UInt8.self).baseAddress,
                                     keySize
                )
            }
        }
    }
    guard keyResult == kCCSuccess else {
        NSLog("Failed to derive key: \(keyResult)")
        return nil
    }
    guard !isZeros(keyData) && !isZeros(ivData) && !isZeros(saltData) else {
        NSLog("Failed generating non-zero key/iv/salt")
        return nil
    }
    guard let key = SecKeyCreateFromData([kSecAttrKeyType:kSecAttrKeyTypeAES] as CFDictionary, keyData as CFData, &error) else {
        NSLog("Failed to create key: \(String(describing: error))")
        return nil
    }


    // Construct AES encryption transform.
    let aesTransform = SecEncryptTransformCreate(key, &error)
    if error != nil {
        NSLog("Failed to create transform: \(String(describing: error))")
        return nil
    }
    guard SecTransformSetAttribute(aesTransform, kSecTransformInputAttributeName, data.data(using: .utf8)! as CFData, &error) else {
        NSLog("Failed to set transform input: \(String(describing: error))")
        return nil
    }
    guard SecTransformSetAttribute(aesTransform, kSecIVKey, ivData as CFData, &error) else {
        NSLog("Failed to set transform iv: \(String(describing: error))")
        return nil
    }
    guard SecTransformSetAttribute(aesTransform, kSecEncryptionMode, kSecModeCBCKey, &error) else {
        NSLog("Failed to set transform encryption mode: \(String(describing: error))")
        return nil
    }


    // Execute transform.
    let outputData = SecTransformExecute(aesTransform, &error)
    if let error = error {
        NSLog("Failed to execute transform: \(String(describing: error))")
        return nil
    }
    
    
    return EncryptionOutput(cipherText: outputData as! Data, iv: ivData, salt: saltData)
}
