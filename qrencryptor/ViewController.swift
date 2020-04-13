//
//  ViewController.swift
//  qrencryptor
//
//  Created by Melby Ruarus on 13/4/20.
//  Copyright © 2020 Melby Ruarus. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    @IBOutlet var textView: NSTextView!
    @IBOutlet var passwordField: NSSecureTextField!
    @IBOutlet var button: NSButton!
    @IBOutlet var loadingIndicator: NSProgressIndicator!
    
    @IBAction func encryptText(sender: AnyObject) {
        // Validate data.
        let data = textView.textStorage!.string
        let password = passwordField.stringValue
        guard !data.isEmpty else {
            showMessage(message: "Data to encrypt is missing", detail: "Please provide content to encrypt")
            return
        }
        guard !password.isEmpty else {
            showMessage(message: "Password is missing", detail: "Please provide a password to encrypt your content")
            return
        }
        
        // Defocus the text fields.
        view.window?.makeFirstResponder(nil)
        
        // Start encrypting.
        startLoading()
        DispatchQueue.global().async {
            guard let encryptionResult =
                encrypt(data: data, password: password) else {
                    DispatchQueue.main.async {
                        self.showMessage(message: "Encryption failed", detail: "Please try again with a different message or password")
                        self.stopLoading()
                    }
                    return
            }
            
            // Construct the CLI decryption string.
            let commandToEncode = self.createCLIDecryptionString(result: encryptionResult)
            
            DispatchQueue.main.async {
                // Stop loading, everything after this point is obvious what is happening.
                self.stopLoading()
                
                self.getSavePath { (url) in
                    if let url = url {
                        if self.writeQRCode(text: commandToEncode, url: url) {
                            self.showMessage(message: "Success!", detail: "Make sure to verify that you can successfuly decrypt the content before relying on the QR code")
                        } else {
                            self.showMessage(message: "Encryption failed", detail: "The message you are attempting to encrypt might be too long to fit in the QR code")
                        }
                    }
                }
            }
        }
    }
    
    func showMessage(message: String, detail: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = detail
        alert.alertStyle = .informational
        
        alert.runModal()
    }
    
    func startLoading() {
        button.isHidden = true
        loadingIndicator.startAnimation(self)
    }
    
    func stopLoading() {
        button.isHidden = false
        loadingIndicator.stopAnimation(self)
    }
    
    func createCLIDecryptionString(result: EncryptionOutput) -> String {
        let base64CipherText = result.cipherText.base64EncodedString()
        let base64Salt = result.salt.base64EncodedString()
        let base64Iv = result.iv.base64EncodedString()
                
        return "php -r \"echo openssl_decrypt(base64_decode('\(base64CipherText)'),'AES-256-CBC',hash_pbkdf2('sha512',exec(\\\"python -c 'import getpass;print getpass.getpass()'\\\"),base64_decode('\(base64Salt)'),1e7,32,true),OPENSSL_RAW_DATA,base64_decode('\(base64Iv)')).\\\"\\\\n\\\";\""
    }
    
    func getSavePath(completion: @escaping (URL?) -> ()) {
        let panel = NSSavePanel()
        panel.allowedFileTypes = ["png"]
        panel.beginSheetModal(for: view.window!) { (response) in
            if response == .OK {
                completion(panel.url)
            } else {
                completion(nil)
            }
        }
    }
    
    func writeQRCode(text: String, url: URL) -> Bool {
        let filter = CIFilter(name: "CIQRCodeGenerator")!
        filter.setValue(text.data(using: .utf8), forKey: "inputMessage")
        let imageWithRep = NSImage()
        
        guard let outputImage = filter.outputImage else {
            return false
        }
        imageWithRep.addRepresentation(NSCIImageRep(ciImage: outputImage))
        let image = NSImage(size: NSSize(width: 1000, height: 1000))
        image.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .none
        imageWithRep.draw(in: NSRect(x: 0, y: 0, width: 1000, height: 1000))
        image.unlockFocus()
        
        let bitmapData = NSBitmapImageRep(data: image.tiffRepresentation!)?.representation(using: .png, properties: [:])
        try! bitmapData?.write(to: url)
        
        return true
    }
}

