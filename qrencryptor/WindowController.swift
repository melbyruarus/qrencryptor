//
//  WindowController.swift
//  qrencryptor
//
//  Created by Melby Ruarus on 13/4/20.
//  Copyright © 2020 Melby Ruarus. All rights reserved.
//

import Cocoa

class WindowController: NSWindowController, NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        NSApp.terminate(self)
    }
}
