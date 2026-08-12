//
//  PlatformInput.swift
//  VPNClient
//
//  Small cross-platform helpers for the shared SwiftUI views. The app is built
//  for iOS, iPadOS and macOS from one source tree, and the touch platforms need
//  configuration that simply does not exist on AppKit: software keyboards must
//  be told what kind of text a field holds, and controls need a finger-sized
//  hit area. These wrappers keep the `#if os(...)` noise out of the views.
//

import SwiftUI
#if os(iOS)
// UITextContentType and its cases live in UIKit, and the target builds with
// MEMBER_IMPORT_VISIBILITY, so the module has to be imported explicitly here.
import UIKit
#endif

/// What a text field holds, so the software keyboard can be configured for it.
enum TextFieldKind {
    case host
    case port
    case username
    case password
}

extension View {

    /// Configures the software keyboard for `kind` on touch platforms.
    ///
    /// Without this, iOS applies its defaults: the first letter of a server
    /// address or username is auto-capitalized and autocorrect rewrites it, so
    /// a user who types `vpn.example.com` submits `Vpn.example.com` and the
    /// connection fails with no obvious cause. On macOS this is a no-op — none
    /// of these modifiers exist there.
    @ViewBuilder
    func textFieldKind(_ kind: TextFieldKind) -> some View {
        #if os(iOS)
        switch kind {
        case .host:
            self.keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textContentType(.URL)
                .submitLabel(.next)
        case .port:
            self.keyboardType(.numberPad)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        case .username:
            self.keyboardType(.asciiCapable)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textContentType(.username)
                .submitLabel(.next)
        case .password:
            self.textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textContentType(.password)
                .submitLabel(.go)
        }
        #else
        self
        #endif
    }

    /// Grows a control to the 44×44pt minimum touch target on touch platforms.
    /// Icon-only buttons are otherwise only as large as their glyph, which is
    /// comfortably tappable with a cursor but not with a thumb.
    @ViewBuilder
    func touchTarget() -> some View {
        #if os(iOS)
        self.frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
        #else
        self
        #endif
    }
}

/// Human-readable name of the platform the app is running on, for the Settings
/// "Platform" row — which used to read "macOS" on every platform, including on
/// an iPhone.
enum RuntimePlatform {
    static var displayName: String {
        #if os(macOS)
        return "macOS"
        #elseif os(iOS)
        return "iOS"
        #else
        return "Unknown"
        #endif
    }
}
