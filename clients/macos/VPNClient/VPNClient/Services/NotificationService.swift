//
//  NotificationService.swift
//  VPNClient
//
//  Posts user notifications for VPN connection events (unexpected disconnect,
//  successful reconnect, reconnect failure). Notifications can only be posted
//  from the app process — the PacketTunnel extension cannot — so VPNManager
//  drives this off the NEVPNStatusDidChange observations.
//
//  Authorization is requested lazily, the first time a notification is about
//  to be posted. The "vpn_notify_disconnect" setting (default ON, see
//  SettingsView) gates every post.
//

import Foundation
import UserNotifications

@MainActor
final class NotificationService: NSObject {

    static let shared = NotificationService()

    /// Settings toggle: notify on unexpected disconnect / reconnect events.
    /// Default is ON when the key has never been written.
    static let notifyDisconnectKey = "vpn_notify_disconnect"

    static var isNotifyEnabled: Bool {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: notifyDisconnectKey) == nil { return true }
        return defaults.bool(forKey: notifyDisconnectKey)
    }

    private override init() {
        super.init()
    }

    /// Installs this service as the notification-center delegate so banners
    /// are shown even while the app is frontmost. Call at app launch.
    func activate() {
        UNUserNotificationCenter.current().delegate = self
    }

    /// Posts a notification if the user's "notify on disconnect" setting is on.
    /// Requests authorization on first use.
    func postIfEnabled(title: String, body: String) {
        guard Self.isNotifyEnabled else { return }
        Task {
            guard await self.ensureAuthorized() else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let request = UNNotificationRequest(
                identifier: UUID().uuidString,
                content: content,
                trigger: nil
            )
            try? await UNUserNotificationCenter.current().add(request)
        }
    }

    private func ensureAuthorized() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional:
            return true
        case .notDetermined:
            return (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        default:
            return false
        }
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension NotificationService: UNUserNotificationCenterDelegate {
    /// Show the banner even when the app is in the foreground (a menu-bar app
    /// is frequently "active" without any visible window).
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
