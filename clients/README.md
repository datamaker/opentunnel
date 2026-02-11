# OpenTunnel VPN Clients

Native VPN clients for all major platforms.

## Platforms

| Platform | Language | Framework | Status |
|----------|----------|-----------|--------|
| [macOS](./macos/) | Swift | NetworkExtension | Ready |
| [iOS](./ios/) | Swift | NetworkExtension | Ready |
| [Android](./android/) | Kotlin | VpnService | Ready |
| [Windows](./windows/) | C# | WinTun | Ready |

## Building

### macOS

Requirements:
- Xcode 15+
- Apple Developer Account (for code signing)

```bash
cd macos/VPNClient
open VPNClient.xcodeproj
# Configure signing in Xcode
# Build and Run
```

### iOS

Requirements:
- Xcode 15+
- Apple Developer Account
- Physical device (VPN doesn't work in simulator)

```bash
cd ios/VPNClient
open VPNClient.xcodeproj
# Configure signing
# Build and Run on device
```

### Android

Requirements:
- Android Studio Hedgehog+
- Android SDK 24+

```bash
cd android
./gradlew assembleDebug
# Install APK on device
```

### Windows

Requirements:
- Visual Studio 2022
- .NET 6.0 SDK
- WinTun driver

```bash
cd windows
dotnet build
# Run VPNClient.exe as Administrator
```

## Common Features

All clients implement:
- TLS 1.3 connection to server
- Username/password authentication
- VPN tunnel management
- Connection status monitoring
- Auto-reconnect

## Protocol

Clients communicate with the server using a binary protocol over TLS:

```
[type:1][length:4][payload:N]
```

See server documentation for message type details.

## Testing

1. Start the VPN server
2. Create a test user via admin panel
3. Connect with client using credentials
4. Verify internet connectivity through VPN

## Troubleshooting

### macOS/iOS
- Ensure Network Extension capability is enabled
- Check System Preferences > VPN for configuration
- View Console.app for extension logs

### Android
- Grant VPN permission when prompted
- Check Logcat for tunnel logs
- Ensure battery optimization is disabled

### Windows
- Run as Administrator
- Install WinTun driver
- Check Windows Event Viewer for errors

## License

MIT
