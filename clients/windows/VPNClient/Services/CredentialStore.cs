using System.Security.Cryptography;
using System.Text;
using VPNClient.Properties;

namespace VPNClient.Services;

/// <summary>
/// Persists the login credentials so the user stays signed in across app
/// restarts (matching the iOS/macOS/Android clients).
///
/// The username, server and port are stored in plain user settings; the
/// password is encrypted at rest with Windows DPAPI (<see cref="DataProtectionScope.CurrentUser"/>),
/// so it can only be decrypted by the same Windows user on the same machine.
/// </summary>
public static class CredentialStore
{
    /// <summary>Saved credentials, or null if none are stored / cannot be read.</summary>
    public static (string Username, string Password, string Server, int Port)? Load()
    {
        var s = Settings.Default;
        if (!s.RememberMe
            || string.IsNullOrEmpty(s.SavedUsername)
            || string.IsNullOrEmpty(s.SavedPasswordEnc))
        {
            return null;
        }

        var password = Unprotect(s.SavedPasswordEnc);
        if (password == null)
        {
            return null;
        }

        var server = string.IsNullOrWhiteSpace(s.LastServerAddress)
            ? "vpn.example.com"
            : s.LastServerAddress;
        return (s.SavedUsername, password, server, s.LastServerPort);
    }

    /// <summary>Persist credentials for auto-login on the next launch.</summary>
    public static void Save(string username, string password, string server, int port)
    {
        var s = Settings.Default;
        s.SavedUsername = username;
        s.SavedPasswordEnc = Protect(password);
        s.LastServerAddress = server;
        s.LastServerPort = port;
        s.RememberMe = true;
        s.Save();
    }

    /// <summary>Forget stored credentials (called on logout / when Remember is off).</summary>
    public static void Clear()
    {
        var s = Settings.Default;
        s.SavedUsername = string.Empty;
        s.SavedPasswordEnc = string.Empty;
        s.RememberMe = false;
        s.Save();
    }

    private static string Protect(string plain)
    {
        var bytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(plain), optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(bytes);
    }

    private static string? Unprotect(string encoded)
    {
        try
        {
            var bytes = ProtectedData.Unprotect(
                Convert.FromBase64String(encoded), optionalEntropy: null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            // Corrupt/blob from another user or machine — treat as "no credentials".
            return null;
        }
    }
}
