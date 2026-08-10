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
    /// <summary>The stored session authenticates with username + password.</summary>
    public const string AuthModePassword = "password";

    /// <summary>The stored session authenticates with the SSO session token.</summary>
    public const string AuthModeSso = "sso";

    /// <summary>How the persisted session authenticates ("password" or "sso").</summary>
    public static string AuthMode
    {
        get
        {
            var mode = Settings.Default.AuthMode;
            return string.IsNullOrEmpty(mode) ? AuthModePassword : mode;
        }
    }

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
        // A password login supersedes any earlier SSO session.
        s.SavedSessionTokenEnc = string.Empty;
        s.AuthMode = AuthModePassword;
        s.LastServerAddress = server;
        s.LastServerPort = port;
        s.RememberMe = true;
        s.Save();
    }

    /// <summary>
    /// Saved SSO session (Datasee SSO device flow), or null if none is stored /
    /// cannot be read. Username is the SSO account email, used for display.
    /// </summary>
    public static (string Username, string SessionToken, string Server, int Port)? LoadSsoSession()
    {
        var s = Settings.Default;
        if (AuthMode != AuthModeSso || string.IsNullOrEmpty(s.SavedSessionTokenEnc))
        {
            return null;
        }

        var token = Unprotect(s.SavedSessionTokenEnc);
        if (token == null)
        {
            return null;
        }

        var server = string.IsNullOrWhiteSpace(s.LastServerAddress)
            ? "vpn.example.com"
            : s.LastServerAddress;
        return (s.SavedUsername, token, server, s.LastServerPort);
    }

    /// <summary>
    /// Persist the SSO session for auto-login: the server-issued 30-day session
    /// token is stored DPAPI-encrypted (same scheme as the password). No
    /// password is kept — reconnects authenticate with {authType:"session"}.
    /// </summary>
    public static void SaveSsoSession(string username, string sessionToken, string server, int port)
    {
        var s = Settings.Default;
        s.SavedUsername = username;
        s.SavedPasswordEnc = string.Empty;
        s.SavedSessionTokenEnc = Protect(sessionToken);
        s.AuthMode = AuthModeSso;
        s.LastServerAddress = server;
        s.LastServerPort = port;
        s.RememberMe = true;
        s.Save();
    }

    /// <summary>Replace the stored session token (server rotated it on re-auth).</summary>
    public static void UpdateSessionToken(string sessionToken)
    {
        var s = Settings.Default;
        s.SavedSessionTokenEnc = Protect(sessionToken);
        s.Save();
    }

    /// <summary>
    /// Forget only the session token — called when the server rejects it
    /// (expired/revoked), so the next launch shows the login screen again.
    /// </summary>
    public static void ClearSessionToken()
    {
        var s = Settings.Default;
        s.SavedSessionTokenEnc = string.Empty;
        s.Save();
    }

    /// <summary>Forget stored credentials (called on logout / when Remember is off).</summary>
    public static void Clear()
    {
        var s = Settings.Default;
        s.SavedUsername = string.Empty;
        s.SavedPasswordEnc = string.Empty;
        s.SavedSessionTokenEnc = string.Empty;
        s.AuthMode = AuthModePassword;
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
