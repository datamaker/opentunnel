using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VPNClient.Services;

/// <summary>
/// OAuth 2.0 Device Authorization Grant (RFC 8628) client for the Datasee IdP
/// (auth.datasee.co.kr). Used by the "Google로 로그인 (Datasee SSO)" flow:
/// the IdP is public and reachable without the VPN, the user completes the
/// Google login in their default browser and this service polls the token
/// endpoint until an id_token is issued.
/// </summary>
public class DeviceFlowService
{
    private const string DeviceAuthEndpoint = "https://auth.datasee.co.kr/oidc/device/auth";
    private const string TokenEndpoint = "https://auth.datasee.co.kr/oidc/token";
    private const string ClientId = "opentunnel";
    private const string Scope = "openid email profile";

    // One shared client for the app lifetime (avoids socket exhaustion).
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Step 1: request a device/user code pair from the IdP.
    /// </summary>
    public async Task<DeviceAuthorization> StartAsync(CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["scope"] = Scope
        });

        using var response = await Http.PostAsync(DeviceAuthEndpoint, content, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new DeviceFlowException($"SSO 로그인 시작에 실패했습니다. (HTTP {(int)response.StatusCode})");
        }

        DeviceAuthorization? auth;
        try
        {
            auth = JsonSerializer.Deserialize<DeviceAuthorization>(body, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new DeviceFlowException("SSO 서버 응답을 해석할 수 없습니다.", ex);
        }

        if (auth == null
            || string.IsNullOrEmpty(auth.DeviceCode)
            || string.IsNullOrEmpty(auth.UserCode))
        {
            throw new DeviceFlowException("SSO 서버 응답이 올바르지 않습니다.");
        }

        return auth;
    }

    /// <summary>
    /// Step 3: poll the token endpoint until the user completes the browser
    /// login. Returns the OIDC id_token on success; throws
    /// <see cref="DeviceFlowException"/> on denial/expiry, or
    /// <see cref="OperationCanceledException"/> when the user cancels.
    /// </summary>
    public async Task<string> PollForIdTokenAsync(DeviceAuthorization auth, CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(auth.Interval, 1));
        var expiresIn = auth.ExpiresIn > 0 ? auth.ExpiresIn : 600;
        var deadline = DateTime.UtcNow.AddSeconds(expiresIn);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (DateTime.UtcNow >= deadline)
            {
                throw new DeviceFlowException("로그인 시간이 만료되었습니다. 다시 시도해 주세요.");
            }

            await Task.Delay(interval, cancellationToken);

            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["device_code"] = auth.DeviceCode,
                ["client_id"] = ClientId
            });

            using var response = await Http.PostAsync(TokenEndpoint, content, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            TokenResponse? token = null;
            try
            {
                token = JsonSerializer.Deserialize<TokenResponse>(body, JsonOptions);
            }
            catch (JsonException)
            {
                // Fall through to the null check below.
            }

            if (token == null)
            {
                throw new DeviceFlowException("SSO 서버 응답을 해석할 수 없습니다.");
            }

            if (!string.IsNullOrEmpty(token.IdToken))
            {
                return token.IdToken;
            }

            switch (token.Error)
            {
                case "authorization_pending":
                    continue;

                case "slow_down":
                    // RFC 8628: add 5 seconds to the polling interval.
                    interval += TimeSpan.FromSeconds(5);
                    continue;

                case "expired_token":
                    throw new DeviceFlowException("로그인 시간이 만료되었습니다. 다시 시도해 주세요.");

                case "access_denied":
                    throw new DeviceFlowException("로그인이 거부되었습니다.");

                default:
                    throw new DeviceFlowException(
                        $"SSO 로그인에 실패했습니다. ({token.Error ?? "id_token 없음"})");
            }
        }
    }

    /// <summary>
    /// Best-effort extraction of the "email" claim from a JWT id_token, used
    /// only for display (the server verifies the token's signature itself).
    /// </summary>
    public static string? TryGetEmail(string idToken)
    {
        try
        {
            var parts = idToken.Split('.');
            if (parts.Length < 2)
            {
                return null;
            }

            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("email", out var email)
                && email.ValueKind == JsonValueKind.String)
            {
                return email.GetString();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Response of the device authorization endpoint (RFC 8628 section 3.2).
/// </summary>
public class DeviceAuthorization
{
    [JsonPropertyName("device_code")]
    public string DeviceCode { get; set; } = string.Empty;

    [JsonPropertyName("user_code")]
    public string UserCode { get; set; } = string.Empty;

    [JsonPropertyName("verification_uri")]
    public string VerificationUri { get; set; } = string.Empty;

    [JsonPropertyName("verification_uri_complete")]
    public string VerificationUriComplete { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("interval")]
    public int Interval { get; set; } = 5;
}

/// <summary>
/// Response of the token endpoint — either an issued token set or an
/// RFC 8628/6749 error code (authorization_pending, slow_down, ...).
/// </summary>
internal class TokenResponse
{
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }

    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}

/// <summary>
/// Raised when the device flow fails (denied, expired, malformed response).
/// The message is user-facing (Korean, consistent with the login UI).
/// </summary>
public class DeviceFlowException : Exception
{
    public DeviceFlowException(string message) : base(message) { }
    public DeviceFlowException(string message, Exception innerException) : base(message, innerException) { }
}
