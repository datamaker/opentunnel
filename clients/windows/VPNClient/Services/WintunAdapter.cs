using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace VPNClient.Services;

/// <summary>
/// WinTun adapter wrapper for managing the virtual network interface
/// Uses P/Invoke to interact with wintun.dll
/// </summary>
public unsafe class WintunAdapter : IDisposable
{
    private readonly ILogger<WintunAdapter> _logger;

    private IntPtr _adapter;
    private IntPtr _session;
    private IntPtr _readEvent;
    private bool _isInitialized;
    private bool _isDisposed;

    private readonly Channel<byte[]> _receiveChannel;
    private readonly Channel<byte[]> _sendChannel;
    private Task? _readTask;
    private Task? _writeTask;
    private CancellationTokenSource? _cancellationTokenSource;

    private const int WINTUN_MIN_RING_CAPACITY = 0x20000;   // 128 KB
    private const int WINTUN_MAX_RING_CAPACITY = 0x4000000; // 64 MB
    private const int WINTUN_RING_CAPACITY = 0x400000;      // 4 MB

    private const string ADAPTER_NAME = "VPNClient";
    private const string TUNNEL_TYPE = "VPN";

    // WinTun GUID for our adapter
    private static readonly Guid AdapterGuid = new("8D1BE3A2-6B85-4A5C-B7E3-C8F7D2A1E9B3");

    public WintunAdapter(ILogger<WintunAdapter> logger)
    {
        _logger = logger;
        _receiveChannel = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(1000)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });
        _sendChannel = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(1000)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });
    }

    /// <summary>
    /// Initialize the WinTun adapter with the specified configuration
    /// </summary>
    public async Task InitializeAsync(string ipAddress, string subnetMask, string gateway, string[] dns, int mtu)
    {
        if (_isInitialized)
        {
            throw new InvalidOperationException("WinTun adapter is already initialized");
        }

        await Task.Run(() =>
        {
            _logger.LogInformation("Initializing WinTun adapter");

            try
            {
                // Create the adapter
                _adapter = WintunCreateAdapter(ADAPTER_NAME, TUNNEL_TYPE, ref AdapterGuid);
                if (_adapter == IntPtr.Zero)
                {
                    var error = Marshal.GetLastWin32Error();
                    throw new WintunException($"Failed to create WinTun adapter. Error code: {error}");
                }

                _logger.LogDebug("WinTun adapter created successfully");

                // Start the session
                _session = WintunStartSession(_adapter, WINTUN_RING_CAPACITY);
                if (_session == IntPtr.Zero)
                {
                    var error = Marshal.GetLastWin32Error();
                    throw new WintunException($"Failed to start WinTun session. Error code: {error}");
                }

                _logger.LogDebug("WinTun session started successfully");

                // Get the read event handle for waiting on packets
                _readEvent = WintunGetReadWaitEvent(_session);
                if (_readEvent == IntPtr.Zero)
                {
                    throw new WintunException("Failed to get read wait event");
                }

                _isInitialized = true;
            }
            catch (Exception)
            {
                Cleanup();
                throw;
            }
        });

        // Configure the network interface
        await ConfigureInterfaceAsync(ipAddress, subnetMask, gateway, dns, mtu);

        // Start the read/write tasks
        _cancellationTokenSource = new CancellationTokenSource();
        StartIoTasks(_cancellationTokenSource.Token);

        _logger.LogInformation("WinTun adapter initialized successfully with IP: {IP}", ipAddress);
    }

    /// <summary>
    /// Configure the network interface with IP, gateway, DNS, etc.
    /// </summary>
    private async Task ConfigureInterfaceAsync(string ipAddress, string subnetMask, string gateway, string[] dns, int mtu)
    {
        _logger.LogInformation("Configuring network interface");

        // Get adapter LUID for configuration
        var luid = GetAdapterLuid();
        if (luid == 0)
        {
            throw new WintunException("Failed to get adapter LUID");
        }

        // Use netsh to configure the interface (more reliable than direct API calls)
        await RunNetshCommandAsync($"interface ip set address name=\"{ADAPTER_NAME}\" static {ipAddress} {subnetMask} {gateway}");

        // Configure DNS
        if (dns != null && dns.Length > 0)
        {
            await RunNetshCommandAsync($"interface ip set dns name=\"{ADAPTER_NAME}\" static {dns[0]}");

            for (int i = 1; i < dns.Length; i++)
            {
                await RunNetshCommandAsync($"interface ip add dns name=\"{ADAPTER_NAME}\" {dns[i]} index={i + 1}");
            }
        }

        // Set MTU
        await RunNetshCommandAsync($"interface ipv4 set subinterface \"{ADAPTER_NAME}\" mtu={mtu} store=persistent");

        _logger.LogInformation("Network interface configured: IP={IP}, Gateway={Gateway}, DNS={DNS}, MTU={MTU}",
            ipAddress, gateway, string.Join(", ", dns ?? Array.Empty<string>()), mtu);
    }

    private async Task RunNetshCommandAsync(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Verb = "runas" // Run as administrator
        };

        using var process = Process.Start(psi);
        if (process == null)
        {
            throw new WintunException($"Failed to start netsh command: {arguments}");
        }

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            var error = await process.StandardError.ReadToEndAsync();
            _logger.LogWarning("netsh command failed: {Arguments}, Error: {Error}", arguments, error);
        }
    }

    private ulong GetAdapterLuid()
    {
        if (_adapter == IntPtr.Zero)
            return 0;

        ulong luid = 0;
        WintunGetAdapterLUID(_adapter, ref luid);
        return luid;
    }

    private void StartIoTasks(CancellationToken cancellationToken)
    {
        // Read task - reads packets from the TUN interface
        _readTask = Task.Run(async () =>
        {
            _logger.LogDebug("Starting TUN read task");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Wait for packets to be available
                    var waitResult = WaitForSingleObject(_readEvent, 100); // 100ms timeout

                    if (waitResult == WAIT_TIMEOUT)
                        continue;

                    if (waitResult != WAIT_OBJECT_0)
                    {
                        _logger.LogWarning("WaitForSingleObject returned: {Result}", waitResult);
                        continue;
                    }

                    // Read all available packets
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        uint packetSize;
                        var packetPtr = WintunReceivePacket(_session, &packetSize);

                        if (packetPtr == null)
                            break;

                        if (packetSize > 0)
                        {
                            var packet = new byte[packetSize];
                            Marshal.Copy((IntPtr)packetPtr, packet, 0, (int)packetSize);

                            await _receiveChannel.Writer.WriteAsync(packet, cancellationToken);
                        }

                        WintunReleaseReceivePacket(_session, packetPtr);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error reading from TUN interface");
                }
            }

            _logger.LogDebug("TUN read task stopped");
        }, cancellationToken);

        // Write task - writes packets to the TUN interface
        _writeTask = Task.Run(async () =>
        {
            _logger.LogDebug("Starting TUN write task");

            await foreach (var packet in _sendChannel.Reader.ReadAllAsync(cancellationToken))
            {
                try
                {
                    var packetPtr = WintunAllocateSendPacket(_session, (uint)packet.Length);
                    if (packetPtr == null)
                    {
                        _logger.LogWarning("Failed to allocate send packet");
                        continue;
                    }

                    Marshal.Copy(packet, 0, (IntPtr)packetPtr, packet.Length);
                    WintunSendPacket(_session, packetPtr);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error writing to TUN interface");
                }
            }

            _logger.LogDebug("TUN write task stopped");
        }, cancellationToken);
    }

    /// <summary>
    /// Read a packet from the TUN interface
    /// </summary>
    public async Task<byte[]?> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        if (!_isInitialized)
        {
            throw new InvalidOperationException("WinTun adapter is not initialized");
        }

        try
        {
            return await _receiveChannel.Reader.ReadAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Write a packet to the TUN interface
    /// </summary>
    public async Task WritePacketAsync(byte[] packet)
    {
        if (!_isInitialized)
        {
            throw new InvalidOperationException("WinTun adapter is not initialized");
        }

        await _sendChannel.Writer.WriteAsync(packet);
    }

    /// <summary>
    /// Shutdown the WinTun adapter
    /// </summary>
    public async Task ShutdownAsync()
    {
        if (!_isInitialized)
            return;

        _logger.LogInformation("Shutting down WinTun adapter");

        _cancellationTokenSource?.Cancel();

        // Wait for IO tasks to complete
        var tasks = new List<Task>();
        if (_readTask != null) tasks.Add(_readTask);
        if (_writeTask != null) tasks.Add(_writeTask);

        if (tasks.Count > 0)
        {
            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error waiting for IO tasks to complete");
            }
        }

        await Task.Run(Cleanup);

        _logger.LogInformation("WinTun adapter shut down");
    }

    private void Cleanup()
    {
        if (_session != IntPtr.Zero)
        {
            WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
        _isInitialized = false;
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        _ = ShutdownAsync();
    }

    #region WinTun P/Invoke

    private const string WINTUN_DLL = "wintun.dll";

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr WintunCreateAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string Name,
        [MarshalAs(UnmanagedType.LPWStr)] string TunnelType,
        ref Guid RequestedGUID);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr WintunOpenAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string Name);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunCloseAdapter(IntPtr Adapter);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunDeleteDriver();

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunGetAdapterLUID(IntPtr Adapter, ref ulong Luid);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr WintunStartSession(IntPtr Adapter, uint Capacity);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunEndSession(IntPtr Session);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WintunGetReadWaitEvent(IntPtr Session);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern byte* WintunReceivePacket(IntPtr Session, uint* PacketSize);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunReleaseReceivePacket(IntPtr Session, byte* Packet);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern byte* WintunAllocateSendPacket(IntPtr Session, uint PacketSize);

    [DllImport(WINTUN_DLL, CallingConvention = CallingConvention.StdCall)]
    private static extern void WintunSendPacket(IntPtr Session, byte* Packet);

    // Kernel32 imports for event handling
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint WAIT_FAILED = 0xFFFFFFFF;

    #endregion
}

/// <summary>
/// Exception for WinTun-specific errors
/// </summary>
public class WintunException : Exception
{
    public WintunException(string message) : base(message) { }
    public WintunException(string message, Exception innerException) : base(message, innerException) { }
}
