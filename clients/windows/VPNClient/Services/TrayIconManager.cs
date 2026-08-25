using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using VPNClient.ViewModels;
using Forms = System.Windows.Forms;
using WpfApplication = System.Windows.Application;
using WpfWindow = System.Windows.Window;

namespace VPNClient.Services;

/// <summary>
/// Owns the system-tray (notification area) icon that mirrors the VPN status,
/// so the user can see whether the tunnel is up — and connect/disconnect —
/// without opening the main window (parity with the macOS menu-bar item).
///
/// The icon is a colored dot: green = connected, amber = connecting,
/// gray = disconnected. It stays visible for the lifetime of the app; closing
/// the window hides it to the tray (the VPN keeps running), and "Exit" from the
/// tray menu is the only way to fully quit.
/// </summary>
public sealed class TrayIconManager : IDisposable
{
    private readonly WpfWindow _window;
    private readonly MainViewModel _viewModel;
    private readonly Forms.NotifyIcon _notifyIcon;

    private readonly Forms.ToolStripMenuItem _statusItem;
    private readonly Forms.ToolStripMenuItem _connectItem;
    private readonly Forms.ToolStripMenuItem _disconnectItem;

    private readonly Icon _connectedIcon;
    private readonly Icon _connectingIcon;
    private readonly Icon _disconnectedIcon;
    // Native HICON handles behind the Icon objects above; freed on Dispose.
    private readonly List<IntPtr> _iconHandles = new();

    private bool _hideHintShown;
    private bool _disposed;

    /// <summary>True once the user picked "Exit" from the tray menu, telling the
    /// window it should really close instead of hiding to the tray.</summary>
    public bool ExitRequested { get; private set; }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);

    public TrayIconManager(WpfWindow window, MainViewModel viewModel)
    {
        _window = window;
        _viewModel = viewModel;

        // Match the app's brand status colors (App.xaml): Success / Warning / Secondary.
        _connectedIcon = CreateDotIcon(Color.FromArgb(16, 124, 16));    // #107C10
        _connectingIcon = CreateDotIcon(Color.FromArgb(255, 185, 0));   // #FFB900
        _disconnectedIcon = CreateDotIcon(Color.FromArgb(140, 140, 140));

        _statusItem = new Forms.ToolStripMenuItem("Disconnected") { Enabled = false };
        _connectItem = new Forms.ToolStripMenuItem("Connect", null, (_, _) => Invoke(_viewModel.ConnectCommand));
        _disconnectItem = new Forms.ToolStripMenuItem("Disconnect", null, (_, _) => Invoke(_viewModel.DisconnectCommand));
        var showItem = new Forms.ToolStripMenuItem("Open OpenTunnel", null, (_, _) => ShowWindow());
        var exitItem = new Forms.ToolStripMenuItem("Exit", null, (_, _) => ExitApp());

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_connectItem);
        menu.Items.Add(_disconnectItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(showItem);
        menu.Items.Add(exitItem);

        _notifyIcon = new Forms.NotifyIcon
        {
            Icon = _disconnectedIcon,
            Text = "OpenTunnel — Disconnected",
            Visible = true,
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => ShowWindow();

        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _viewModel.TrayNotificationRequested += OnTrayNotificationRequested;
        UpdateVisuals();
    }

    // MARK: - View-model → tray sync

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.IsConnected)
            or nameof(MainViewModel.IsConnecting)
            or nameof(MainViewModel.IsReconnecting)
            or nameof(MainViewModel.ConnectionStatus))
        {
            // Tunnel events can arrive on background threads; touch the tray on the UI thread.
            _window.Dispatcher.Invoke(UpdateVisuals);
        }
    }

    /// <summary>
    /// Balloon notifications from the view-model: unexpected disconnect,
    /// successful reconnect, or reconnect failure. The view-model already
    /// checks the DisconnectNotify setting before raising this.
    /// </summary>
    private void OnTrayNotificationRequested(object? sender, TrayNotificationEventArgs e)
    {
        // Raised from tunnel/retry-loop background threads; NotifyIcon is UI-affine.
        _window.Dispatcher.Invoke(() =>
        {
            if (_disposed) return;
            _notifyIcon.ShowBalloonTip(
                5000,
                e.Title,
                e.Message,
                e.IsError ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
        });
    }

    private void UpdateVisuals()
    {
        if (_disposed) return;

        var status = _viewModel.ConnectionStatus;

        if (_viewModel.IsConnected)
        {
            _notifyIcon.Icon = _connectedIcon;
        }
        else if (_viewModel.IsConnecting || _viewModel.IsReconnecting)
        {
            _notifyIcon.Icon = _connectingIcon;
        }
        else
        {
            _notifyIcon.Icon = _disconnectedIcon;
        }

        // NotifyIcon.Text is capped at 63 characters.
        _notifyIcon.Text = Truncate($"OpenTunnel — {status}", 63);
        _statusItem.Text = status;

        _connectItem.Enabled = _viewModel.IsAuthenticated && !_viewModel.IsConnected
            && !_viewModel.IsConnecting && !_viewModel.IsReconnecting;
        // Keep Disconnect available while auto-reconnecting so the user can
        // abort the retry loop from the tray.
        _disconnectItem.Enabled = _viewModel.IsConnected || _viewModel.IsConnecting || _viewModel.IsReconnecting;
    }

    // MARK: - Actions

    private static void Invoke(System.Windows.Input.ICommand command)
    {
        if (command.CanExecute(null))
        {
            command.Execute(null);
        }
    }

    private void ShowWindow()
    {
        // Reuse the window's canonical restore path (also used by the
        // single-instance activation signal) instead of duplicating it here.
        if (_window is MainWindow main)
        {
            main.RestoreFromTray();
        }
    }

    private void ExitApp()
    {
        ExitRequested = true;
        _window.Dispatcher.Invoke(() => WpfApplication.Current.Shutdown());
    }

    /// <summary>
    /// Shown once, the first time the user closes the window to the tray, so the
    /// app doesn't seem to have vanished while the VPN is still up.
    /// </summary>
    public void ShowHideToTrayHintOnce()
    {
        if (_hideHintShown || _disposed) return;
        _hideHintShown = true;
        _notifyIcon.ShowBalloonTip(
            3000,
            "OpenTunnel is still running",
            "The VPN stays connected. Right-click the tray icon to connect, disconnect, or exit.",
            Forms.ToolTipIcon.Info);
    }

    // MARK: - Icon rendering

    /// <summary>Draws a 16×16 filled dot of the given color as a tray icon.</summary>
    private Icon CreateDotIcon(Color color)
    {
        using var bitmap = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var fill = new SolidBrush(color);
            g.FillEllipse(fill, 2, 2, 11, 11);
            using var outline = new Pen(Color.FromArgb(70, 0, 0, 0));
            g.DrawEllipse(outline, 2, 2, 11, 11);
        }

        // GetHicon() creates an unmanaged HICON that Icon.FromHandle does not own;
        // we keep the handle and free it ourselves in Dispose.
        var handle = bitmap.GetHicon();
        _iconHandles.Add(handle);
        return Icon.FromHandle(handle);
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    // MARK: - Cleanup

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _viewModel.TrayNotificationRequested -= OnTrayNotificationRequested;

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();

        _connectedIcon.Dispose();
        _connectingIcon.Dispose();
        _disconnectedIcon.Dispose();
        foreach (var handle in _iconHandles)
        {
            DestroyIcon(handle);
        }
        _iconHandles.Clear();
    }
}
