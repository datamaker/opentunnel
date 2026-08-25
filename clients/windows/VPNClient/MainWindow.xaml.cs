using System.ComponentModel;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Services;
using VPNClient.ViewModels;
using VPNClient.Views;

namespace VPNClient;

/// <summary>
/// Thin shell window that navigates between the three screens
/// (Login, Main, Settings) by swapping the content of a single
/// <see cref="System.Windows.Controls.ContentControl"/>.
/// </summary>
public partial class MainWindow : Window
{
    private readonly ILogger<MainWindow> _logger;
    private readonly MainViewModel _viewModel;
    private readonly TrayIconManager _tray;

    private LoginView? _loginView;
    private MainView? _mainView;
    private SettingsView? _settingsView;

    public MainWindow()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<MainWindow>>();
        _viewModel = App.ServiceProvider.GetRequiredService<MainViewModel>();

        // The shared view-model is the DataContext for every screen; the
        // hosted UserControls inherit it through the ContentControl.
        DataContext = _viewModel;

        // System-tray status icon (green/amber/gray). Lives for the app's
        // lifetime; see OnClosing for the close-to-tray behavior.
        _tray = new TrayIconManager(this, _viewModel);

        // Stay signed in across restarts: if we have a saved SSO session or
        // saved credentials, restore the session and go straight to the Main
        // screen. Otherwise show the login screen.
        var restoredSession = false;

        if (CredentialStore.LoadSsoSession() is { } sso)
        {
            // SSO session: no password stored — reconnects authenticate with
            // the DPAPI-protected 30-day session token ({authType:"session"}).
            _viewModel.Username = sso.Username;
            _viewModel.SessionToken = sso.SessionToken;
            _viewModel.AuthMode = CredentialStore.AuthModeSso;
            _viewModel.ServerAddress = sso.Server;
            _viewModel.ServerPort = sso.Port;
            _viewModel.IsAuthenticated = true;
            ShowMain();
            restoredSession = true;
        }
        else if (CredentialStore.Load() is { } cred)
        {
            _viewModel.Username = cred.Username;
            _viewModel.Password = cred.Password;
            _viewModel.AuthMode = CredentialStore.AuthModePassword;
            _viewModel.ServerAddress = cred.Server;
            _viewModel.ServerPort = cred.Port;
            _viewModel.IsAuthenticated = true;
            ShowMain();
            restoredSession = true;
        }
        else
        {
            ShowLogin();
        }

        // On restart with a remembered session, auto-connect only if the user
        // opted into it (AutoConnect toggle). A fresh login always auto-connects
        // — see OnLoginSuccessful — regardless of that toggle.
        if (restoredSession && IsAutoConnectOnStartupEnabled())
        {
            TriggerAutoConnect();
        }

        _logger.LogInformation("MainWindow initialized");
    }

    /// <summary>The "Auto-connect on startup" setting, defaulting to false if it
    /// can't be read.</summary>
    private static bool IsAutoConnectOnStartupEnabled()
    {
        try
        {
            return Properties.Settings.Default.AutoConnect;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Kick off a connection without waiting for the user to press Connect.
    /// Routes through the shared <see cref="MainViewModel.ConnectCommand"/>
    /// (same path as the tray "Connect"), which guards against connecting when
    /// already connected/connecting and re-arms unexpected-drop detection.
    /// </summary>
    private void TriggerAutoConnect()
    {
        if (_viewModel.IsConnected || _viewModel.IsConnecting)
        {
            return;
        }

        if (_viewModel.ConnectCommand.CanExecute(null))
        {
            _logger.LogInformation("Auto-connecting VPN");
            _viewModel.ConnectCommand.Execute(null);
        }
    }

    /// <summary>
    /// A login (password or SSO) just succeeded: show the Main screen and
    /// connect immediately. Always auto-connects — the AutoConnect setting
    /// governs only the connect-on-restart behavior, not a fresh sign-in.
    /// </summary>
    private void OnLoginSuccessful()
    {
        ShowMain();
        TriggerAutoConnect();
    }

    private void ShowLogin()
    {
        if (_loginView == null)
        {
            _loginView = new LoginView();
            _loginView.LoginSuccessful += (_, _) => OnLoginSuccessful();
        }

        RootContent.Content = _loginView;
    }

    private void ShowMain()
    {
        if (_mainView == null)
        {
            _mainView = new MainView();
            _mainView.SettingsRequested += (_, _) => ShowSettings();
            _mainView.LogoutRequested += (_, _) => ShowLogin();
        }

        RootContent.Content = _mainView;
    }

    private void ShowSettings()
    {
        if (_settingsView == null)
        {
            _settingsView = new SettingsView();
            _settingsView.CloseRequested += (_, _) => ShowMain();
        }

        RootContent.Content = _settingsView;
    }

    /// <summary>
    /// Bring the window back from the tray: show it, un-minimize, and pull it to
    /// the foreground. Safe to call from any thread — it marshals onto the UI
    /// thread itself. This is the single restore path shared by the tray "Open"
    /// menu (<see cref="Services.TrayIconManager"/>) and the single-instance
    /// activation signal (a second launch surfaces the running window).
    /// </summary>
    public void RestoreFromTray()
    {
        Dispatcher.Invoke(() =>
        {
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            Activate();
            // Nudge to the foreground without staying pinned on top.
            Topmost = true;
            Topmost = false;
        });
    }

    /// <summary>
    /// Closing the window hides it to the tray instead of quitting, so the VPN
    /// keeps running in the background (like OpenVPN). The app only truly exits
    /// when the user picks "Exit" from the tray menu.
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_tray.ExitRequested)
        {
            e.Cancel = true;
            Hide();
            _tray.ShowHideToTrayHintOnce();
            return;
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        // Real exit: disconnect the tunnel and release the tray icon.
        _mainView?.Cleanup();
        _tray.Dispose();
        base.OnClosed(e);
    }
}
