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

        // Stay signed in across restarts: if we have saved credentials, restore
        // the session and go straight to the Main screen (the user still taps
        // Connect). Otherwise show the login screen.
        var saved = CredentialStore.Load();
        if (saved is { } cred)
        {
            _viewModel.Username = cred.Username;
            _viewModel.Password = cred.Password;
            _viewModel.ServerAddress = cred.Server;
            _viewModel.ServerPort = cred.Port;
            _viewModel.IsAuthenticated = true;
            ShowMain();
        }
        else
        {
            ShowLogin();
        }

        _logger.LogInformation("MainWindow initialized");
    }

    private void ShowLogin()
    {
        if (_loginView == null)
        {
            _loginView = new LoginView();
            _loginView.LoginSuccessful += (_, _) => ShowMain();
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
