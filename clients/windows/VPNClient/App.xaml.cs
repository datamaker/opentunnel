using System.Threading;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Services;
using VPNClient.ViewModels;
using VPNClient.Network;

namespace VPNClient;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private static IServiceProvider? _serviceProvider;

    public static IServiceProvider ServiceProvider => _serviceProvider
        ?? throw new InvalidOperationException("Service provider not initialized");

    // Single-instance coordination. Local\ scope keeps these per interactive
    // logon session (i.e. per user), so different users can each run their own
    // instance. The mutex distinguishes the first launch from later ones; the
    // event lets a later launch tell the running instance to surface its window.
    private const string SingleInstanceMutexName = @"Local\OpenTunnel.SingleInstance";
    private const string ShowWindowEventName = @"Local\OpenTunnel.ShowWindow";

    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _signalListenerThread;
    private volatile bool _shuttingDown;
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Single-instance guard: only the first launch creates (and owns) the
        // named mutex. A later launch signals the running instance to surface
        // its window and exits immediately — without building services or a
        // second window (the app otherwise lives in the tray).
        _singleInstanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
        if (!createdNew)
        {
            SignalRunningInstance();
            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
            Shutdown();
            return;
        }

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        var logger = _serviceProvider.GetRequiredService<ILogger<App>>();
        logger.LogInformation("VPN Client starting up...");

        // Set up global exception handling
        AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
        {
            var ex = (Exception)args.ExceptionObject;
            logger.LogCritical(ex, "Unhandled exception occurred");
            MessageBox.Show($"A critical error occurred: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        };

        DispatcherUnhandledException += (sender, args) =>
        {
            logger.LogError(args.Exception, "Dispatcher unhandled exception");
            MessageBox.Show($"An error occurred: {args.Exception.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        // StartupUri was removed from App.xaml so we own window creation; show
        // the main window explicitly now that the services it needs are ready.
        _showWindowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowWindowEventName);
        _mainWindow = new MainWindow();
        this.MainWindow = _mainWindow;
        _mainWindow.Show();

        // Start listening only after the window exists, so a signal that races
        // startup always finds a window to restore.
        StartSignalListener();
    }

    /// <summary>
    /// A second instance is starting: open the running instance's named event
    /// and set it so its listener surfaces the window. Best-effort — if the
    /// handle can't be opened (e.g. the owner is mid-shutdown) we just exit.
    /// </summary>
    private static void SignalRunningInstance()
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(ShowWindowEventName, out var existing))
            {
                using (existing)
                {
                    existing.Set();
                }
            }
        }
        catch
        {
            // Best effort — a failure here just means the running window
            // isn't surfaced; the second instance still exits cleanly.
        }
    }

    /// <summary>
    /// Background listener that waits on the named event and restores the main
    /// window whenever another launch signals it. Runs for the app's lifetime;
    /// woken and stopped on exit via <see cref="_shuttingDown"/> + a final Set.
    /// </summary>
    private void StartSignalListener()
    {
        _signalListenerThread = new Thread(() =>
        {
            while (!_shuttingDown)
            {
                try
                {
                    _showWindowEvent!.WaitOne();
                }
                catch
                {
                    break;
                }

                if (_shuttingDown)
                {
                    break;
                }

                // RestoreFromTray marshals onto the UI thread itself.
                _mainWindow?.RestoreFromTray();
            }
        })
        {
            IsBackground = true,
            Name = "OpenTunnel-SingleInstanceListener"
        };

        _signalListenerThread.Start();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        // Services
        services.AddSingleton<WintunAdapter>();
        services.AddSingleton<TlsConnection>();
        services.AddSingleton<VpnTunnel>();

        // ViewModels
        services.AddSingleton<MainViewModel>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Stop the single-instance listener: flag shutdown, then wake it so it
        // observes the flag and exits its wait loop.
        _shuttingDown = true;
        try
        {
            _showWindowEvent?.Set();
        }
        catch
        {
            // Ignore — the handle may already be disposed.
        }
        _showWindowEvent?.Dispose();
        _showWindowEvent = null;

        // Release the single-instance mutex so the next launch is treated as the
        // first instance again. ReleaseMutex must run on the acquiring thread;
        // OnStartup and OnExit both run on the app's main (UI) thread.
        if (_singleInstanceMutex != null)
        {
            try
            {
                _singleInstanceMutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not the owner / already released — safe to ignore.
            }
            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
        }

        if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
        base.OnExit(e);
    }
}
