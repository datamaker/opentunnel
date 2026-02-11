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

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

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
        if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
        base.OnExit(e);
    }
}
