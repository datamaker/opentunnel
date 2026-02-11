using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace VPNClient.Views;

/// <summary>
/// Interaction logic for SettingsView.xaml
/// </summary>
public partial class SettingsView : UserControl
{
    private readonly ILogger<SettingsView> _logger;

    public event EventHandler? CloseRequested;

    public SettingsView()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<SettingsView>>();

        // Load current settings
        LoadSettings();

        // Subscribe to slider changes
        MtuSlider.ValueChanged += MtuSlider_ValueChanged;
    }

    private void LoadSettings()
    {
        try
        {
            var settings = Properties.Settings.Default;

            StartWithWindowsCheckBox.IsChecked = settings.StartWithWindows;
            AutoConnectCheckBox.IsChecked = settings.AutoConnect;
            MinimizeToTrayCheckBox.IsChecked = settings.MinimizeToTray;
            KillSwitchCheckBox.IsChecked = settings.KillSwitch;
            MtuSlider.Value = settings.MtuSize;
            MtuTextBox.Text = settings.MtuSize.ToString();
            CustomDnsTextBox.Text = settings.CustomDns;
            EnableLoggingCheckBox.IsChecked = settings.EnableLogging;
            TimeoutTextBox.Text = settings.ConnectionTimeout.ToString();

            _logger.LogDebug("Settings loaded successfully");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load settings, using defaults");
            ResetToDefaults();
        }
    }

    private void SaveSettings()
    {
        try
        {
            var settings = Properties.Settings.Default;

            settings.StartWithWindows = StartWithWindowsCheckBox.IsChecked ?? false;
            settings.AutoConnect = AutoConnectCheckBox.IsChecked ?? false;
            settings.MinimizeToTray = MinimizeToTrayCheckBox.IsChecked ?? false;
            settings.KillSwitch = KillSwitchCheckBox.IsChecked ?? false;
            settings.MtuSize = (int)MtuSlider.Value;
            settings.CustomDns = CustomDnsTextBox.Text.Trim();
            settings.EnableLogging = EnableLoggingCheckBox.IsChecked ?? true;

            if (int.TryParse(TimeoutTextBox.Text, out int timeout) && timeout > 0)
            {
                settings.ConnectionTimeout = timeout;
            }

            settings.Save();

            // Handle Windows startup setting
            UpdateStartupSetting(settings.StartWithWindows);

            _logger.LogInformation("Settings saved successfully");
            MessageBox.Show("Settings saved successfully!", "Settings",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save settings");
            MessageBox.Show($"Failed to save settings: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UpdateStartupSetting(bool startWithWindows)
    {
        try
        {
            var runKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);

            if (runKey == null) return;

            const string appName = "VPNClient";

            if (startWithWindows)
            {
                var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(exePath))
                {
                    runKey.SetValue(appName, $"\"{exePath}\"");
                }
            }
            else
            {
                runKey.DeleteValue(appName, false);
            }

            runKey.Close();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to update Windows startup setting");
        }
    }

    private void ResetToDefaults()
    {
        StartWithWindowsCheckBox.IsChecked = false;
        AutoConnectCheckBox.IsChecked = false;
        MinimizeToTrayCheckBox.IsChecked = true;
        KillSwitchCheckBox.IsChecked = false;
        MtuSlider.Value = 1400;
        MtuTextBox.Text = "1400";
        CustomDnsTextBox.Text = string.Empty;
        EnableLoggingCheckBox.IsChecked = true;
        TimeoutTextBox.Text = "30";
    }

    private void MtuSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (MtuTextBox != null)
        {
            MtuTextBox.Text = ((int)e.NewValue).ToString();
        }
    }

    private void MtuTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (int.TryParse(MtuTextBox.Text, out int value))
        {
            if (value >= 576 && value <= 1500)
            {
                MtuSlider.Value = value;
            }
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        SaveSettings();
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    private void ResetButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to reset all settings to their default values?",
            "Reset Settings",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            ResetToDefaults();
            _logger.LogInformation("Settings reset to defaults");
        }
    }
}
