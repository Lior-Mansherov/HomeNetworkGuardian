using HomeNetworkGuardian.Models;
using HomeNetworkGuardian.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace HomeNetworkGuardian.Views
{
    /// <summary>
    /// Main View Logic. Orchestrates the interaction between the UI and backend services.
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly OUIService ouiService;
        private readonly DeviceClassifier deviceClassifier;

        public MainWindow()
        {
            InitializeComponent();

            // Setup paths for configuration and database files
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string ouiJsonPath = Path.Combine(baseDir, "Data", "oui.json");
            string deviceTypeMapPath = Path.Combine(baseDir, "Data", "DeviceTypeMap.json");

            // Dependency Injection (Manual): Loading databases into services
            List<OuiEntry> ouiDatabase = DataUtils.LoadOuiDatabase(ouiJsonPath);
            ouiService = new OUIService(ouiDatabase);

            var deviceTypeDatabase = DataUtils.LoadVendorMapFromJson(deviceTypeMapPath);
            deviceClassifier = new DeviceClassifier(deviceTypeDatabase);
        }

        /// <summary>
        /// Event handler for the scan button. 
        /// Uses async/await to keep the UI responsive during network operations.
        /// </summary>
        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // UI Visual Feedback
                btnStartScan.IsEnabled = false;
                lblStatus.Content = "Scanning network... Please wait.";

                // 1. Execute Scan in a background thread
                string networkRange = NetworkUtils.FindLocalNetworkRange();
                var devices = await Task.Run(() => NmapScanner.ScanNetwork(networkRange));

                if (devices == null || devices.Count == 0)
                {
                    MessageBox.Show("No devices found or scan failed.", "Scan Result", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 2. Post-Processing: Enrichment and Classification
                foreach (var device in devices)
                {
                    device.Vendor = ouiService.GetVendor(device.MAC);
                    device.DeviceType = deviceClassifier.DetermineDeviceType(device);

                    // Simple Security Heuristic: Mark as suspicious if identity is hidden or services are unknown
                    // TODO: Enhance suspicion logic. 
                    // Current heuristic: flagged if vendor or ports are unidentified.
                    // Future: integrate with port-risk dictionary (e.g., flagging ports 21, 23, 445).
                    device.IsSuspicious = (device.Vendor == "Unknown" || device.OpenPorts.Contains("Unknown"));
                }

                // 3. Update UI (DataGrid)
                dgDevices.ItemsSource = devices;
                lblStatus.Content = $"Scan complete. {devices.Count} devices found.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred during scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Debug.WriteLine($"[UI Error] {ex.Message}");
            }
            finally
            {
                btnStartScan.IsEnabled = true;
            }
        }
    }
}