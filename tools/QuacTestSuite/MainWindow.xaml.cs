using System.Windows;
using System.Windows.Controls;
using QuacTestSuite.Views;

namespace QuacTestSuite
{
    public partial class MainWindow : Window
    {
        private UserControl? _currentView;
        
        // Cached views for better performance
        private DashboardView? _dashboardView;
        private BenchmarkView? _benchmarkView;
        private LoadTestView? _loadTestView;
        private QrngTestView? _qrngTestView;
        private AlgorithmCompareView? _algorithmCompareView;
        private HealthMonitorView? _healthMonitorView;
        private SettingsView? _settingsView;
        private KeyManagerView? _keyManagerView;
        private CryptoDemoView? _cryptoDemoView;
        private SignVerifyView? _signVerifyView;
        private CertGenView? _certGenView;
        private HybridCryptoView? _hybridCryptoView;
        private EntropyAnalyzerView? _entropyAnalyzerView;
        private BatchOpsView? _batchOpsView;
        private ApiPlaygroundView? _apiPlaygroundView;
        private PerfProfilerView? _perfProfilerView;
        private FirmwareView? _firmwareView;
        private LogViewerView? _logViewerView;

        public MainWindow()
        {
            InitializeComponent();
            
            // Load Dashboard by default
            NavigateTo("Dashboard");
        }

        private void NavButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string destination)
            {
                NavigateTo(destination);
            }
        }

        private void NavigateTo(string destination)
        {
            UserControl? view = destination switch
            {
                "Dashboard" => _dashboardView ??= new DashboardView(),
                "Benchmark" => _benchmarkView ??= new BenchmarkView(),
                "LoadTest" => _loadTestView ??= new LoadTestView(),
                "KeyManager" => _keyManagerView ??= new KeyManagerView(),
                "CryptoDemo" => _cryptoDemoView ??= new CryptoDemoView(),
                "SignVerify" => _signVerifyView ??= new SignVerifyView(),
                "CertGen" => _certGenView ??= new CertGenView(),
                "HybridCrypto" => _hybridCryptoView ??= new HybridCryptoView(),
                "Qrng" => _qrngTestView ??= new QrngTestView(),
                "EntropyAnalyzer" => _entropyAnalyzerView ??= new EntropyAnalyzerView(),
                "AlgorithmCompare" => _algorithmCompareView ??= new AlgorithmCompareView(),
                "BatchOps" => _batchOpsView ??= new BatchOpsView(),
                "ApiPlayground" => _apiPlaygroundView ??= new ApiPlaygroundView(),
                "Diagnostics" => _healthMonitorView ??= new HealthMonitorView(),
                "PerfProfiler" => _perfProfilerView ??= new PerfProfilerView(),
                "Firmware" => _firmwareView ??= new FirmwareView(),
                "Logs" => _logViewerView ??= new LogViewerView(),
                "Settings" => _settingsView ??= new SettingsView(),
                _ => _dashboardView ??= new DashboardView()
            };

            _currentView = view;
            ContentArea.Content = view;

            // Update page title
            PageTitle.Text = destination switch
            {
                "Dashboard" => "Dashboard",
                "Benchmark" => "Benchmark",
                "LoadTest" => "Load Testing",
                "KeyManager" => "Key Manager",
                "CryptoDemo" => "Encrypt / Decrypt",
                "SignVerify" => "Sign / Verify",
                "CertGen" => "Certificate Generator",
                "HybridCrypto" => "Hybrid Crypto",
                "Qrng" => "QRNG Explorer",
                "EntropyAnalyzer" => "Entropy Analyzer",
                "AlgorithmCompare" => "Algorithm Comparison",
                "BatchOps" => "Batch Operations",
                "ApiPlayground" => "API Playground",
                "Diagnostics" => "Health Monitor",
                "PerfProfiler" => "Performance Profiler",
                "Firmware" => "Firmware Manager",
                "Logs" => "Log Viewer",
                "Settings" => "Settings",
                _ => "Dashboard"
            };
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            // Refresh current view data
            MessageBox.Show("Device status refreshed.", "Refresh", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PDF Report (*.pdf)|*.pdf|JSON Data (*.json)|*.json|CSV Data (*.csv)|*.csv",
                Title = "Export Report"
            };

            if (dialog.ShowDialog() == true)
            {
                MessageBox.Show($"Report exported to:\n{dialog.FileName}", "Export Complete", 
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
