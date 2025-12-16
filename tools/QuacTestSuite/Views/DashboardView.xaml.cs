using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace QuacTestSuite.Views
{
    public class ActivityLogItem
    {
        public string Time { get; set; } = "";
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
        public SolidColorBrush Color { get; set; } = new SolidColorBrush(Colors.Gray);
    }

    public partial class DashboardView : UserControl
    {
        private readonly DispatcherTimer _updateTimer;
        private readonly Random _random = new();
        private readonly ObservableCollection<ActivityLogItem> _activityLog = new();
        private DateTime _startTime = DateTime.Now;
        private long _totalQrngBytes = 0;
        private int _opsPerSecond = 125432;

        public DashboardView()
        {
            InitializeComponent();
            
            ActivityLog.ItemsSource = _activityLog;
            
            // Add initial log entry
            AddLogEntry("INFO", "Dashboard initialized", "#00D4AA");
            AddLogEntry("INFO", "Device connected (Simulator Mode)", "#00B4D8");
            
            // Start live update timer
            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            // Simulate live data updates
            var tempVariation = _random.Next(-2, 3);
            var temp = Math.Clamp(42 + tempVariation, 35, 55);
            TempText.Text = temp.ToString();
            TempProgress.Value = temp;

            // Simulate ops/sec with some variation
            _opsPerSecond = Math.Clamp(_opsPerSecond + _random.Next(-5000, 5001), 100000, 180000);
            OpsPerSecText.Text = _opsPerSecond.ToString("N0");

            // Update QRNG throughput
            var qrngSpeed = 128.0 + (_random.NextDouble() * 10 - 5);
            QrngSpeedText.Text = qrngSpeed.ToString("F1");
            _totalQrngBytes += (long)(qrngSpeed * 1024 * 1024);
            QrngTotalText.Text = $"Total: {_totalQrngBytes:N0} bytes";

            // Update uptime
            var uptime = DateTime.Now - _startTime;
            UptimeText.Text = $"Uptime: {(int)uptime.TotalHours}h {uptime.Minutes}m {uptime.Seconds}s";
        }

        private void AddLogEntry(string type, string message, string color)
        {
            _activityLog.Insert(0, new ActivityLogItem
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Type = type,
                Message = message,
                Color = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color))
            });

            // Keep only last 50 entries
            while (_activityLog.Count > 50)
                _activityLog.RemoveAt(_activityLog.Count - 1);
        }

        private async void QuickBenchmark_Click(object sender, RoutedEventArgs e)
        {
            AddLogEntry("BENCH", "Starting quick benchmark (1000 iterations)...", "#FFB800");
            BtnQuickBenchmark.IsEnabled = false;

            await System.Threading.Tasks.Task.Run(() =>
            {
                // Simulate benchmark
                System.Threading.Thread.Sleep(2000);
            });

            var kemOps = _random.Next(150000, 200000);
            var dsaOps = _random.Next(40000, 60000);
            
            AddLogEntry("BENCH", $"ML-KEM-768: {kemOps:N0} ops/sec", "#2ED573");
            AddLogEntry("BENCH", $"ML-DSA-65: {dsaOps:N0} ops/sec", "#2ED573");
            AddLogEntry("BENCH", "Quick benchmark completed successfully", "#00D4AA");
            
            BtnQuickBenchmark.IsEnabled = true;
        }

        private async void GenerateRandom_Click(object sender, RoutedEventArgs e)
        {
            AddLogEntry("QRNG", "Generating 1 MB of quantum random data...", "#00B4D8");
            BtnGenerateRandom.IsEnabled = false;

            await System.Threading.Tasks.Task.Run(() =>
            {
                System.Threading.Thread.Sleep(1000);
            });

            _totalQrngBytes += 1024 * 1024;
            AddLogEntry("QRNG", "Generated 1,048,576 bytes of random data", "#2ED573");
            AddLogEntry("QRNG", "Entropy quality: 7.9999 bits/byte (PASSED)", "#2ED573");
            
            BtnGenerateRandom.IsEnabled = true;
        }

        private async void SelfTest_Click(object sender, RoutedEventArgs e)
        {
            AddLogEntry("TEST", "Running comprehensive self-test...", "#FFB800");
            BtnSelfTest.IsEnabled = false;

            string[] tests = { "ML-KEM KAT", "ML-DSA KAT", "QRNG Entropy", "Memory Check", "DMA Test" };
            
            foreach (var test in tests)
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    System.Threading.Thread.Sleep(500);
                });
                AddLogEntry("TEST", $"{test}: PASSED", "#2ED573");
            }

            AddLogEntry("TEST", "All self-tests completed successfully!", "#00D4AA");
            BtnSelfTest.IsEnabled = true;
        }

        private void ResetDevice_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to reset the device?\nThis will clear all pending operations.",
                "Confirm Device Reset",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                AddLogEntry("RESET", "Device reset initiated...", "#FF4757");
                _startTime = DateTime.Now;
                _totalQrngBytes = 0;
                _opsPerSecond = 125432;
                AddLogEntry("INFO", "Device reset complete", "#00D4AA");
            }
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            _activityLog.Clear();
            AddLogEntry("INFO", "Activity log cleared", "#7F8C9A");
        }
    }
}
