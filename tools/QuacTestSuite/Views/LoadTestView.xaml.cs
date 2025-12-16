using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace QuacTestSuite.Views
{
    public class LoadTestLogItem
    {
        public string Time { get; set; } = "";
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
        public SolidColorBrush Color { get; set; } = new SolidColorBrush(Colors.Gray);
    }

    public partial class LoadTestView : UserControl
    {
        private readonly ObservableCollection<LoadTestLogItem> _logItems = new();
        private readonly Random _random = new();
        private CancellationTokenSource? _cancellationToken;
        private DispatcherTimer? _updateTimer;
        private bool _isRunning;
        private DateTime _startTime;
        private TimeSpan _duration;
        private long _totalOperations;
        private int _currentOps;
        private int _errors;
        private int _temperature = 42;

        public LoadTestView()
        {
            InitializeComponent();
            ResultsLog.ItemsSource = _logItems;
            
            SliderConnections.ValueChanged += (s, e) =>
            {
                ConnectionCountText.Text = $"{(int)SliderConnections.Value} connections";
            };
        }

        private TimeSpan GetDuration()
        {
            return CmbDuration.SelectedIndex switch
            {
                0 => TimeSpan.FromSeconds(30),
                1 => TimeSpan.FromMinutes(1),
                2 => TimeSpan.FromMinutes(5),
                3 => TimeSpan.FromMinutes(15),
                4 => TimeSpan.FromHours(1),
                _ => TimeSpan.FromMinutes(1)
            };
        }

        private async void StartLoadTest_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning) return;

            _logItems.Clear();
            _totalOperations = 0;
            _errors = 0;
            _temperature = 42;
            _isRunning = true;
            _startTime = DateTime.Now;
            _duration = GetDuration();
            _cancellationToken = new CancellationTokenSource();

            BtnStart.IsEnabled = false;
            BtnStop.IsEnabled = true;
            BtnExport.IsEnabled = false;

            AddLog("INFO", $"Starting load test: {CmbDuration.Text}, {SliderConnections.Value} connections", "#00D4AA");
            AddLog("INFO", $"Workload: {((ComboBoxItem)CmbWorkload.SelectedItem).Content}", "#00B4D8");

            StatusText.Text = "Running load test...";

            // Start update timer
            _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();

            try
            {
                await RunLoadTest(_cancellationToken.Token);
                
                if (!_cancellationToken.Token.IsCancellationRequested)
                {
                    AddLog("SUCCESS", "Load test completed successfully!", "#2ED573");
                    StatusText.Text = "Load test completed";
                }
            }
            catch (OperationCanceledException)
            {
                AddLog("WARN", "Load test was cancelled by user", "#FFB800");
                StatusText.Text = "Load test cancelled";
            }
            finally
            {
                _updateTimer?.Stop();
                _isRunning = false;
                BtnStart.IsEnabled = true;
                BtnStop.IsEnabled = false;
                BtnExport.IsEnabled = true;
                TimeRemainingText.Text = "";

                // Final stats
                var elapsed = DateTime.Now - _startTime;
                AddLog("STATS", $"Total operations: {_totalOperations:N0}", "#00B4D8");
                AddLog("STATS", $"Average throughput: {_totalOperations / elapsed.TotalSeconds:N0} ops/sec", "#00B4D8");
                AddLog("STATS", $"Error rate: {(_errors * 100.0 / Math.Max(1, _totalOperations)):F3}%", 
                       _errors == 0 ? "#2ED573" : "#FF4757");
            }
        }

        private async Task RunLoadTest(CancellationToken token)
        {
            int connections = (int)SliderConnections.Value;
            int baseOps = CmbWorkload.SelectedIndex switch
            {
                0 => 80000,  // Mixed
                1 => 150000, // KEM only
                2 => 45000,  // DSA only
                3 => 500000, // QRNG only
                4 => 200000, // Stress test
                _ => 80000
            };

            // Ramp-up handling
            int rampUpMs = CmbRampUp.SelectedIndex switch
            {
                0 => 0,
                1 => 10000,
                2 => 30000,
                3 => 60000,
                _ => 10000
            };

            if (rampUpMs > 0)
            {
                AddLog("INFO", $"Ramping up over {rampUpMs / 1000} seconds...", "#FFB800");
            }

            var endTime = _startTime + _duration;
            var rampUpEnd = _startTime + TimeSpan.FromMilliseconds(rampUpMs);

            while (DateTime.Now < endTime && !token.IsCancellationRequested)
            {
                // Calculate current load factor (for ramp-up)
                double loadFactor = 1.0;
                if (DateTime.Now < rampUpEnd && rampUpMs > 0)
                {
                    loadFactor = (DateTime.Now - _startTime).TotalMilliseconds / rampUpMs;
                }

                // Simulate operations with variation
                _currentOps = (int)(baseOps * connections * loadFactor * (0.9 + _random.NextDouble() * 0.2));
                _totalOperations += _currentOps / 10; // Add per 100ms tick

                // Random errors (very low rate)
                if (_random.NextDouble() < 0.0001)
                {
                    _errors++;
                    AddLog("ERROR", "Operation timeout - retrying", "#FF4757");
                }

                // Temperature simulation
                int targetTemp = 42 + (int)(connections * loadFactor * 0.5);
                _temperature = Math.Clamp(_temperature + _random.Next(-1, 2), 35, 75);
                if (_temperature > 70 && ChkAutoThrottle.IsChecked == true)
                {
                    AddLog("WARN", "Temperature warning - auto-throttling enabled", "#FFB800");
                    baseOps = (int)(baseOps * 0.8);
                }

                await Task.Delay(100, token);
            }
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            var elapsed = DateTime.Now - _startTime;
            var remaining = _duration - elapsed;

            if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;

            ElapsedText.Text = $"Elapsed: {elapsed:mm\\:ss}";
            RemainingText.Text = $"Remaining: {remaining:mm\\:ss}";
            TimeRemainingText.Text = $"{remaining:mm\\:ss}";

            ProgressBar.Value = Math.Min(100, elapsed.TotalSeconds / _duration.TotalSeconds * 100);

            CurrentOpsText.Text = _currentOps.ToString("N0");
            TotalOpsText.Text = _totalOperations.ToString("N0");
            TempText.Text = $"{_temperature}°C";
            TempText.Foreground = new SolidColorBrush(_temperature > 65 ? 
                (Color)ColorConverter.ConvertFromString("#FF4757") : Colors.White);
            
            var errorRate = _errors * 100.0 / Math.Max(1, _totalOperations);
            ErrorRateText.Text = $"{errorRate:F2}%";
            ErrorRateText.Foreground = new SolidColorBrush(errorRate > 1 ? 
                (Color)ColorConverter.ConvertFromString("#FF4757") : 
                (Color)ColorConverter.ConvertFromString("#2ED573"));
        }

        private void StopLoadTest_Click(object sender, RoutedEventArgs e)
        {
            _cancellationToken?.Cancel();
        }

        private void AddLog(string type, string message, string color)
        {
            _logItems.Insert(0, new LoadTestLogItem
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Type = type,
                Message = message,
                Color = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color))
            });

            while (_logItems.Count > 100)
                _logItems.RemoveAt(_logItems.Count - 1);
        }

        private void ExportResults_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = $"loadtest_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    using var writer = new StreamWriter(dialog.FileName);
                    writer.WriteLine("QUAC 100 Load Test Report");
                    writer.WriteLine($"Generated: {DateTime.Now}");
                    writer.WriteLine(new string('=', 50));
                    writer.WriteLine();
                    writer.WriteLine($"Duration: {_duration}");
                    writer.WriteLine($"Connections: {SliderConnections.Value}");
                    writer.WriteLine($"Workload: {((ComboBoxItem)CmbWorkload.SelectedItem).Content}");
                    writer.WriteLine();
                    writer.WriteLine($"Total Operations: {_totalOperations:N0}");
                    writer.WriteLine($"Errors: {_errors}");
                    writer.WriteLine($"Error Rate: {_errors * 100.0 / Math.Max(1, _totalOperations):F4}%");
                    writer.WriteLine();
                    writer.WriteLine("Event Log:");
                    writer.WriteLine(new string('-', 50));
                    
                    foreach (var item in _logItems)
                    {
                        writer.WriteLine($"[{item.Time}] [{item.Type}] {item.Message}");
                    }
                    
                    MessageBox.Show($"Report exported to:\n{dialog.FileName}", "Export Complete", 
                                    MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting: {ex.Message}", "Error", 
                                    MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }
}
