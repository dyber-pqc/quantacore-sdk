using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace QuacTestSuite.Views
{
    public partial class LogViewerView : UserControl
    {
        private readonly Random _random = new Random();
        private readonly DispatcherTimer _timer;
        private int _errorCount;
        private int _warnCount;
        private int _infoCount;

        public ObservableCollection<LogEntry> LogEntries { get; set; } = new ObservableCollection<LogEntry>();

        private readonly string[] _infoMessages = new[]
        {
            "SDK initialized successfully",
            "Device opened: index=0",
            "KEM keygen completed: algorithm=ML-KEM-768",
            "Random bytes generated: 1024 bytes",
            "Self-test passed: all algorithms",
            "Temperature reading: 45°C",
            "DMA transfer completed: 4096 bytes",
            "Batch operation submitted: 100 items",
            "Device health check: OK",
            "Connection established to QUAC 100"
        };

        private readonly string[] _warnMessages = new[]
        {
            "Device temperature elevated: 52°C",
            "Slow DMA transfer detected: 15ms",
            "Retry on operation: attempt 2/3",
            "Deprecated API called: quac_legacy_init",
            "QRNG entropy below optimal: 7.85 bits/byte"
        };

        private readonly string[] _errorMessages = new[]
        {
            "Operation timeout: exceeded 5000ms",
            "Invalid parameter: buffer size too small",
            "DMA error: transfer aborted"
        };

        private readonly string[] _sources = new[] { "SDK", "Driver", "Device", "App" };

        public LogViewerView()
        {
            InitializeComponent();
            LogList.ItemsSource = LogEntries;

            // Add initial log entries
            AddLog("INFO", "SDK", "QuantaCore SDK v1.0.0 initialized");
            AddLog("INFO", "Driver", "QUAC 100 driver loaded successfully");
            AddLog("INFO", "Device", "Device enumeration complete: 1 device found");
            AddLog("INFO", "SDK", "Simulator mode: enabled");
            AddLog("DEBUG", "SDK", "Thread pool initialized: 4 workers");

            // Start live logging simulation
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            UpdateCounts();
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            // Random log entry
            var roll = _random.Next(100);
            string level;
            string message;

            if (roll < 5) // 5% errors
            {
                level = "ERROR";
                message = _errorMessages[_random.Next(_errorMessages.Length)];
            }
            else if (roll < 15) // 10% warnings
            {
                level = "WARN";
                message = _warnMessages[_random.Next(_warnMessages.Length)];
            }
            else // 85% info
            {
                level = "INFO";
                message = _infoMessages[_random.Next(_infoMessages.Length)];
            }

            var source = _sources[_random.Next(_sources.Length)];
            AddLog(level, source, message);

            if (ChkAutoScroll.IsChecked == true && LogEntries.Count > 0)
            {
                LogList.ScrollIntoView(LogEntries[LogEntries.Count - 1]);
            }
        }

        private void AddLog(string level, string source, string message)
        {
            var color = level switch
            {
                "ERROR" => "#FF4757",
                "WARN" => "#FFB800",
                "INFO" => "#2ED573",
                "DEBUG" => "#7F8C9A",
                _ => "#FFFFFF"
            };

            LogEntries.Add(new LogEntry
            {
                Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                Level = level,
                LevelColor = color,
                Source = source,
                Message = message
            });

            // Keep only last 500 entries
            while (LogEntries.Count > 500)
            {
                LogEntries.RemoveAt(0);
            }

            // Update counts
            switch (level)
            {
                case "ERROR": _errorCount++; break;
                case "WARN": _warnCount++; break;
                case "INFO": _infoCount++; break;
            }

            UpdateCounts();
        }

        private void UpdateCounts()
        {
            TxtErrorCount.Text = _errorCount.ToString();
            TxtWarnCount.Text = _warnCount.ToString();
            TxtInfoCount.Text = _infoCount.ToString();
            TxtTotalLogs.Text = $"{LogEntries.Count} log entries";
        }

        private void LogLevel_Changed(object sender, SelectionChangedEventArgs e)
        {
            // In a real implementation, this would filter the log view
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            LogEntries.Clear();
            _errorCount = 0;
            _warnCount = 0;
            _infoCount = 0;
            UpdateCounts();
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv",
                Title = "Export Logs",
                FileName = $"quac100_log_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                var lines = new System.Text.StringBuilder();
                foreach (var entry in LogEntries)
                {
                    lines.AppendLine($"{entry.Timestamp}\t{entry.Level}\t{entry.Source}\t{entry.Message}");
                }
                System.IO.File.WriteAllText(dialog.FileName, lines.ToString());
                MessageBox.Show($"Logs exported to:\n{dialog.FileName}", "Export Complete",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }

    public class LogEntry
    {
        public string Timestamp { get; set; } = "";
        public string Level { get; set; } = "";
        public string LevelColor { get; set; } = "#FFFFFF";
        public string Source { get; set; } = "";
        public string Message { get; set; } = "";
    }
}
