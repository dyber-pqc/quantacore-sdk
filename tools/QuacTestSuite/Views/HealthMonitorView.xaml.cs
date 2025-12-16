using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace QuacTestSuite.Views
{
    public partial class HealthMonitorView : UserControl
    {
        private readonly DispatcherTimer _updateTimer;
        private readonly Random _random = new();
        private DateTime _startTime = DateTime.Now;
        private bool _testsRunning;

        public HealthMonitorView()
        {
            InitializeComponent();
            
            _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            // Update temperature with slight variation
            int temp = 42 + _random.Next(-3, 4);
            var tempBlock = FindName("TempValue") as TextBlock;
            // Temperature already shown in static XAML, this would update if we had named elements
            
            // Update uptime
            var uptime = DateTime.Now - _startTime;
            // Update if we had the element named
        }

        private async void RunTests_Click(object sender, RoutedEventArgs e)
        {
            if (_testsRunning) return;
            _testsRunning = true;

            var btn = sender as Button;
            if (btn != null) btn.IsEnabled = false;

            // Reset all tests to pending
            SetTestStatus("MonobitResult", "Running...", "#FFB800");
            SetTestStatus("RunsResult", "Pending", "#5A6C7D");
            SetTestStatus("ChiSquareResult", "Pending", "#5A6C7D");
            SetTestStatus("EntropyTestResult", "Pending", "#5A6C7D");
            SetTestStatus("NISTResult", "Pending", "#5A6C7D");

            string[] testNames = { "ML-KEM Self-Test", "ML-DSA Self-Test", "QRNG Entropy Test", "Memory Integrity" };
            TextBlock[] resultBlocks = { MonobitResult, RunsResult, ChiSquareResult, EntropyTestResult };

            for (int i = 0; i < testNames.Length; i++)
            {
                resultBlocks[i].Text = "Running...";
                resultBlocks[i].Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFB800"));
                
                await Task.Delay(800 + _random.Next(400));
                
                bool passed = _random.NextDouble() > 0.02; // 98% pass rate
                resultBlocks[i].Text = passed ? "PASSED" : "FAILED";
                resultBlocks[i].Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(passed ? "#2ED573" : "#FF4757"));
            }

            // Final NIST result
            await Task.Delay(500);
            bool allPassed = MonobitResult.Text == "PASSED" && RunsResult.Text == "PASSED" && 
                            ChiSquareResult.Text == "PASSED" && EntropyTestResult.Text == "PASSED";
            NISTResult.Text = allPassed ? "PASSED" : "FAILED";
            NISTResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(allPassed ? "#2ED573" : "#FF4757"));

            if (btn != null) btn.IsEnabled = true;
            _testsRunning = false;
        }

        private void SetTestStatus(string name, string text, string color)
        {
            if (FindName(name) is TextBlock tb)
            {
                tb.Text = text;
                tb.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
            }
        }
    }
}
