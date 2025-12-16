using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;

namespace QuacTestSuite.Views
{
    public class BenchmarkResult
    {
        public string Algorithm { get; set; } = "";
        public string Operation { get; set; } = "";
        public string OpsPerSec { get; set; } = "";
        public string AvgLatency { get; set; } = "";
        public string P99Latency { get; set; } = "";
        public string Iterations { get; set; } = "";
        
        public int OpsPerSecRaw { get; set; }
        public double AvgLatencyRaw { get; set; }
    }

    public partial class BenchmarkView : UserControl
    {
        private readonly ObservableCollection<BenchmarkResult> _results = new();
        private readonly Random _random = new();
        private CancellationTokenSource? _cancellationToken;
        private bool _isRunning;
        private DateTime _startTime;

        public BenchmarkView()
        {
            InitializeComponent();
            ResultsGrid.ItemsSource = _results;
            
            SliderThreads.ValueChanged += (s, e) =>
            {
                ThreadCountText.Text = $"{(int)SliderThreads.Value} threads";
            };
        }

        private async void StartBenchmark_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning) return;

            _results.Clear();
            EmptyState.Visibility = Visibility.Collapsed;
            ProgressPanel.Visibility = Visibility.Visible;
            SummaryPanel.Visibility = Visibility.Collapsed;
            
            BtnStart.IsEnabled = false;
            BtnStop.IsEnabled = true;
            BtnExport.IsEnabled = false;
            
            _isRunning = true;
            _startTime = DateTime.Now;
            _cancellationToken = new CancellationTokenSource();

            var algorithms = GetSelectedAlgorithms();
            var operations = GetSelectedOperations();
            var iterations = GetIterationCount();
            var threads = (int)SliderThreads.Value;
            
            int totalTests = algorithms.Count * operations.Count;
            int currentTest = 0;

            try
            {
                // Warmup phase
                if (ChkWarmup.IsChecked == true)
                {
                    ProgressText.Text = "Warmup phase...";
                    await Task.Delay(1000, _cancellationToken.Token);
                }

                foreach (var algo in algorithms)
                {
                    if (_cancellationToken.Token.IsCancellationRequested) break;

                    foreach (var op in operations)
                    {
                        if (_cancellationToken.Token.IsCancellationRequested) break;

                        currentTest++;
                        var progress = (double)currentTest / totalTests * 100;
                        
                        ProgressText.Text = $"Testing {algo} - {op}...";
                        ProgressPercent.Text = $"{progress:F0}%";
                        ProgressBar.Value = progress;

                        var elapsed = DateTime.Now - _startTime;
                        ElapsedText.Text = $"Elapsed: {elapsed:mm\\:ss}";
                        
                        if (currentTest > 1)
                        {
                            var remaining = TimeSpan.FromSeconds(elapsed.TotalSeconds / currentTest * (totalTests - currentTest));
                            RemainingText.Text = $"Remaining: ~{remaining:mm\\:ss}";
                        }

                        // Simulate benchmark
                        await Task.Delay(800 + _random.Next(400), _cancellationToken.Token);

                        var result = GenerateBenchmarkResult(algo, op, iterations, threads);
                        _results.Add(result);
                    }
                }

                // Complete
                ProgressPercent.Text = "100%";
                ProgressBar.Value = 100;
                ProgressText.Text = "Benchmark completed!";
                
                ShowSummary();
            }
            catch (OperationCanceledException)
            {
                ProgressText.Text = "Benchmark cancelled";
            }
            finally
            {
                _isRunning = false;
                BtnStart.IsEnabled = true;
                BtnStop.IsEnabled = false;
                BtnExport.IsEnabled = _results.Count > 0;
                
                await Task.Delay(2000);
                ProgressPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void StopBenchmark_Click(object sender, RoutedEventArgs e)
        {
            _cancellationToken?.Cancel();
        }

        private void ShowSummary()
        {
            SummaryPanel.Visibility = Visibility.Visible;
            
            int totalOps = 0;
            int peakOps = 0;
            double totalLatency = 0;
            
            foreach (var result in _results)
            {
                totalOps += result.OpsPerSecRaw;
                peakOps = Math.Max(peakOps, result.OpsPerSecRaw);
                totalLatency += result.AvgLatencyRaw;
            }

            TotalOps.Text = totalOps.ToString("N0");
            PeakThroughput.Text = $"{peakOps:N0} ops/s";
            AvgLatency.Text = $"{totalLatency / _results.Count:F1} µs";
            TotalTime.Text = $"{(DateTime.Now - _startTime).TotalSeconds:F1}s";
        }

        private BenchmarkResult GenerateBenchmarkResult(string algorithm, string operation, int iterations, int threads)
        {
            // Simulate realistic performance based on algorithm
            int baseOps = algorithm switch
            {
                "ML-KEM-512" => 180000,
                "ML-KEM-768" => 145000,
                "ML-KEM-1024" => 98000,
                "ML-DSA-44" => 48000,
                "ML-DSA-65" => 35000,
                "ML-DSA-87" => 22000,
                "SLH-DSA-128s" => 1200,
                "SLH-DSA-128f" => 8500,
                _ => 50000
            };

            // Adjust for operation type
            double opMultiplier = operation switch
            {
                "KeyGen" => 1.0,
                "Encaps" or "Sign" => 0.95,
                "Decaps" or "Verify" => 0.85,
                _ => 1.0
            };

            // Add thread scaling (not linear)
            double threadMultiplier = 1 + (threads - 1) * 0.6;

            int opsPerSec = (int)(baseOps * opMultiplier * threadMultiplier * (0.9 + _random.NextDouble() * 0.2));
            double avgLatency = 1000000.0 / opsPerSec;
            double p99Latency = avgLatency * (1.5 + _random.NextDouble() * 0.5);

            return new BenchmarkResult
            {
                Algorithm = algorithm,
                Operation = operation,
                OpsPerSec = opsPerSec.ToString("N0"),
                AvgLatency = $"{avgLatency:F1} µs",
                P99Latency = $"{p99Latency:F1} µs",
                Iterations = iterations.ToString("N0"),
                OpsPerSecRaw = opsPerSec,
                AvgLatencyRaw = avgLatency
            };
        }

        private List<string> GetSelectedAlgorithms()
        {
            var algos = new List<string>();
            if (ChkKyber512.IsChecked == true) algos.Add("ML-KEM-512");
            if (ChkKyber768.IsChecked == true) algos.Add("ML-KEM-768");
            if (ChkKyber1024.IsChecked == true) algos.Add("ML-KEM-1024");
            if (ChkDilithium2.IsChecked == true) algos.Add("ML-DSA-44");
            if (ChkDilithium3.IsChecked == true) algos.Add("ML-DSA-65");
            if (ChkDilithium5.IsChecked == true) algos.Add("ML-DSA-87");
            if (ChkSphincs128s.IsChecked == true) algos.Add("SLH-DSA-128s");
            if (ChkSphincs128f.IsChecked == true) algos.Add("SLH-DSA-128f");
            return algos;
        }

        private List<string> GetSelectedOperations()
        {
            var ops = new List<string>();
            if (ChkKeyGen.IsChecked == true) ops.Add("KeyGen");
            if (ChkEncaps.IsChecked == true) ops.Add("Encaps");
            if (ChkDecaps.IsChecked == true) ops.Add("Decaps");
            return ops;
        }

        private int GetIterationCount()
        {
            return CmbIterations.SelectedIndex switch
            {
                0 => 1000,
                1 => 10000,
                2 => 100000,
                3 => 1000000,
                _ => 10000
            };
        }

        private void ExportResults_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"benchmark_results_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    using var writer = new StreamWriter(dialog.FileName);
                    writer.WriteLine("Algorithm,Operation,Ops/sec,Avg Latency (µs),P99 Latency (µs),Iterations");
                    
                    foreach (var result in _results)
                    {
                        writer.WriteLine($"{result.Algorithm},{result.Operation},{result.OpsPerSecRaw},{result.AvgLatencyRaw:F2},{result.P99Latency},{result.Iterations}");
                    }
                    
                    MessageBox.Show($"Results exported to:\n{dialog.FileName}", "Export Complete", 
                                    MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting results: {ex.Message}", "Export Error", 
                                    MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }
}
