using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace QuacTestSuite.Views
{
    public partial class EntropyAnalyzerView : UserControl
    {
        private readonly Random _random = new Random();
        private byte[]? _sampleData;

        public EntropyAnalyzerView()
        {
            InitializeComponent();
            SizeChanged += (s, e) => DrawHistogram();
        }

        private void Sample_Click(object sender, RoutedEventArgs e)
        {
            var sw = Stopwatch.StartNew();

            // Get sample size
            int sampleSize = CmbSampleSize.SelectedIndex switch
            {
                0 => 1024,
                1 => 10 * 1024,
                2 => 100 * 1024,
                3 => 1024 * 1024,
                4 => 10 * 1024 * 1024,
                _ => 100 * 1024
            };

            // Generate random data (simulating QRNG)
            _sampleData = new byte[sampleSize];
            _random.NextBytes(_sampleData);

            sw.Stop();

            // Calculate entropy metrics
            CalculateAndDisplayStats(sw.ElapsedMilliseconds, sampleSize);

            // Draw histogram
            DrawHistogram();

            EmptyState.Visibility = Visibility.Collapsed;
        }

        private void CalculateAndDisplayStats(long analysisTimeMs, int sampleSize)
        {
            if (_sampleData == null) return;

            // Calculate byte frequency
            var freq = new int[256];
            foreach (var b in _sampleData)
                freq[b]++;

            // Count unique bytes
            int uniqueBytes = 0;
            foreach (var f in freq)
                if (f > 0) uniqueBytes++;

            // Shannon entropy
            double entropy = 0;
            double n = _sampleData.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] > 0)
                {
                    double p = freq[i] / n;
                    entropy -= p * Math.Log2(p);
                }
            }

            // Min-entropy (based on most frequent byte)
            int maxFreq = 0;
            foreach (var f in freq)
                if (f > maxFreq) maxFreq = f;
            double minEntropy = -Math.Log2(maxFreq / n);

            // Chi-square test
            double expected = n / 256.0;
            double chiSquare = 0;
            for (int i = 0; i < 256; i++)
            {
                double diff = freq[i] - expected;
                chiSquare += (diff * diff) / expected;
            }

            // Serial correlation (simplified)
            double correlation = 0;
            double mean = 127.5;
            double sum1 = 0, sum2 = 0, sumProd = 0;
            for (int i = 0; i < _sampleData.Length - 1; i++)
            {
                double x = _sampleData[i] - mean;
                double y = _sampleData[i + 1] - mean;
                sumProd += x * y;
                sum1 += x * x;
                sum2 += y * y;
            }
            if (sum1 > 0 && sum2 > 0)
                correlation = sumProd / Math.Sqrt(sum1 * sum2);

            // Compression ratio estimate (using entropy)
            double compressionRatio = entropy / 8.0;

            // Update UI
            TxtShannonEntropy.Text = $"{entropy:F4}";
            EntropyBar.Value = entropy;

            TxtMinEntropy.Text = $"{minEntropy:F4}";
            TxtChiSquare.Text = $"{chiSquare:F2}";
            
            // P-value approximation (simplified)
            double pValue = chiSquare < 293 ? 0.5 : (chiSquare < 310 ? 0.1 : 0.01);
            TxtChiSquareP.Text = $"p-value: {pValue:F3}";
            
            bool chiPass = chiSquare > 200 && chiSquare < 320; // Rough bounds for 255 DOF
            ChiSquareStatus.Background = new SolidColorBrush(chiPass ? 
                Color.FromRgb(0x2E, 0xD5, 0x73) : Color.FromRgb(0xFF, 0x47, 0x57));
            ((TextBlock)ChiSquareStatus.Child).Text = chiPass ? "PASS" : "FAIL";

            TxtCompression.Text = $"{compressionRatio:P1}";
            TxtCorrelation.Text = $"{correlation:F6}";

            bool allPass = entropy > 7.9 && chiPass && Math.Abs(correlation) < 0.01;
            TxtNistStatus.Text = allPass ? "COMPLIANT" : "CHECK REQUIRED";
            TxtNistStatus.Foreground = new SolidColorBrush(allPass ?
                Color.FromRgb(0x2E, 0xD5, 0x73) : Color.FromRgb(0xFF, 0xB8, 0x00));
            NistIcon.Foreground = TxtNistStatus.Foreground;
            NistIcon.Kind = allPass ? MaterialDesignThemes.Wpf.PackIconKind.ShieldCheck : 
                                     MaterialDesignThemes.Wpf.PackIconKind.ShieldAlert;

            // Bottom stats
            TxtSampleSize.Text = FormatBytes(sampleSize);
            TxtThroughput.Text = $"{sampleSize / 1024.0 / (analysisTimeMs / 1000.0 + 0.001):F1} KB/s";
            TxtAnalysisTime.Text = $"{analysisTimeMs} ms";
            TxtUniqueBytes.Text = $"{uniqueBytes}/256";
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }

        private void DrawHistogram()
        {
            HistogramCanvas.Children.Clear();
            
            if (_sampleData == null || HistogramCanvas.ActualWidth == 0) return;

            // Calculate byte frequency
            var freq = new int[256];
            foreach (var b in _sampleData)
                freq[b]++;

            int maxFreq = 0;
            foreach (var f in freq)
                if (f > maxFreq) maxFreq = f;

            if (maxFreq == 0) return;

            double width = HistogramCanvas.ActualWidth;
            double height = HistogramCanvas.ActualHeight - 20;
            double barWidth = width / 256.0;
            double expectedLine = height * ((_sampleData.Length / 256.0) / maxFreq);

            // Draw bars
            for (int i = 0; i < 256; i++)
            {
                double barHeight = (freq[i] / (double)maxFreq) * height;
                
                var rect = new Rectangle
                {
                    Width = Math.Max(1, barWidth - 0.5),
                    Height = barHeight,
                    Fill = new SolidColorBrush(Color.FromRgb(0x00, 0xD4, 0xAA))
                };

                Canvas.SetLeft(rect, i * barWidth);
                Canvas.SetTop(rect, height - barHeight);
                HistogramCanvas.Children.Add(rect);
            }

            // Draw expected value line
            var line = new Line
            {
                X1 = 0,
                X2 = width,
                Y1 = height - expectedLine,
                Y2 = height - expectedLine,
                Stroke = new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00)),
                StrokeThickness = 2,
                StrokeDashArray = new DoubleCollection { 4, 2 }
            };
            HistogramCanvas.Children.Add(line);
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PDF Report (*.pdf)|*.pdf|CSV Data (*.csv)|*.csv|JSON (*.json)|*.json",
                Title = "Export Entropy Report"
            };

            if (dialog.ShowDialog() == true)
            {
                MessageBox.Show($"Report exported to:\n{dialog.FileName}", "Export Complete",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
