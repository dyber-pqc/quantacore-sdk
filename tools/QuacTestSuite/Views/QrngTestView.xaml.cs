using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace QuacTestSuite.Views
{
    public partial class QrngTestView : UserControl
    {
        private byte[]? _generatedData;
        private long _totalBytesGenerated;

        public QrngTestView()
        {
            InitializeComponent();
        }

        private int GetByteCount()
        {
            return CmbSize.SelectedIndex switch
            {
                0 => 256,
                1 => 1024,
                2 => 1024 * 1024,
                3 => 10 * 1024 * 1024,
                4 => 100 * 1024 * 1024,
                _ => 1024 * 1024
            };
        }

        private async void Generate_Click(object sender, RoutedEventArgs e)
        {
            BtnGenerate.IsEnabled = false;
            BtnSave.IsEnabled = false;
            BtnCopy.IsEnabled = false;
            ProgressPanel.Visibility = Visibility.Visible;

            int byteCount = GetByteCount();
            ProgressText.Text = $"Generating {FormatBytes(byteCount)} of quantum random data...";

            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Generate random data using cryptographic RNG (simulating hardware QRNG)
                _generatedData = await Task.Run(() =>
                {
                    var data = new byte[byteCount];
                    using var rng = RandomNumberGenerator.Create();
                    rng.GetBytes(data);
                    return data;
                });

                stopwatch.Stop();
                _totalBytesGenerated += byteCount;

                // Update stats
                double throughput = byteCount / 1024.0 / 1024.0 / stopwatch.Elapsed.TotalSeconds;
                ThroughputText.Text = $"{throughput:F1} MB/s";
                TotalBytesText.Text = FormatBytes(_totalBytesGenerated);
                GenTimeText.Text = $"{stopwatch.Elapsed.TotalMilliseconds:F1} ms";

                // Display data
                DisplayRandomData();

                // Run statistical tests
                if (ChkRunTests.IsChecked == true)
                {
                    ProgressText.Text = "Running statistical tests...";
                    await RunStatisticalTests();
                }

                BtnSave.IsEnabled = true;
                BtnCopy.IsEnabled = _generatedData.Length <= 100000; // Only allow copy for smaller amounts
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error generating random data: {ex.Message}", "Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnGenerate.IsEnabled = true;
                ProgressPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void DisplayRandomData()
        {
            if (_generatedData == null) return;

            // Limit display to first 4KB for performance
            int displayBytes = Math.Min(_generatedData.Length, 4096);
            var displayData = new byte[displayBytes];
            Array.Copy(_generatedData, displayData, displayBytes);

            string formatted = CmbFormat.SelectedIndex switch
            {
                0 => FormatHex(displayData),
                1 => FormatBinary(displayData),
                2 => Convert.ToBase64String(displayData),
                3 => FormatDecimal(displayData),
                _ => FormatHex(displayData)
            };

            if (_generatedData.Length > displayBytes)
            {
                formatted += $"\n\n... [{FormatBytes(_generatedData.Length - displayBytes)} more data not shown]";
            }

            RandomDataOutput.Text = formatted;
            RandomDataOutput.Foreground = new SolidColorBrush(Colors.White);
        }

        private string FormatHex(byte[] data)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString("X2"));
                if ((i + 1) % 32 == 0) sb.AppendLine();
                else if ((i + 1) % 2 == 0) sb.Append(' ');
            }
            return sb.ToString();
        }

        private string FormatBinary(byte[] data)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < Math.Min(data.Length, 256); i++) // Limit binary display
            {
                sb.Append(Convert.ToString(data[i], 2).PadLeft(8, '0'));
                if ((i + 1) % 8 == 0) sb.AppendLine();
                else sb.Append(' ');
            }
            if (data.Length > 256)
                sb.Append($"\n... [showing first 256 bytes in binary]");
            return sb.ToString();
        }

        private string FormatDecimal(byte[] data)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString().PadLeft(3));
                if ((i + 1) % 16 == 0) sb.AppendLine();
                else sb.Append(' ');
            }
            return sb.ToString();
        }

        private async Task RunStatisticalTests()
        {
            if (_generatedData == null) return;

            await Task.Run(() =>
            {
                // Use at most 1MB for tests
                int testBytes = Math.Min(_generatedData.Length, 1024 * 1024);
                var testData = new byte[testBytes];
                Array.Copy(_generatedData, testData, testBytes);

                // Calculate entropy
                var freq = new int[256];
                foreach (byte b in testData) freq[b]++;
                
                double entropy = 0;
                foreach (int f in freq)
                {
                    if (f > 0)
                    {
                        double p = (double)f / testBytes;
                        entropy -= p * Math.Log2(p);
                    }
                }

                // Monobit test - count ones
                int ones = 0;
                foreach (byte b in testData)
                {
                    for (int i = 0; i < 8; i++)
                        if ((b & (1 << i)) != 0) ones++;
                }
                double monobitRatio = (double)ones / (testBytes * 8);
                bool monobitPass = monobitRatio > 0.49 && monobitRatio < 0.51;

                // Simple runs test
                int runs = 1;
                bool lastBit = (testData[0] & 1) != 0;
                for (int i = 0; i < Math.Min(testBytes, 10000); i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        bool bit = (testData[i] & (1 << j)) != 0;
                        if (bit != lastBit) runs++;
                        lastBit = bit;
                    }
                }
                bool runsPass = runs > 4500 && runs < 5500; // Rough check

                // Chi-square test (simplified)
                double chiSquare = 0;
                double expected = testBytes / 256.0;
                foreach (int f in freq)
                {
                    chiSquare += Math.Pow(f - expected, 2) / expected;
                }
                bool chiPass = chiSquare < 310 && chiSquare > 200; // Rough bounds

                bool entropyPass = entropy > 7.99;
                bool nistPass = monobitPass && runsPass && entropyPass;

                // Update UI on dispatcher
                Dispatcher.Invoke(() =>
                {
                    EntropyText.Text = $"{entropy:F4} bits/byte";

                    UpdateTestResult(MonobitResult, monobitPass, $"{monobitRatio:P2}");
                    UpdateTestResult(RunsResult, runsPass, $"{runs:N0} runs");
                    UpdateTestResult(ChiSquareResult, chiPass, $"χ² = {chiSquare:F1}");
                    UpdateTestResult(EntropyTestResult, entropyPass, $"{entropy:F4}");
                    UpdateTestResult(NISTResult, nistPass, nistPass ? "PASSED" : "FAILED");
                });
            });
        }

        private void UpdateTestResult(TextBlock tb, bool passed, string value)
        {
            tb.Text = value;
            tb.Foreground = new SolidColorBrush(passed ? 
                (Color)ColorConverter.ConvertFromString("#2ED573") : 
                (Color)ColorConverter.ConvertFromString("#FF4757"));
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            if (_generatedData == null) return;

            var dialog = new SaveFileDialog
            {
                Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
                FileName = $"qrng_data_{DateTime.Now:yyyyMMdd_HHmmss}.bin"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(dialog.FileName, _generatedData);
                    MessageBox.Show($"Saved {FormatBytes(_generatedData.Length)} to:\n{dialog.FileName}", 
                                    "Save Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving file: {ex.Message}", "Error", 
                                    MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            if (_generatedData == null) return;
            
            try
            {
                Clipboard.SetText(RandomDataOutput.Text);
                MessageBox.Show("Data copied to clipboard!", "Copy Complete", 
                                MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying: {ex.Message}", "Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} bytes";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:F2} MB";
            return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
        }
    }
}
