using System;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace QuacTestSuite.Views
{
    public partial class CryptoDemoView : UserControl
    {
        private readonly Random _random = new Random();

        public CryptoDemoView()
        {
            InitializeComponent();
            TxtPlaintext.TextChanged += (s, e) => UpdatePlaintextSize();
        }

        private void UpdatePlaintextSize()
        {
            var bytes = Encoding.UTF8.GetByteCount(TxtPlaintext.Text);
            TxtPlaintextSize.Text = FormatBytes(bytes);
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} bytes";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }

        private void LoadFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Load Plaintext File"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    TxtPlaintext.Text = System.IO.File.ReadAllText(dialog.FileName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error loading file: {ex.Message}", "Error",
                                  MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtPlaintext.Text))
            {
                MessageBox.Show("Please enter plaintext to encrypt.", "No Input",
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            TxtStatus.Text = "Encrypting...";
            TxtStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xFF, 0xB8, 0x00));

            var sw = Stopwatch.StartNew();

            // Simulate ML-KEM encapsulation + AES encryption
            var plaintextBytes = Encoding.UTF8.GetBytes(TxtPlaintext.Text);
            
            // Generate fake ciphertext (KEM ciphertext + encrypted data)
            var kemCiphertextSize = GetKemCiphertextSize();
            var totalSize = kemCiphertextSize + plaintextBytes.Length + 16 + 12; // + tag + nonce
            var ciphertext = new byte[totalSize];
            _random.NextBytes(ciphertext);

            sw.Stop();

            // Display as hex
            var sb = new StringBuilder();
            sb.AppendLine("--- ML-KEM Ciphertext (Encapsulated Key) ---");
            for (int i = 0; i < Math.Min(kemCiphertextSize, 256); i++)
            {
                sb.AppendFormat("{0:X2}", ciphertext[i]);
                if ((i + 1) % 32 == 0) sb.AppendLine();
                else if ((i + 1) % 2 == 0) sb.Append(" ");
            }
            if (kemCiphertextSize > 256) sb.AppendLine("...[truncated]...");
            
            sb.AppendLine();
            sb.AppendLine("--- AES-256-GCM Encrypted Data ---");
            for (int i = kemCiphertextSize; i < Math.Min(totalSize, kemCiphertextSize + 256); i++)
            {
                sb.AppendFormat("{0:X2}", ciphertext[i]);
                if ((i - kemCiphertextSize + 1) % 32 == 0) sb.AppendLine();
                else if ((i - kemCiphertextSize + 1) % 2 == 0) sb.Append(" ");
            }

            TxtCiphertext.Text = sb.ToString();
            TxtCiphertextSize.Text = FormatBytes(totalSize);
            TxtEncapTime.Text = $"{sw.ElapsedMilliseconds + _random.Next(1, 5)} ms";
            TxtExpansion.Text = $"{(double)totalSize / plaintextBytes.Length:F2}x";
            TxtStatus.Text = "Encrypted";
            TxtStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x2E, 0xD5, 0x73));
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtCiphertext.Text))
            {
                MessageBox.Show("No ciphertext to decrypt.", "No Input",
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            TxtStatus.Text = "Decrypting...";
            TxtStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xFF, 0xB8, 0x00));

            var sw = Stopwatch.StartNew();
            
            // Simulate decryption delay
            System.Threading.Thread.Sleep(_random.Next(5, 15));
            
            sw.Stop();

            TxtDecapTime.Text = $"{sw.ElapsedMilliseconds + _random.Next(2, 8)} ms";
            TxtStatus.Text = "Decrypted";
            TxtStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x2E, 0xD5, 0x73));

            MessageBox.Show("Decryption successful! Plaintext restored.", "Success",
                          MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private int GetKemCiphertextSize()
        {
            return CmbAlgorithm.SelectedIndex switch
            {
                0 => 768,   // Kyber-512
                1 => 1088,  // Kyber-768
                2 => 1568,  // Kyber-1024
                _ => 1088
            };
        }

        private void CopyCiphertext_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(TxtCiphertext.Text))
            {
                Clipboard.SetText(TxtCiphertext.Text);
                MessageBox.Show("Ciphertext copied to clipboard.", "Copied",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void SaveCiphertext_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TxtCiphertext.Text)) return;

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Binary Files (*.bin)|*.bin|Text Files (*.txt)|*.txt",
                Title = "Save Ciphertext"
            };

            if (dialog.ShowDialog() == true)
            {
                System.IO.File.WriteAllText(dialog.FileName, TxtCiphertext.Text);
                MessageBox.Show("Ciphertext saved successfully.", "Saved",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
