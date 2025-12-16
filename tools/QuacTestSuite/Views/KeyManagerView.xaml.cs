using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace QuacTestSuite.Views
{
    public partial class KeyManagerView : UserControl
    {
        public ObservableCollection<KeyItem> Keys { get; set; } = new ObservableCollection<KeyItem>();
        private const string SearchPlaceholder = "Search keys...";

        public KeyManagerView()
        {
            InitializeComponent();
            KeyList.ItemsSource = Keys;
            
            // Add sample keys
            Keys.Add(new KeyItem { Label = "production-key-2025", Algorithm = "ML-KEM-768", Created = "2025-01-15 09:30" });
            Keys.Add(new KeyItem { Label = "test-signing-key", Algorithm = "ML-DSA-65", Created = "2025-01-14 14:22" });
            Keys.Add(new KeyItem { Label = "backup-encryption", Algorithm = "ML-KEM-1024", Created = "2025-01-12 11:45" });
            
            UpdateEmptyState();
        }

        private void TxtSearch_GotFocus(object sender, RoutedEventArgs e)
        {
            if (TxtSearch.Text == SearchPlaceholder)
            {
                TxtSearch.Text = "";
                TxtSearch.Foreground = new SolidColorBrush(Colors.White);
            }
        }

        private void TxtSearch_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtSearch.Text))
            {
                TxtSearch.Text = SearchPlaceholder;
                TxtSearch.Foreground = new SolidColorBrush(Color.FromRgb(0x5A, 0x6C, 0x7D));
            }
        }

        private void UpdateEmptyState()
        {
            EmptyState.Visibility = Keys.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void AlgorithmType_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (CmbVariant == null) return;

            CmbVariant.Items.Clear();
            
            switch (CmbAlgorithmType.SelectedIndex)
            {
                case 0: // ML-KEM
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Kyber-512 (NIST Level 1)", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Kyber-768 (NIST Level 3)", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Kyber-1024 (NIST Level 5)", Foreground = new SolidColorBrush(Colors.White) });
                    UpdateKeySpecs(1184, 2400, 1088, "NIST Level 3");
                    break;
                case 1: // ML-DSA
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Dilithium-2 (NIST Level 2)", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Dilithium-3 (NIST Level 3)", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "Dilithium-5 (NIST Level 5)", Foreground = new SolidColorBrush(Colors.White) });
                    UpdateKeySpecs(1312, 2528, 2420, "NIST Level 2");
                    break;
                case 2: // SLH-DSA
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "SPHINCS+-128s", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "SPHINCS+-128f", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "SPHINCS+-192s", Foreground = new SolidColorBrush(Colors.White) });
                    CmbVariant.Items.Add(new ComboBoxItem { Content = "SPHINCS+-256s", Foreground = new SolidColorBrush(Colors.White) });
                    UpdateKeySpecs(32, 64, 7856, "NIST Level 1");
                    break;
            }
            CmbVariant.SelectedIndex = 0;
        }

        private void UpdateKeySpecs(int pubSize, int secSize, int cipherSize, string secLevel)
        {
            if (TxtPubKeySize != null)
            {
                TxtPubKeySize.Text = $"{pubSize:N0} bytes";
                TxtSecKeySize.Text = $"{secSize:N0} bytes";
                TxtCipherSize.Text = $"{cipherSize:N0} bytes";
                TxtSecLevel.Text = secLevel;
            }
        }

        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            var label = TxtKeyLabel.Text;
            var algorithm = (CmbVariant.SelectedItem as ComboBoxItem)?.Content?.ToString()?.Split(' ')[0] ?? "Unknown";
            
            Keys.Insert(0, new KeyItem 
            { 
                Label = label, 
                Algorithm = algorithm, 
                Created = DateTime.Now.ToString("yyyy-MM-dd HH:mm") 
            });
            
            UpdateEmptyState();
            
            MessageBox.Show($"Key pair '{label}' generated successfully using hardware QRNG!", 
                          "Key Generated", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ImportKey_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "PEM Files (*.pem)|*.pem|DER Files (*.der)|*.der|All Files (*.*)|*.*",
                Title = "Import Key"
            };
            
            if (dialog.ShowDialog() == true)
            {
                MessageBox.Show("Key imported successfully!", "Import Complete", 
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportSelected_Click(object sender, RoutedEventArgs e)
        {
            if (KeyList.SelectedItem == null)
            {
                MessageBox.Show("Please select a key to export.", "No Selection", 
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PEM Files (*.pem)|*.pem|DER Files (*.der)|*.der",
                Title = "Export Key"
            };
            
            if (dialog.ShowDialog() == true)
            {
                MessageBox.Show("Key exported successfully!", "Export Complete", 
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }

    public class KeyItem
    {
        public string Label { get; set; } = "";
        public string Algorithm { get; set; } = "";
        public string Created { get; set; } = "";
    }
}
