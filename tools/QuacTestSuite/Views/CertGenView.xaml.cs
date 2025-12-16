using System;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace QuacTestSuite.Views
{
    public partial class CertGenView : UserControl
    {
        private readonly Random _random = new Random();

        public CertGenView()
        {
            InitializeComponent();
            DpFrom.SelectedDate = DateTime.Today;
        }

        private void Generate_Click(object sender, RoutedEventArgs e)
        {
            var cn = TxtCN.Text;
            var org = TxtOrg.Text;
            var country = TxtCountry.Text;
            var algorithm = (CmbAlgorithm.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "ML-DSA-65";

            // Generate fake certificate
            var serial = new byte[20];
            _random.NextBytes(serial);
            var serialHex = BitConverter.ToString(serial).Replace("-", ":");

            var validFrom = DpFrom.SelectedDate ?? DateTime.Today;
            var validDays = CmbValidity.SelectedIndex switch
            {
                0 => 30,
                1 => 365,
                2 => 730,
                3 => 3650,
                _ => 365
            };
            var validTo = validFrom.AddDays(validDays);

            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            
            // Generate fake base64 content (simulating DER-encoded certificate)
            var certBytes = new byte[2048];
            _random.NextBytes(certBytes);
            var base64 = Convert.ToBase64String(certBytes);
            for (int i = 0; i < base64.Length; i += 64)
            {
                sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
            }
            
            sb.AppendLine("-----END CERTIFICATE-----");
            sb.AppendLine();
            sb.AppendLine("Certificate Details:");
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine();
            sb.AppendLine($"  Version:              3 (0x2)");
            sb.AppendLine($"  Serial Number:        {serialHex}");
            sb.AppendLine($"  Signature Algorithm:  {algorithm}");
            sb.AppendLine($"  Issuer:               CN={cn}, O={org}, C={country}");
            sb.AppendLine($"  Validity:");
            sb.AppendLine($"      Not Before:       {validFrom:MMM dd HH:mm:ss yyyy} UTC");
            sb.AppendLine($"      Not After:        {validTo:MMM dd HH:mm:ss yyyy} UTC");
            sb.AppendLine($"  Subject:              CN={cn}, O={org}, C={country}");
            sb.AppendLine($"  Subject Public Key Info:");
            sb.AppendLine($"      Public Key Algorithm: {algorithm}");
            sb.AppendLine($"      Public Key:       (post-quantum lattice-based)");
            sb.AppendLine();
            sb.AppendLine("  X509v3 Extensions:");
            sb.AppendLine($"      Basic Constraints: critical");
            sb.AppendLine($"          CA:TRUE");
            sb.AppendLine($"      Key Usage: critical");
            sb.AppendLine($"          Digital Signature, Certificate Sign, CRL Sign");
            sb.AppendLine($"      Subject Key Identifier:");
            sb.AppendLine($"          {BitConverter.ToString(serial, 0, 10).Replace("-", ":")}...");

            TxtCertificate.Text = sb.ToString();

            // Update info
            TxtCertSize.Text = $"{certBytes.Length + 200} bytes";
            TxtPubKeySize.Text = algorithm.Contains("44") ? "1,312 bytes" : 
                                 algorithm.Contains("65") ? "1,952 bytes" : "2,592 bytes";
            TxtSigSize.Text = algorithm.Contains("44") ? "2,420 bytes" : 
                              algorithm.Contains("65") ? "3,293 bytes" : "4,595 bytes";

            MessageBox.Show($"Post-quantum certificate generated successfully!\n\n" +
                          $"Subject: CN={cn}, O={org}, C={country}\n" +
                          $"Algorithm: {algorithm}\n" +
                          $"Valid: {validDays} days",
                          "Certificate Generated", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void CopyCert_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(TxtCertificate.Text))
            {
                Clipboard.SetText(TxtCertificate.Text);
                MessageBox.Show("Certificate copied to clipboard.", "Copied",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void SaveCert_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TxtCertificate.Text) || TxtCertificate.Text.StartsWith("//"))
            {
                MessageBox.Show("Please generate a certificate first.", "No Certificate",
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PEM Certificate (*.pem)|*.pem|DER Certificate (*.der)|*.der|PKCS#12 (*.p12)|*.p12",
                Title = "Export Certificate",
                FileName = $"{TxtCN.Text.Replace(".", "_")}_cert"
            };

            if (dialog.ShowDialog() == true)
            {
                // Just save the text content for demo
                System.IO.File.WriteAllText(dialog.FileName, TxtCertificate.Text);
                MessageBox.Show($"Certificate exported to:\n{dialog.FileName}", "Export Complete",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
