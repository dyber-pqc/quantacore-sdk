using System.Windows;
using System.Windows.Controls;

namespace QuacTestSuite.Views
{
    public partial class FirmwareView : UserControl
    {
        public FirmwareView()
        {
            InitializeComponent();
        }

        private void CheckUpdate_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Checking for firmware updates...\n\n" +
                          "✓ Connected to Dyber update server\n" +
                          "✓ Current version: 2.1.0\n" +
                          "✓ Latest version: 2.1.0\n\n" +
                          "Your firmware is up to date!",
                          "Firmware Update Check", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BrowseFirmware_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Firmware Files (*.fw;*.bin)|*.fw;*.bin|All Files (*.*)|*.*",
                Title = "Select Firmware File"
            };

            if (dialog.ShowDialog() == true)
            {
                var result = MessageBox.Show($"Selected firmware: {System.IO.Path.GetFileName(dialog.FileName)}\n\n" +
                              "WARNING: Updating firmware is a critical operation.\n" +
                              "Do not power off the device during update.\n\n" +
                              "Do you want to proceed with the firmware update?",
                              "Confirm Firmware Update", 
                              MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    MessageBox.Show("Firmware update initiated...\n\n" +
                                  "This is a simulation. In production, the firmware\n" +
                                  "would be verified and flashed to the device.",
                                  "Firmware Update", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }
    }
}
