using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace QuacTestSuite.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        [ObservableProperty]
        private object? _currentViewModel;

        [ObservableProperty]
        private string _currentPageTitle = "Dashboard";

        [ObservableProperty]
        private string _deviceStatusText = "Connected";

        [ObservableProperty]
        private string _deviceName = "QUAC 100 (Simulator)";

        [ObservableProperty]
        private SolidColorBrush _deviceStatusColor = new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73));

        [ObservableProperty]
        private int _temperature = 42;

        [ObservableProperty]
        private SolidColorBrush _temperatureColor = new SolidColorBrush(Colors.White);

        [ObservableProperty]
        private double _powerConsumption = 12.5;

        [ObservableProperty]
        private string _versionString = "v1.0.0";

        [ObservableProperty]
        private SolidColorBrush _connectionStatusColor = new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73));

        [ObservableProperty]
        private string _connectionStatusText = "Connected";

        public MainViewModel()
        {
            // Navigation is handled by MainWindow code-behind
        }

        [RelayCommand]
        private void Refresh()
        {
            DeviceStatusText = "Connected";
            ConnectionStatusText = "Connected";
        }

        [RelayCommand]
        private void ExportReport()
        {
            // Export functionality
        }
    }
}
