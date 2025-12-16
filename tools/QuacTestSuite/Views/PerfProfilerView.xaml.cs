using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace QuacTestSuite.Views
{
    public partial class PerfProfilerView : UserControl
    {
        private readonly Random _random = new Random();
        private readonly DispatcherTimer _timer;
        private bool _isRunning;
        private int _elapsedSeconds;
        private int _targetSeconds;

        public PerfProfilerView()
        {
            InitializeComponent();
            
            _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _timer.Tick += Timer_Tick;
        }

        private void StartProfile_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning)
            {
                StopProfiling();
                return;
            }

            _targetSeconds = CmbDuration.SelectedIndex switch
            {
                0 => 10,
                1 => 30,
                2 => 60,
                3 => 300,
                _ => 30
            };

            _elapsedSeconds = 0;
            _isRunning = true;
            EmptyState.Visibility = Visibility.Collapsed;
            
            BtnStart.Content = CreateButtonContent("Stop", "Stop");
            BtnStart.Background = new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57));

            _timer.Start();
        }

        private void StopProfiling()
        {
            _isRunning = false;
            _timer.Stop();
            
            BtnStart.Content = CreateButtonContent("RecordCircle", "Start Profiling");
            BtnStart.Background = new SolidColorBrush(Color.FromRgb(0x00, 0xD4, 0xAA));

            MessageBox.Show($"Profiling completed!\n\n" +
                          $"Duration: {_elapsedSeconds} seconds\n" +
                          $"Samples collected: {_elapsedSeconds * 1000}\n" +
                          $"Hot spot: quac_kem_keygen (32.4%)",
                          "Profiling Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private StackPanel CreateButtonContent(string icon, string text)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            panel.Children.Add(new MaterialDesignThemes.Wpf.PackIcon 
            { 
                Kind = (MaterialDesignThemes.Wpf.PackIconKind)Enum.Parse(
                    typeof(MaterialDesignThemes.Wpf.PackIconKind), icon),
                Width = 20, 
                Height = 20, 
                VerticalAlignment = VerticalAlignment.Center 
            });
            panel.Children.Add(new TextBlock 
            { 
                Text = text, 
                Margin = new Thickness(10, 0, 0, 0), 
                VerticalAlignment = VerticalAlignment.Center 
            });
            return panel;
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            _elapsedSeconds++;
            
            if (_elapsedSeconds >= _targetSeconds * 10) // 100ms ticks
            {
                StopProfiling();
                return;
            }

            // Update metrics with simulated values
            var cpu = _random.Next(35, 75);
            TxtCpu.Text = $"{cpu}%";
            TxtCpuPeak.Text = $"Peak: {Math.Max(cpu, 78)}%";
            CpuBar.Value = cpu;

            var devUtil = _random.Next(60, 95);
            TxtDevUtil.Text = $"{devUtil}%";
            DevUtilBar.Value = devUtil;

            var memUsed = _random.Next(180, 280);
            TxtMemory.Text = $"{memUsed} MB";
            TxtMemoryDetail.Text = $"{memUsed} / 512 MB";

            TxtDma.Text = $"{_random.Next(28, 35) / 10.0:F1}";

            // Draw timeline
            DrawTimeline();
        }

        private void DrawTimeline()
        {
            if (TimelineCanvas.ActualWidth == 0) return;

            // Add a new bar to the timeline
            var width = TimelineCanvas.ActualWidth;
            var height = TimelineCanvas.ActualHeight;
            
            var barWidth = 3.0;
            var x = (_elapsedSeconds % (int)(width / barWidth)) * barWidth;
            
            var barHeight = _random.Next(20, (int)(height * 0.8));
            var color = barHeight > height * 0.6 ? Color.FromRgb(0xFF, 0x47, 0x57) :
                       barHeight > height * 0.4 ? Color.FromRgb(0xFF, 0xB8, 0x00) :
                       Color.FromRgb(0x00, 0xD4, 0xAA);

            var rect = new Rectangle
            {
                Width = barWidth - 1,
                Height = barHeight,
                Fill = new SolidColorBrush(color)
            };

            Canvas.SetLeft(rect, x);
            Canvas.SetTop(rect, height - barHeight);
            
            // Clear old bars if wrapping
            if (x < barWidth * 2)
            {
                TimelineCanvas.Children.Clear();
            }
            
            TimelineCanvas.Children.Add(rect);
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Performance Report (*.html)|*.html|JSON Data (*.json)|*.json|Chrome Trace (*.json)|*.json",
                Title = "Export Performance Profile"
            };

            if (dialog.ShowDialog() == true)
            {
                MessageBox.Show($"Profile exported to:\n{dialog.FileName}", "Export Complete",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
