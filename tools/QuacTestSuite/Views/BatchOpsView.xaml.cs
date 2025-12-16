using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace QuacTestSuite.Views
{
    public partial class BatchOpsView : UserControl
    {
        private readonly Random _random = new Random();
        private readonly DispatcherTimer _timer;
        private int _completed;
        private int _total;
        private bool _isRunning;

        public ObservableCollection<BatchItem> QueueItems { get; set; } = new ObservableCollection<BatchItem>();

        public BatchOpsView()
        {
            InitializeComponent();
            QueueList.ItemsSource = QueueItems;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
            _timer.Tick += Timer_Tick;
        }

        private void Start_Click(object sender, RoutedEventArgs e)
        {
            _total = GetBatchSize();
            _completed = 0;
            _isRunning = true;

            BtnStart.IsEnabled = false;
            BtnStop.IsEnabled = true;

            QueueItems.Clear();
            for (int i = 0; i < Math.Min(10, _total); i++)
            {
                QueueItems.Add(new BatchItem 
                { 
                    Operation = $"Operation #{i + 1}", 
                    Status = "Pending",
                    Icon = "Clock",
                    Color = "#7F8C9A"
                });
            }

            TxtProgress.Text = "Executing batch operations...";
            _timer.Start();
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            _isRunning = false;
            _timer.Stop();
            BtnStart.IsEnabled = true;
            BtnStop.IsEnabled = false;
            TxtProgress.Text = "Batch execution stopped";
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            if (!_isRunning || _completed >= _total)
            {
                _timer.Stop();
                _isRunning = false;
                BtnStart.IsEnabled = true;
                BtnStop.IsEnabled = false;
                TxtProgress.Text = "Batch execution complete";
                return;
            }

            // Simulate progress
            int batchStep = Math.Max(1, _total / 100);
            _completed = Math.Min(_completed + batchStep, _total);

            double percent = (double)_completed / _total * 100;
            ProgressBar.Value = percent;
            TxtPercent.Text = $"{percent:F1}%";
            TxtCompleted.Text = $"{_completed:N0} / {_total:N0} operations";

            TxtThroughput.Text = $"{_random.Next(80000, 150000):N0}";
            TxtLatency.Text = $"{_random.Next(5, 15)}";
            TxtSuccess.Text = $"{_completed:N0}";
            TxtErrors.Text = "0";
            TxtTotalTime.Text = $"{(_completed * 0.01):F2}s";
            TxtP99.Text = $"{_random.Next(15, 25)} µs";
            TxtCpu.Text = $"{_random.Next(40, 70)}%";
            TxtTemp.Text = $"{_random.Next(42, 52)}°C";

            // Update queue display
            if (QueueItems.Count > 0)
            {
                QueueItems[0].Status = "Completed";
                QueueItems[0].Icon = "CheckCircle";
                QueueItems[0].Color = "#2ED573";
            }
        }

        private int GetBatchSize()
        {
            return CmbBatchSize.SelectedIndex switch
            {
                0 => 10,
                1 => 100,
                2 => 1000,
                3 => 10000,
                4 => 100000,
                _ => 1000
            };
        }
    }

    public class BatchItem
    {
        public string Operation { get; set; } = "";
        public string Status { get; set; } = "";
        public string Icon { get; set; } = "Clock";
        public string Color { get; set; } = "#7F8C9A";
    }
}
