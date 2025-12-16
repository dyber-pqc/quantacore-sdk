using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace QuacTestSuite.Controls
{
    /// <summary>
    /// Circular gauge control for displaying metrics
    /// </summary>
    public class CircularGauge : Control
    {
        static CircularGauge()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(CircularGauge),
                new FrameworkPropertyMetadata(typeof(CircularGauge)));
        }

        public static readonly DependencyProperty ValueProperty =
            DependencyProperty.Register("Value", typeof(double), typeof(CircularGauge),
                new PropertyMetadata(0.0, OnValueChanged));

        public static readonly DependencyProperty MinimumProperty =
            DependencyProperty.Register("Minimum", typeof(double), typeof(CircularGauge),
                new PropertyMetadata(0.0));

        public static readonly DependencyProperty MaximumProperty =
            DependencyProperty.Register("Maximum", typeof(double), typeof(CircularGauge),
                new PropertyMetadata(100.0));

        public static readonly DependencyProperty TitleProperty =
            DependencyProperty.Register("Title", typeof(string), typeof(CircularGauge),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty UnitProperty =
            DependencyProperty.Register("Unit", typeof(string), typeof(CircularGauge),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty GaugeColorProperty =
            DependencyProperty.Register("GaugeColor", typeof(Brush), typeof(CircularGauge),
                new PropertyMetadata(Brushes.Cyan));

        public static readonly DependencyProperty BackgroundArcColorProperty =
            DependencyProperty.Register("BackgroundArcColor", typeof(Brush), typeof(CircularGauge),
                new PropertyMetadata(new SolidColorBrush(Color.FromRgb(0x25, 0x25, 0x38))));

        public double Value
        {
            get => (double)GetValue(ValueProperty);
            set => SetValue(ValueProperty, value);
        }

        public double Minimum
        {
            get => (double)GetValue(MinimumProperty);
            set => SetValue(MinimumProperty, value);
        }

        public double Maximum
        {
            get => (double)GetValue(MaximumProperty);
            set => SetValue(MaximumProperty, value);
        }

        public string Title
        {
            get => (string)GetValue(TitleProperty);
            set => SetValue(TitleProperty, value);
        }

        public string Unit
        {
            get => (string)GetValue(UnitProperty);
            set => SetValue(UnitProperty, value);
        }

        public Brush GaugeColor
        {
            get => (Brush)GetValue(GaugeColorProperty);
            set => SetValue(GaugeColorProperty, value);
        }

        public Brush BackgroundArcColor
        {
            get => (Brush)GetValue(BackgroundArcColorProperty);
            set => SetValue(BackgroundArcColorProperty, value);
        }

        public double Percentage => Maximum > Minimum ? (Value - Minimum) / (Maximum - Minimum) * 100 : 0;

        private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is CircularGauge gauge)
            {
                gauge.InvalidateVisual();
            }
        }
    }

    /// <summary>
    /// Metric card control for displaying key metrics
    /// </summary>
    public class MetricCard : ContentControl
    {
        static MetricCard()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(MetricCard),
                new FrameworkPropertyMetadata(typeof(MetricCard)));
        }

        public static readonly DependencyProperty TitleProperty =
            DependencyProperty.Register("Title", typeof(string), typeof(MetricCard),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty ValueProperty =
            DependencyProperty.Register("Value", typeof(string), typeof(MetricCard),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty UnitProperty =
            DependencyProperty.Register("Unit", typeof(string), typeof(MetricCard),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty IconProperty =
            DependencyProperty.Register("Icon", typeof(object), typeof(MetricCard),
                new PropertyMetadata(null));

        public static readonly DependencyProperty IconColorProperty =
            DependencyProperty.Register("IconColor", typeof(Brush), typeof(MetricCard),
                new PropertyMetadata(Brushes.Cyan));

        public static readonly DependencyProperty TrendProperty =
            DependencyProperty.Register("Trend", typeof(string), typeof(MetricCard),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty TrendColorProperty =
            DependencyProperty.Register("TrendColor", typeof(Brush), typeof(MetricCard),
                new PropertyMetadata(Brushes.Green));

        public string Title
        {
            get => (string)GetValue(TitleProperty);
            set => SetValue(TitleProperty, value);
        }

        public string Value
        {
            get => (string)GetValue(ValueProperty);
            set => SetValue(ValueProperty, value);
        }

        public string Unit
        {
            get => (string)GetValue(UnitProperty);
            set => SetValue(UnitProperty, value);
        }

        public object Icon
        {
            get => GetValue(IconProperty);
            set => SetValue(IconProperty, value);
        }

        public Brush IconColor
        {
            get => (Brush)GetValue(IconColorProperty);
            set => SetValue(IconColorProperty, value);
        }

        public string Trend
        {
            get => (string)GetValue(TrendProperty);
            set => SetValue(TrendProperty, value);
        }

        public Brush TrendColor
        {
            get => (Brush)GetValue(TrendColorProperty);
            set => SetValue(TrendColorProperty, value);
        }
    }

    /// <summary>
    /// Status indicator control
    /// </summary>
    public class StatusIndicator : Control
    {
        static StatusIndicator()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(StatusIndicator),
                new FrameworkPropertyMetadata(typeof(StatusIndicator)));
        }

        public static readonly DependencyProperty StatusProperty =
            DependencyProperty.Register("Status", typeof(StatusType), typeof(StatusIndicator),
                new PropertyMetadata(StatusType.Unknown, OnStatusChanged));

        public static readonly DependencyProperty TextProperty =
            DependencyProperty.Register("Text", typeof(string), typeof(StatusIndicator),
                new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty ShowTextProperty =
            DependencyProperty.Register("ShowText", typeof(bool), typeof(StatusIndicator),
                new PropertyMetadata(true));

        public StatusType Status
        {
            get => (StatusType)GetValue(StatusProperty);
            set => SetValue(StatusProperty, value);
        }

        public string Text
        {
            get => (string)GetValue(TextProperty);
            set => SetValue(TextProperty, value);
        }

        public bool ShowText
        {
            get => (bool)GetValue(ShowTextProperty);
            set => SetValue(ShowTextProperty, value);
        }

        public Brush StatusColor => Status switch
        {
            StatusType.Ok => new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73)),
            StatusType.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00)),
            StatusType.Error => new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57)),
            StatusType.Info => new SolidColorBrush(Color.FromRgb(0x00, 0xB4, 0xD8)),
            _ => new SolidColorBrush(Color.FromRgb(0x80, 0x80, 0x80))
        };

        private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is StatusIndicator indicator)
            {
                indicator.InvalidateVisual();
            }
        }
    }

    public enum StatusType
    {
        Unknown,
        Ok,
        Warning,
        Error,
        Info
    }

    /// <summary>
    /// Progress ring control
    /// </summary>
    public class ProgressRing : Control
    {
        static ProgressRing()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(ProgressRing),
                new FrameworkPropertyMetadata(typeof(ProgressRing)));
        }

        public static readonly DependencyProperty IsActiveProperty =
            DependencyProperty.Register("IsActive", typeof(bool), typeof(ProgressRing),
                new PropertyMetadata(false));

        public static readonly DependencyProperty ValueProperty =
            DependencyProperty.Register("Value", typeof(double), typeof(ProgressRing),
                new PropertyMetadata(0.0));

        public static readonly DependencyProperty IsIndeterminateProperty =
            DependencyProperty.Register("IsIndeterminate", typeof(bool), typeof(ProgressRing),
                new PropertyMetadata(true));

        public static readonly DependencyProperty RingColorProperty =
            DependencyProperty.Register("RingColor", typeof(Brush), typeof(ProgressRing),
                new PropertyMetadata(new SolidColorBrush(Color.FromRgb(0x00, 0xB4, 0xD8))));

        public bool IsActive
        {
            get => (bool)GetValue(IsActiveProperty);
            set => SetValue(IsActiveProperty, value);
        }

        public double Value
        {
            get => (double)GetValue(ValueProperty);
            set => SetValue(ValueProperty, value);
        }

        public bool IsIndeterminate
        {
            get => (bool)GetValue(IsIndeterminateProperty);
            set => SetValue(IsIndeterminateProperty, value);
        }

        public Brush RingColor
        {
            get => (Brush)GetValue(RingColorProperty);
            set => SetValue(RingColorProperty, value);
        }
    }

    /// <summary>
    /// Hex viewer control for displaying binary data
    /// </summary>
    public class HexViewer : Control
    {
        static HexViewer()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(HexViewer),
                new FrameworkPropertyMetadata(typeof(HexViewer)));
        }

        public static readonly DependencyProperty DataProperty =
            DependencyProperty.Register("Data", typeof(byte[]), typeof(HexViewer),
                new PropertyMetadata(null, OnDataChanged));

        public static readonly DependencyProperty BytesPerLineProperty =
            DependencyProperty.Register("BytesPerLine", typeof(int), typeof(HexViewer),
                new PropertyMetadata(16));

        public static readonly DependencyProperty ShowAsciiProperty =
            DependencyProperty.Register("ShowAscii", typeof(bool), typeof(HexViewer),
                new PropertyMetadata(true));

        public byte[] Data
        {
            get => (byte[])GetValue(DataProperty);
            set => SetValue(DataProperty, value);
        }

        public int BytesPerLine
        {
            get => (int)GetValue(BytesPerLineProperty);
            set => SetValue(BytesPerLineProperty, value);
        }

        public bool ShowAscii
        {
            get => (bool)GetValue(ShowAsciiProperty);
            set => SetValue(ShowAsciiProperty, value);
        }

        public string FormattedHex
        {
            get
            {
                if (Data == null || Data.Length == 0) return string.Empty;

                var sb = new System.Text.StringBuilder();
                for (int i = 0; i < Data.Length; i += BytesPerLine)
                {
                    // Address
                    sb.Append($"{i:X8}  ");

                    // Hex bytes
                    for (int j = 0; j < BytesPerLine; j++)
                    {
                        if (i + j < Data.Length)
                            sb.Append($"{Data[i + j]:X2} ");
                        else
                            sb.Append("   ");

                        if (j == 7) sb.Append(" ");
                    }

                    // ASCII
                    if (ShowAscii)
                    {
                        sb.Append(" |");
                        for (int j = 0; j < BytesPerLine && i + j < Data.Length; j++)
                        {
                            var b = Data[i + j];
                            sb.Append(b >= 32 && b < 127 ? (char)b : '.');
                        }
                        sb.Append("|");
                    }

                    sb.AppendLine();
                }

                return sb.ToString();
            }
        }

        private static void OnDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is HexViewer viewer)
            {
                viewer.InvalidateVisual();
            }
        }
    }
}
