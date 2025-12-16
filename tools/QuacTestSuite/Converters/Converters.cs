using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace QuacTestSuite.Converters
{
    /// <summary>
    /// Converts boolean to visibility
    /// </summary>
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                bool invert = parameter?.ToString() == "Invert";
                return (boolValue != invert) ? Visibility.Visible : Visibility.Collapsed;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is Visibility visibility && visibility == Visibility.Visible;
        }
    }

    /// <summary>
    /// Converts health status to color
    /// </summary>
    public class HealthStatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string status)
            {
                return status.ToUpperInvariant() switch
                {
                    "OK" or "HEALTHY" or "PASS" => new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73)),
                    "WARNING" => new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00)),
                    "ERROR" or "CRITICAL" or "FAIL" => new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57)),
                    _ => new SolidColorBrush(Color.FromRgb(0x80, 0x80, 0x80))
                };
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts temperature to color gradient
    /// </summary>
    public class TemperatureToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int temp || (value is double d && int.TryParse(d.ToString(), out temp)))
            {
                if (temp < 50) return new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73)); // Green
                if (temp < 65) return new SolidColorBrush(Color.FromRgb(0x00, 0xB4, 0xD8)); // Cyan
                if (temp < 75) return new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00)); // Orange
                return new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57)); // Red
            }
            return new SolidColorBrush(Colors.White);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Formats large numbers with K/M/B suffix
    /// </summary>
    public class NumberFormatConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double num || (value is int i && (num = i) >= 0) || (value is long l && (num = l) >= 0))
            {
                if (num >= 1_000_000_000) return $"{num / 1_000_000_000:N1}B";
                if (num >= 1_000_000) return $"{num / 1_000_000:N1}M";
                if (num >= 1_000) return $"{num / 1_000:N1}K";
                return num.ToString("N0");
            }
            return value?.ToString() ?? "0";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts bytes to human readable format
    /// </summary>
    public class BytesToHumanReadableConverter : IValueConverter
    {
        private static readonly string[] Sizes = { "B", "KB", "MB", "GB", "TB" };

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes || (value is int i && (bytes = i) >= 0) || (value is double d && (bytes = (long)d) >= 0))
            {
                int order = 0;
                double size = bytes;
                while (size >= 1024 && order < Sizes.Length - 1)
                {
                    order++;
                    size /= 1024;
                }
                return $"{size:N2} {Sizes[order]}";
            }
            return "0 B";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts latency in microseconds to appropriate format
    /// </summary>
    public class LatencyFormatConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double us)
            {
                if (us >= 1000) return $"{us / 1000:N2} ms";
                return $"{us:N1} µs";
            }
            return "0 µs";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts throughput to ops/sec or MB/s format
    /// </summary>
    public class ThroughputFormatConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double ops)
            {
                string unit = parameter?.ToString() ?? "ops";
                if (unit == "bytes")
                {
                    if (ops >= 1_000_000) return $"{ops / 1_000_000:N1} MB/s";
                    if (ops >= 1_000) return $"{ops / 1_000:N1} KB/s";
                    return $"{ops:N0} B/s";
                }
                else
                {
                    if (ops >= 1_000_000) return $"{ops / 1_000_000:N1}M ops/s";
                    if (ops >= 1_000) return $"{ops / 1_000:N1}K ops/s";
                    return $"{ops:N0} ops/s";
                }
            }
            return "0 ops/s";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts activity log type to color
    /// </summary>
    public class ActivityTypeToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string type)
            {
                return type.ToLowerInvariant() switch
                {
                    "success" => new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73)),
                    "error" => new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57)),
                    "warning" => new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00)),
                    "info" => new SolidColorBrush(Color.FromRgb(0x00, 0xB4, 0xD8)),
                    _ => new SolidColorBrush(Color.FromRgb(0x60, 0x60, 0x60))
                };
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts percentage to progress bar color
    /// </summary>
    public class PercentToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double percent || (value is int i && (percent = i) >= 0))
            {
                if (percent < 50) return new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73));
                if (percent < 75) return new SolidColorBrush(Color.FromRgb(0x00, 0xB4, 0xD8));
                if (percent < 90) return new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x00));
                return new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57));
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Inverts a boolean value
    /// </summary>
    public class InverseBoolConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool b && !b;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool b && !b;
        }
    }

    /// <summary>
    /// Null to visibility converter
    /// </summary>
    public class NullToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool invert = parameter?.ToString() == "Invert";
            bool isNull = value == null;
            return (isNull != invert) ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Equality converter - returns true if value equals parameter
    /// </summary>
    public class EqualityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value?.ToString() == parameter?.ToString();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool b && b ? parameter : Binding.DoNothing;
        }
    }
}
