using System;
using System.Windows;
using Serilog;

namespace QuacTestSuite
{
    /// <summary>
    /// QUAC 100 Test Suite Application
    /// Copyright (c) 2025 Dyber, Inc. All Rights Reserved.
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            try
            {
                // Configure logging
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.File("logs/quactestsuite-.log", 
                        rollingInterval: RollingInterval.Day,
                        retainedFileCountLimit: 7)
                    .CreateLogger();
                
                Log.Information("QUAC 100 Test Suite starting...");
            }
            catch
            {
                // Logging setup failed, continue without logging
            }
            
            // Handle unhandled exceptions - show them instead of hiding
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                var ex = args.ExceptionObject as Exception;
                MessageBox.Show($"Fatal error: {ex?.Message}\n\n{ex?.StackTrace}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            };
            
            DispatcherUnhandledException += (s, args) =>
            {
                MessageBox.Show($"Error: {args.Exception.Message}\n\n{args.Exception.StackTrace}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                args.Handled = true;
            };

            try
            {
                // Create and show main window
                var mainWindow = new MainWindow();
                mainWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start: {ex.Message}\n\n{ex.StackTrace}", "Startup Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                Log.Information("QUAC 100 Test Suite shutting down...");
                Log.CloseAndFlush();
            }
            catch { }
            base.OnExit(e);
        }
    }
}
