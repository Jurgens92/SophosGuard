using System;
using System.Windows.Forms;
using System.IO;
using System.Linq;
using System.ServiceProcess;

namespace SophosGuard
{
    static class Program
    {
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SophosGuard",
            "Logs"
        );

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                // Initialize logging
                Directory.CreateDirectory(LogPath);
                LogStartup("Application starting");

                // Check if running as service
                if (args.Length > 0 && args.Contains("/service"))
                {
                    LogStartup("Starting as service");
                    ServiceBase[] servicesToRun = new ServiceBase[]
                    {
                        new SophosGuardService()
                    };
                    ServiceBase.Run(servicesToRun);
                    return;
                }

                // Run as Windows Forms application
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                LogStartup("Creating main form");
                using (var mainForm = new MainForm())
                {
                    LogStartup("Running application");
                    Application.Run(mainForm);
                }
            }
            catch (Exception ex)
            {
                var message = $"Critical Error: {ex.Message}\n\n{ex.StackTrace}";
                MessageBox.Show(message);
                LogStartup($"Critical Error: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static void LogStartup(string message)
        {
            try
            {
                string logFile = Path.Combine(LogPath, "startup.log");
                string logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";
                File.AppendAllText(logFile, logMessage);
            }
            catch
            {
                // If we can't log, don't crash the application
            }
        }
    }
}