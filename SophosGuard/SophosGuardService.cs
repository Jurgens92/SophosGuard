using System;
using System.ServiceProcess;
using System.Timers;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Xml.Linq;

namespace SophosGuard
{
    public class SophosGuardService : ServiceBase
    {
        private readonly string _logFilePath;
        private readonly string _ipListPath;
        private SophosGuardWorker _worker;
        private IPListManager _ipListManager;
        private Configuration _config;
        private static object _logLock = new object();

        public SophosGuardService()
        {
            ServiceName = "SophosGuard";

            // Initialize paths
            _logFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SophosGuard",
                "Logs"
            );

            _ipListPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SophosGuard",
                "IPList"
            );

            // Ensure directories exist
            Directory.CreateDirectory(_logFilePath);
            Directory.CreateDirectory(_ipListPath);
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                LogMessage("Service starting");

                // Load configuration
                _config = ConfigurationManager.LoadConfiguration();
                LogMessage("Configuration loaded");

                // Initialize managers
                _ipListManager = new IPListManager(_ipListPath);

                // Initialize and start worker
                _worker = new SophosGuardWorker(_ipListManager, _config);
                _worker.Start();

                LogMessage("Service started successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error starting service: {ex.Message}");
                throw;
            }
        }

        protected override void OnStop()
        {
            try
            {
                LogMessage("Service stopping");
                _worker?.Stop();
                _worker?.Dispose();
                _ipListManager?.Dispose();
                LogMessage("Service stopped successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping service: {ex.Message}");
                throw;
            }
        }

        public static void LogMessage(string message)
        {
            try
            {
                var logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "Logs"
                );

                var logFile = Path.Combine(logPath, $"sophosguard-{DateTime.Now:yyyy-MM-dd}.log");
                var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";

                lock (_logLock)
                {
                    Directory.CreateDirectory(logPath);
                    File.AppendAllText(logFile, logMessage);
                }
            }
            catch
            {
                // Ignore logging errors to prevent service disruption
            }
        }
    }
}