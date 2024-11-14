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
        private readonly Timer _timer;
        private readonly HttpClient _httpClient;
        private Configuration _config;
        private readonly string _logFilePath;
        private readonly string _ipListPath;
        private readonly IPListManager _ipListManager;
        private bool _isRunning;

        public SophosGuardService()
        {
            ServiceName = "SophosGuard";
            _timer = new Timer();

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };
            _httpClient = new HttpClient(handler);

            _logFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SophosGuard",
                "Logs"
            );

            var ipListPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SophosGuard",
                "IPList"
            );

            _ipListManager = new IPListManager(ipListPath);
        }

        private string BuildXmlRequest(string username, string password)
        {
            return $@"<Request>
                <Login>
                    <Username>{username}</Username>
                    <Password passwordform=""encrypt"">{password}</Password>
                </Login>
                <Get>
                    <IPHost></IPHost>
                </Get>
            </Request>";
        }

        private async Task<List<string>> FetchIPHosts()
        {
            try
            {
                var apiUrl = $"https://{_config.FirewallUrl}:4444/webconsole/APIController";

                // Build the request content
                var xmlRequest = BuildXmlRequest(_config.Username, _config.Password);

                // Create form content
                var formContent = new MultipartFormDataContent();
                formContent.Add(new StringContent(xmlRequest), "reqxml");

                // Send request
                var response = await _httpClient.PostAsync(apiUrl, formContent);
                response.EnsureSuccessStatusCode();

                var xmlResponse = await response.Content.ReadAsStringAsync();
                LogMessage($"API Response: {xmlResponse}"); // For debugging

                // Parse XML response
                var doc = XDocument.Parse(xmlResponse);

                // Extract IP hosts from response - adjust XPath based on actual response structure
                var ipHosts = doc.Descendants("IPHost")
                    .Select(ip => ip.Value)
                    .ToList();

                return ipHosts;
            }
            catch (Exception ex)
            {
                LogMessage($"Error fetching IP hosts: {ex.Message}");
                throw;
            }
        }

        private async Task UpdateThreatList()
        {
            const int maxRetries = 3;
            int currentRetry = 0;

            while (currentRetry < maxRetries)
            {
                try
                {
                    if (!_isRunning)
                    {
                        LogMessage("Service is stopping. Canceling update.");
                        return;
                    }

                    LogMessage("Starting threat list update");

                    // Get current list to compare changes later
                    var previousList = _ipListManager.GetCurrentIPList();

                    // Fetch new IP list from Sophos
                    var ipHosts = await FetchIPHosts();

                    // Check if we got any IPs back
                    if (ipHosts.Count == 0)
                    {
                        LogMessage("Warning: No IP hosts found in the response");
                        if (previousList.IPAddresses.Count > 0)
                        {
                            LogMessage("Keeping previous IP list due to empty response");
                            return;
                        }
                    }

                    // Find what changed
                    var newIPs = ipHosts.Except(previousList.IPAddresses).ToList();
                    var removedIPs = previousList.IPAddresses.Except(ipHosts).ToList();

                    // Save the updated list
                    _ipListManager.SaveIPList(ipHosts);

                    // Log all the changes
                    LogMessage($"IP Host list updated successfully. {ipHosts.Count} hosts found.");

                    // Log new IPs
                    if (newIPs.Any())
                    {
                        LogMessage($"New IPs added: {newIPs.Count}");
                        foreach (var ip in newIPs.Take(10))
                        {
                            LogMessage($"New IP: {ip}");
                        }
                        if (newIPs.Count > 10)
                        {
                            LogMessage($"... and {newIPs.Count - 10} more");
                        }
                    }

                    // Log removed IPs
                    if (removedIPs.Any())
                    {
                        LogMessage($"IPs removed: {removedIPs.Count}");
                        foreach (var ip in removedIPs.Take(10))
                        {
                            LogMessage($"Removed IP: {ip}");
                        }
                        if (removedIPs.Count > 10)
                        {
                            LogMessage($"... and {removedIPs.Count - 10} more");
                        }
                    }

                    // Success! Exit the retry loop
                    break;
                }
                catch (HttpRequestException ex)
                {
                    LogMessage($"HTTP request error: {ex.Message}");
                    currentRetry++;
                    if (currentRetry < maxRetries)
                    {
                        LogMessage($"Retrying update... Attempt {currentRetry + 1} of {maxRetries}");
                        await Task.Delay(TimeSpan.FromSeconds(30));
                    }
                    else
                    {
                        LogMessage("Max retries reached. Update failed.");
                        throw;
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Error updating IP host list: {ex.Message}");
                    currentRetry++;
                    if (currentRetry < maxRetries)
                    {
                        LogMessage($"Retrying update... Attempt {currentRetry + 1} of {maxRetries}");
                        await Task.Delay(TimeSpan.FromSeconds(30));
                    }
                    else
                    {
                        LogMessage("Max retries reached. Update failed.");
                        throw;
                    }
                }
            }
        }

        // Method for testing connection
        public static async Task<bool> TestConnection(Configuration config)
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
                };

                using (var client = new HttpClient(handler))
                {
                    var apiUrl = $"https://{config.FirewallUrl}:4444/webconsole/APIController";

                    // Build test request
                    var xmlRequest = $@"<Request>
                        <Login>
                            <Username>{config.Username}</Username>
                            <Password passwordform=""encrypt"">{config.Password}</Password>
                        </Login>
                        <Get>
                            <IPHost></IPHost>
                        </Get>
                    </Request>";

                    // Create form content
                    var formContent = new MultipartFormDataContent();
                    formContent.Add(new StringContent(xmlRequest), "reqxml");

                    // Send request
                    var response = await client.PostAsync(apiUrl, formContent);
                    return response.IsSuccessStatusCode;
                }
            }
            catch
            {
                return false;
            }
        }

        // Other service methods remain the same...
        protected override void OnStart(string[] args)
        {
            try
            {
                _config = ConfigurationManager.LoadConfiguration();

                // Ensure directories exist
                Directory.CreateDirectory(_logFilePath);
                Directory.CreateDirectory(_ipListPath);

                // Configure timer
                _timer.Interval = _config.UpdateIntervalMinutes * 60 * 1000; // Convert minutes to milliseconds
                _timer.Elapsed += async (sender, e) => await UpdateThreatList();

                // Initial update
                Task.Run(async () => await UpdateThreatList()).Wait();

                _timer.Start();
                _isRunning = true;

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
                _timer.Stop();
                _isRunning = false;
                LogMessage("Service stopped successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping service: {ex.Message}");
                throw;
            }
        }

        private void LogMessage(string message)
        {
            try
            {
                var logFile = Path.Combine(_logFilePath, $"sophosguard-{DateTime.Now:yyyy-MM-dd}.log");
                var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";
                File.AppendAllText(logFile, logMessage);
            }
            catch
            {
                // Ignore logging errors to prevent service disruption
            }
        }
    }
}