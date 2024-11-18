using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Linq;
using System.Net;

namespace SophosGuard
{
    public class IPListManager : IDisposable
    {
        private readonly string _ipListPath;
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed;

        public IPListManager(string ipListPath)
        {
            _ipListPath = ipListPath;
            if (!Directory.Exists(_ipListPath))
            {
                Directory.CreateDirectory(_ipListPath);
            }

            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMinutes(2) // Set reasonable timeout
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SophosGuard/1.0");

            _semaphore = new SemaphoreSlim(1, 1); // Ensure thread-safe operations
        }

        public async Task<List<string>> FetchIPThreatList(int threatLevel, CancellationToken cancellationToken = default)
        {
            try
            {
                await _semaphore.WaitAsync(cancellationToken);

                // Validate threat level
                if (threatLevel < 0 || threatLevel > 100)
                {
                    throw new ArgumentException("Threat level must be between 0 and 100");
                }

                using (var response = await _httpClient.GetAsync(
                    $"https://lists.ipthreat.net/file/ipthreat-lists/threat/threat-{threatLevel}.txt",
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken))
                {
                    response.EnsureSuccessStatusCode();

                    var ipAddresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    using (var stream = await response.Content.ReadAsStreamAsync())
                    using (var reader = new StreamReader(stream))
                    {
                        string line;
                        var processedLines = 0;
                        while ((line = await reader.ReadLineAsync()) != null && !cancellationToken.IsCancellationRequested)
                        {
                            processedLines++;
                            if (processedLines % 1000 == 0)
                            {
                                await Task.Yield();
                            }

                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                                continue;

                            var ipPart = line.Split('#')[0].Trim();

                            if (string.IsNullOrWhiteSpace(ipPart))
                                continue;

                            if (ipPart.Contains("-"))
                            {
                                var range = ipPart.Split('-');
                                if (range.Length == 2 &&
                                    IPAddress.TryParse(range[0], out var startIP) &&
                                    IPAddress.TryParse(range[1], out var endIP))
                                {
                                    var ips = ExpandIPRange(startIP, endIP);
                                    foreach (var ip in ips)
                                    {
                                        ipAddresses.Add(ip);
                                    }
                                }
                            }
                            else if (IPAddress.TryParse(ipPart, out _))
                            {
                                ipAddresses.Add(ipPart);
                            }
                        }
                    }

                    return ipAddresses.ToList();
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (HttpRequestException ex)
            {
                LogError($"HTTP request failed for threat level {threatLevel}: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                LogError($"Error fetching IP threat list level {threatLevel}: {ex.Message}");
                throw;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public async Task<Dictionary<int, List<string>>> FetchMultipleThreatLists(int[] threatLevels, CancellationToken cancellationToken = default)
        {
            var result = new Dictionary<int, List<string>>();

            foreach (var level in threatLevels.OrderBy(l => l))
            {
                try
                {
                    var ips = await FetchIPThreatList(level, cancellationToken);
                    result.Add(level, ips);
                }
                catch (Exception ex)
                {
                    LogError($"Failed to fetch threat level {level}: {ex.Message}");
                    // Continue with other levels even if one fails
                }
            }

            return result;
        }

        public void SaveIPList(List<string> ipList)
        {
            try
            {
                var timestamp = DateTime.Now;
                var data = new IPListData
                {
                    IPAddresses = ipList,
                    LastUpdated = timestamp,
                    Count = ipList.Count
                };

                var filePath = Path.Combine(_ipListPath, "current_ip_list.json");
                var json = JsonConvert.SerializeObject(data, Formatting.Indented);

                // Write to temp file first
                var tempPath = Path.GetTempFileName();
                File.WriteAllText(tempPath, json);

                // Then move to final location
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
                File.Move(tempPath, filePath);

                // Save backup with timestamp
                var backupPath = Path.Combine(_ipListPath, $"ip_list_{timestamp:yyyyMMddHHmmss}.json");
                File.Copy(filePath, backupPath);

                // Cleanup old backups
                CleanupOldBackups();
            }
            catch (Exception ex)
            {
                LogError($"Error saving IP list: {ex.Message}");
                throw;
            }
        }

        public IPListData GetCurrentIPList()
        {
            try
            {
                var filePath = Path.Combine(_ipListPath, "current_ip_list.json");
                if (!File.Exists(filePath))
                {
                    return new IPListData
                    {
                        IPAddresses = new List<string>(),
                        LastUpdated = DateTime.MinValue,
                        Count = 0
                    };
                }

                var json = File.ReadAllText(filePath);
                return JsonConvert.DeserializeObject<IPListData>(json) ??
                    new IPListData { IPAddresses = new List<string>() };
            }
            catch (Exception ex)
            {
                LogError($"Error loading IP list: {ex.Message}");
                return new IPListData { IPAddresses = new List<string>() };
            }
        }

        private List<string> ExpandIPRange(IPAddress startIP, IPAddress endIP)
        {
            var result = new List<string>();
            try
            {
                var start = BitConverter.ToUInt32(startIP.GetAddressBytes().Reverse().ToArray(), 0);
                var end = BitConverter.ToUInt32(endIP.GetAddressBytes().Reverse().ToArray(), 0);

                // Limit range expansion to prevent memory issues
                if (end - start > 1000)
                {
                    LogError($"IP range too large: {startIP} - {endIP}");
                    return result;
                }

                for (var i = start; i <= end; i++)
                {
                    var bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                    var ip = new IPAddress(bytes);
                    result.Add(ip.ToString());
                }
            }
            catch (Exception ex)
            {
                LogError($"Error expanding IP range: {ex.Message}");
            }
            return result;
        }

        private void CleanupOldBackups()
        {
            try
            {
                var directory = new DirectoryInfo(_ipListPath);
                var files = directory.GetFiles("ip_list_*.json")
                    .OrderByDescending(f => f.CreationTime)
                    .Skip(5);

                foreach (var file in files)
                {
                    try
                    {
                        file.Delete();
                    }
                    catch (Exception ex)
                    {
                        LogError($"Error deleting backup file {file.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error cleaning up old backups: {ex.Message}");
            }
        }

        private void LogError(string message)
        {
            try
            {
                var logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "Logs"
                );
                Directory.CreateDirectory(logPath);
                var logFile = Path.Combine(logPath, $"iplist-manager-{DateTime.Now:yyyy-MM-dd}.log");
                var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - ERROR - {message}{Environment.NewLine}";
                File.AppendAllText(logFile, logMessage);
            }
            catch
            {
                // Ignore logging errors
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _semaphore?.Dispose();
                _disposed = true;
            }
        }
    }

    public class IPListData
    {
        public List<string> IPAddresses { get; set; } = new List<string>();
        public DateTime LastUpdated { get; set; }
        public int Count { get; set; }
    }
}