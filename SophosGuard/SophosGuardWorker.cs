﻿using System;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;

namespace SophosGuard
{
    public class SophosGuardWorker : IDisposable
    {
        private readonly IPListManager _ipListManager;
        private readonly HttpClient _httpClient;
        private readonly Timer _updateTimer;
        private Configuration _config;
        private bool _isRunning;
        private readonly SemaphoreSlim _updateLock;
        private const int MAX_RETRIES = 3;
        private const int RETRY_DELAY_SECONDS = 30;

        public SophosGuardWorker(IPListManager ipListManager, Configuration config)
        {
            _ipListManager = ipListManager;
            _config = config;
            _updateLock = new SemaphoreSlim(1, 1);

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };
            _httpClient = new HttpClient(handler);

            // Initialize timer but don't start it yet
            _updateTimer = new Timer(async _ => await ExecuteUpdateCycle(), null, Timeout.Infinite, Timeout.Infinite);
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            LogMessage("Worker service starting");
            
            // Run initial update immediately
            Task.Run(async () => await ExecuteUpdateCycle());
            
            // Setup timer for subsequent updates
            var interval = TimeSpan.FromMinutes(_config.UpdateIntervalMinutes);
            _updateTimer.Change(interval, interval);
            
            LogMessage($"Update timer configured for {_config.UpdateIntervalMinutes} minute intervals");
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            _updateTimer.Change(Timeout.Infinite, Timeout.Infinite);
            LogMessage("Worker service stopped");
        }

        private async Task ExecuteUpdateCycle()
        {
            if (!await _updateLock.WaitAsync(0)) // Don't wait if already running
            {
                LogMessage("Update cycle already in progress, skipping");
                return;
            }

            try
            {
                LogMessage("Starting update cycle");
                
                // Step 1: Fetch new IP threat list
                var ipList = await FetchIPThreatListWithRetry();
                if (ipList == null || !ipList.Any())
                {
                    LogMessage("No IP addresses received from threat feed");
                    return;
                }

                // Step 2: Save the updated list
                _ipListManager.SaveIPList(ipList);
                LogMessage($"Saved {ipList.Count} IP addresses to local storage");

                // Step 3: Update Sophos Firewall rules
                await UpdateSophosFirewallWithRetry(ipList);
                
                LogMessage("Update cycle completed successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error in update cycle: {ex.Message}");
            }
            finally
            {
                _updateLock.Release();
            }
        }

        private async Task<List<string>> FetchIPThreatListWithRetry()
        {
            var allIPs = new HashSet<string>();

            for (int attempt = 1; attempt <= MAX_RETRIES; attempt++)
            {
                try
                {
                    // Always fetch the primary threat level
                    LogMessage($"Fetching primary IP threat list level {_config.ThreatLevel} (Attempt {attempt}/{MAX_RETRIES})");
                    var primaryList = await _ipListManager.FetchIPThreatList(_config.ThreatLevel);
                    foreach (var ip in primaryList)
                    {
                        allIPs.Add(ip);
                    }
                    LogMessage($"Fetched {primaryList.Count} IPs from threat level {_config.ThreatLevel}");

                    // If multiple lists are enabled, fetch additional levels
                    if (_config.EnableMultipleLists && _config.AdditionalThreatLevels?.Length > 0)
                    {
                        foreach (var level in _config.AdditionalThreatLevels)
                        {
                            if (level == _config.ThreatLevel) continue; // Skip if same as primary

                            LogMessage($"Fetching additional threat list level {level}");
                            var additionalList = await _ipListManager.FetchIPThreatList(level);
                            var newIPs = additionalList.Except(allIPs).ToList();
                            foreach (var ip in newIPs)
                            {
                                allIPs.Add(ip);
                            }
                            LogMessage($"Added {newIPs.Count} unique IPs from threat level {level}");
                        }
                    }

                    LogMessage($"Total unique IPs collected: {allIPs.Count}");
                    return allIPs.ToList();
                }
                catch (Exception ex)
                {
                    LogMessage($"Error fetching IP list (Attempt {attempt}): {ex.Message}");
                    if (attempt < MAX_RETRIES)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(RETRY_DELAY_SECONDS));
                    }
                }
            }
            throw new Exception($"Failed to fetch IP threat list after {MAX_RETRIES} attempts");
        }

        private async Task UpdateSophosFirewallWithRetry(List<string> ipList)
        {
            // Split IPs into manageable chunks (Sophos has limits)
            var ipChunks = new List<List<string>>();
            for (int i = 0; i < ipList.Count; i += 1000)
            {
                ipChunks.Add(ipList.Skip(i).Take(1000).ToList());
            }

            for (int attempt = 1; attempt <= MAX_RETRIES; attempt++)
            {
                try
                {
                    LogMessage($"Updating Sophos Firewall (Attempt {attempt}/{MAX_RETRIES})");
                    
                    // Update IP lists
                    for (int i = 0; i < ipChunks.Count; i++)
                    {
                        var listName = $"IPThreatList_{i}";
                        var ipListXml = CreateIPListXml(ipChunks[i], listName);
                        await SendSophosRequest(ipListXml);
                        LogMessage($"Updated IP list {listName} with {ipChunks[i].Count} addresses");
                    }

                    // Update firewall rule
                    var ruleXml = CreateFirewallRuleXml(ipChunks.Count);
                    await SendSophosRequest(ruleXml);
                    LogMessage("Updated firewall rule successfully");
                    
                    return; // Success
                }
                catch (Exception ex)
                {
                    LogMessage($"Error updating Sophos Firewall (Attempt {attempt}): {ex.Message}");
                    if (attempt < MAX_RETRIES)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(RETRY_DELAY_SECONDS));
                    }
                }
            }
            throw new Exception($"Failed to update Sophos Firewall after {MAX_RETRIES} attempts");
        }

        private string CreateIPListXml(List<string> ipAddresses, string listName)
        {
            var ipListString = string.Join(",", ipAddresses);
            return $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<Request>
    <Login>
        <Username>{_config.Username}</Username>
        <Password>{_config.Password}</Password>
    </Login>
    <Set>     
        <IPHost>
            <Name>{listName}</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IPList</HostType>        
            <ListOfIPAddresses>{ipListString}</ListOfIPAddresses>  
        </IPHost>     
    </Set>
</Request>";
        }

        private string CreateFirewallRuleXml(int listCount)
        {
            var sourceNetworksXml = string.Join(Environment.NewLine,
                Enumerable.Range(0, listCount)
                    .Select(i => $"<Network>IPThreatList_{i}</Network>"));

            return $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<Request>
    <Login>
        <Username>{_config.Username}</Username>
        <Password>{_config.Password}</Password>
    </Login>
    <Set>
        <FirewallRule transactionid="""">
            <Name>Block_IPThreat_List</Name>
            <Description>Block known malicious IPs from IPThreat.net</Description>
            <IPFamily>IPv4</IPFamily>
            <Status>Enable</Status>
            <Position>Top</Position>
            <PolicyType>Network</PolicyType>
            <NetworkPolicy>
                <Action>Drop</Action>
                <LogTraffic>Enable</LogTraffic>
                <SkipLocalDestined>Disable</SkipLocalDestined>
                <Schedule>All The Time</Schedule>
                <SourceNetworks>
                    {sourceNetworksXml}
                </SourceNetworks>
            </NetworkPolicy>
        </FirewallRule>
    </Set>
</Request>";
        }

        private async Task SendSophosRequest(string xmlContent)
        {
            var apiUrl = $"https://{_config.FirewallUrl}:4444/webconsole/APIController";
            var formContent = new MultipartFormDataContent();
            formContent.Add(new StringContent(xmlContent), "reqxml");

            var response = await _httpClient.PostAsync(apiUrl, formContent);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (responseContent.Contains("Authentication Failure"))
            {
                throw new Exception("Authentication failed with Sophos Firewall");
            }
            if (responseContent.Contains("<Status>Failure</Status>") || responseContent.Contains("<Error>"))
            {
                throw new Exception($"Sophos API Error: {responseContent}");
            }

            response.EnsureSuccessStatusCode();
        }

        private void LogMessage(string message)
        {
            SophosGuardService.LogMessage($"Worker: {message}");
        }

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _httpClient?.Dispose();
            _updateLock?.Dispose();
        }
    }
}