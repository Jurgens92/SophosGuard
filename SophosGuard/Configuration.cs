using System;
using System.IO;
using Newtonsoft.Json;

namespace SophosGuard
{


    public class FirewallRule
    {
        public string Name { get; set; } = "IPThreat";
        public string Description { get; set; } = "Block Known Malicious IPs";
        public string SourceZone { get; set; } = "WAN";
        public string DestinationZone { get; set; } = "LAN";
        public string Action { get; set; } = "Drop";
        public bool Enabled { get; set; } = true;
        public int Position { get; set; } = 1;
        public string IPListName { get; set; } = "ThreatList";
    }

    public class Configuration
    {
        // Connection Settings
        public string FirewallUrl { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";

        // Service Settings
        public int UpdateIntervalMinutes { get; set; } = 60;
        public string LogPath { get; set; } = "Logs";
        public string IPListPath { get; set; } = "IPList";
        public string ServiceName { get; set; } = "SophosGuard";
        public string ServiceDisplayName { get; set; } = "SophosGuard IP Threat Protection";
        public string ServiceDescription { get; set; } = "Manages IP threat lists for Sophos XGS Firewall";

        // Firewall Rule Settings
        public FirewallRule ThreatRule { get; set; } = new FirewallRule();
    }

    public static class ConfigurationManager
    {
        private static readonly string ConfigFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SophosGuard",
            "config.json"
        );

        public static Configuration LoadConfiguration()
        {
            try
            {
                if (File.Exists(ConfigFilePath))
                {
                    string json = File.ReadAllText(ConfigFilePath);
                    var config = JsonConvert.DeserializeObject<Configuration>(json);

                    // If we're loading an old configuration format, migrate it
                    if (config.ThreatRule == null)
                    {
                        config.ThreatRule = new FirewallRule();
                    }

                    return config ?? new Configuration();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error loading configuration: {ex.Message}", ex);
            }

            return new Configuration();
        }

        public static void SaveConfiguration(Configuration config)
        {
            try
            {
                string directoryPath = Path.GetDirectoryName(ConfigFilePath);
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                string json = JsonConvert.SerializeObject(config, Formatting.Indented);
                File.WriteAllText(ConfigFilePath, json);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error saving configuration: {ex.Message}", ex);
            }
        }
    }
}