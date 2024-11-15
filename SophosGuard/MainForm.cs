using System;
using System.Windows.Forms;
using System.Drawing;
using System.Security.Principal;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace SophosGuard
{
    public partial class MainForm : Form
    {
        // Core controls
        private readonly TabControl tabControl;
        private readonly TabPage serviceTab;
        private readonly TabPage configTab;
        private readonly TabPage logsTab;

        // Service tab controls
        private readonly Label serviceStatusLabel;
        private readonly Button installButton;
        private readonly Button uninstallButton;
        private readonly Button startButton;
        private readonly Button stopButton;

        // Config tab controls
        private readonly TextBox firewallUrlTextBox;
        private readonly TextBox usernameTextBox;
        private readonly TextBox passwordTextBox;
        private readonly NumericUpDown updateIntervalNumeric;
        private readonly Button saveConfigButton;
        private readonly Button testConnectionButton;

        // Logs tab controls
        private readonly RichTextBox logViewerTextBox;
        private readonly Button refreshLogsButton;

        // State
        private bool _isAdmin;
        private Configuration _config;
        private readonly HttpClient _httpClient;

        // IPThreat List
        private readonly TabPage ipListTab;
        private readonly DataGridView ipListGridView;
        private readonly Button refreshIpListButton;
        private readonly Label ipListStatusLabel;
        private readonly ProgressBar progressBar;
        private readonly Button applySophosButton;
        private readonly Label lastSyncLabel;
        private readonly ComboBox threatListComboBox;
        private readonly Label threatListLabel;

        public MainForm()
        {
            try
            {
                InitializeComponent();

                // Basic form setup
                this.MinimumSize = new Size(800, 600);
                this.Text = "SophosGuard";

                // Initialize HttpClient
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
                };
                _httpClient = new HttpClient(handler);

                // Load configuration
                _config = ConfigurationManager.LoadConfiguration();

                // Initialize main tab control
                tabControl = new TabControl
                {
                    Dock = DockStyle.Fill
                };
                this.Controls.Add(tabControl);

                // Initialize all tab pages
                serviceTab = new TabPage("Service Management");
                configTab = new TabPage("Configuration");
                logsTab = new TabPage("Logs");
                ipListTab = new TabPage("IP Threat List");

                // Service tab controls
                serviceStatusLabel = new Label();
                installButton = new Button();
                uninstallButton = new Button();
                startButton = new Button();
                stopButton = new Button();

                // Config tab controls
                firewallUrlTextBox = new TextBox();
                usernameTextBox = new TextBox();
                passwordTextBox = new TextBox { UseSystemPasswordChar = true };
                updateIntervalNumeric = new NumericUpDown();
                saveConfigButton = new Button();
                testConnectionButton = new Button();

                // Logs tab controls
                logViewerTextBox = new RichTextBox();
                refreshLogsButton = new Button();

                // IP List tab controls
                ipListGridView = new DataGridView
                {
                    AllowUserToAddRows = false,
                    AllowUserToDeleteRows = false,
                    ReadOnly = true,
                    AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                    SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                    Dock = DockStyle.Fill
                };

                threatListComboBox = new ComboBox
                {
                    Dock = DockStyle.Fill,
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    Margin = new Padding(0, 5, 0, 5)
                };

                threatListLabel = new Label
                {
                    Text = "Select Threat List Level:",
                    AutoSize = true,
                    TextAlign = ContentAlignment.MiddleLeft
                };

                refreshIpListButton = new Button();
                ipListStatusLabel = new Label();
                progressBar = new ProgressBar
                {
                    Visible = false,
                    Style = ProgressBarStyle.Marquee
                };

                applySophosButton = new Button
                {
                    Text = "Apply to Sophos Firewall",
                    Dock = DockStyle.Fill,
                    Padding = new Padding(10, 0, 10, 0),
                    Margin = new Padding(0, 5, 0, 0),
                    BackColor = SystemColors.ControlLight,
                    FlatStyle = FlatStyle.Flat
                };

                lastSyncLabel = new Label
                {
                    Text = "Last Sync: Never",
                    AutoSize = true,
                    TextAlign = ContentAlignment.MiddleLeft
                };

                // Initialize all tabs
                InitializeTabs();

                // Check admin rights
                CheckAdminRights();

                // Update service status
                UpdateServiceStatus();

                // Load initial data
                LoadInitialData();
                InitializeIPList();

                LogMessage("Form initialized successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error initializing form: {ex.Message}\n{ex.StackTrace}");
                MessageBox.Show($"Error initializing form: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }



        private void CreateIpListTab()
        {
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 6,
                Padding = new Padding(10)
            };

            // Configure column styles
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70F));

            // Configure row styles
            panel.RowStyles.Clear();
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));  // Threat selector
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));  // Status label
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));  // Progress bar
            panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));  // Grid
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));  // Last sync label
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));  // Buttons

            // Add threat list selector with proper layout
            threatListLabel.Dock = DockStyle.Fill;
            threatListLabel.TextAlign = ContentAlignment.MiddleLeft;
            panel.Controls.Add(threatListLabel, 0, 0);

            // Populate and configure combo box
            threatListComboBox.Items.Clear();
            threatListComboBox.Items.AddRange(new object[]
            {
            new ThreatListItem(100, "Threat Level 100 (Smallest, Most Recent)"),            
            new ThreatListItem(75, "Threat Level 75 (Medium)"),
            new ThreatListItem(50, "Threat Level 50 (Medium)"),
            new ThreatListItem(25, "Threat Level 25 (Large)"),
            new ThreatListItem(0, "Threat Level 0 (Largest, Complete List)")
            });
            threatListComboBox.SelectedIndex = 0;  // Default to smallest list
            panel.Controls.Add(threatListComboBox, 1, 0);

            // Add status label
            ipListStatusLabel.Dock = DockStyle.Fill;
            ipListStatusLabel.TextAlign = ContentAlignment.MiddleLeft;
            panel.Controls.Add(ipListStatusLabel, 0, 1);
            panel.SetColumnSpan(ipListStatusLabel, 2);

            // Add progress bar
            progressBar.Dock = DockStyle.Fill;
            progressBar.Margin = new Padding(0, 3, 0, 3);
            panel.Controls.Add(progressBar, 0, 2);
            panel.SetColumnSpan(progressBar, 2);

            // Configure IP List Grid
            ipListGridView.Columns.Clear();
            ipListGridView.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "IPAddress",
                HeaderText = "IP Address",
                AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
                MinimumWidth = 120
            });
            ipListGridView.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "DateAdded",
                HeaderText = "Date Added",
                AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
                MinimumWidth = 150
            });

            // Grid styling
            ipListGridView.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(240, 240, 240);
            ipListGridView.EnableHeadersVisualStyles = false;
            ipListGridView.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(230, 230, 230);
            ipListGridView.ColumnHeadersDefaultCellStyle.Font = new Font(ipListGridView.Font, FontStyle.Bold);
            ipListGridView.ColumnHeadersHeight = 30;
            ipListGridView.RowHeadersVisible = false;
            ipListGridView.BorderStyle = BorderStyle.None;
            ipListGridView.BackgroundColor = Color.White;
            ipListGridView.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            ipListGridView.MultiSelect = false;
            ipListGridView.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            ipListGridView.GridColor = Color.LightGray;

            panel.Controls.Add(ipListGridView, 0, 3);
            panel.SetColumnSpan(ipListGridView, 2);

            // Last sync label
            lastSyncLabel.Dock = DockStyle.Fill;
            panel.Controls.Add(lastSyncLabel, 0, 4);
            panel.SetColumnSpan(lastSyncLabel, 2);

            // Button panel
            var buttonPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                AutoSize = true,
                Margin = new Padding(0, 5, 0, 0)
            };

            // Configure buttons
            refreshIpListButton.Text = "Refresh IP List";
            refreshIpListButton.Width = 150;
            refreshIpListButton.Click += RefreshIPList;
            buttonPanel.Controls.Add(refreshIpListButton);

            applySophosButton.Text = "Apply to Sophos";
            applySophosButton.Width = 150;
            applySophosButton.Click += ApplyToSophos;
            buttonPanel.Controls.Add(applySophosButton);

            panel.Controls.Add(buttonPanel, 0, 5);
            panel.SetColumnSpan(buttonPanel, 2);

            // Add copy functionality
            ipListGridView.KeyDown += (s, e) =>
            {
                if (e.Control && e.KeyCode == Keys.C)
                {
                    if (ipListGridView.GetCellCount(DataGridViewElementStates.Selected) > 0)
                    {
                        Clipboard.SetDataObject(ipListGridView.GetClipboardContent());
                    }
                }
            };

            // Add right-click menu
            var contextMenu = new ContextMenuStrip();
            var copyMenuItem = new ToolStripMenuItem("Copy Selected");
            copyMenuItem.Click += (s, e) =>
            {
                if (ipListGridView.GetCellCount(DataGridViewElementStates.Selected) > 0)
                {
                    Clipboard.SetDataObject(ipListGridView.GetClipboardContent());
                }
            };
            contextMenu.Items.Add(copyMenuItem);
            ipListGridView.ContextMenuStrip = contextMenu;

            // Clear any existing controls and add the panel
            ipListTab.Controls.Clear();
            ipListTab.Controls.Add(panel);
        }


        private void InitializeTabs()
        {
            // Clear any existing tabs first
            tabControl.TabPages.Clear();

            // Add tabs only once in the desired order
            tabControl.TabPages.AddRange(new TabPage[]
            {
            serviceTab,     // Service Management tab
            configTab,      // Configuration tab
            logsTab,        // Logs tab
            ipListTab       // IP Threat List tab
            });

            // Now create the content for each tab
            CreateServiceTab();
            CreateConfigTab();
            CreateLogsTab();
            CreateIpListTab();
        }


        private void InitializeIPList()
        {
            LoadLocalIPList();
        }

        private class ThreatListItem
        {
            public int Level { get; }
            public string DisplayName { get; }

            public ThreatListItem(int level, string displayName)
            {
                Level = level;
                DisplayName = displayName;
            }

            public override string ToString()
            {
                return DisplayName;
            }
        }

        //sophos
        private async void ApplyToSophos(object sender, EventArgs e)
        {
            applySophosButton.Enabled = false;
            applySophosButton.Text = "Applying to Firewall...";
            progressBar.Visible = true;

            try
            {
                // Get current IP list
                var allIPs = ipListGridView.Rows.Cast<DataGridViewRow>()
                    .Select(row => row.Cells["IPAddress"].Value.ToString())
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .ToList();

                if (allIPs.Count == 0)
                {
                    MessageBox.Show("No IP addresses to apply.", "Warning",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
                };

                using (var client = new HttpClient(handler))
                {
                    client.Timeout = TimeSpan.FromMinutes(5);
                    var apiUrl = $"https://{_config.FirewallUrl}:4444/webconsole/APIController";

                    // First create the IP list
                    ipListStatusLabel.Text = "Status: Creating IP list...";
                    var ipListXml = CreateIPListXml(allIPs, true);
                    var ipListResponse = await SendSophosRequest(client, apiUrl, ipListXml);

                    if (!ipListResponse.IsSuccessStatusCode)
                    {
                        throw new Exception($"Failed to create IP list: {await ipListResponse.Content.ReadAsStringAsync()}");
                    }

                    // Then create the firewall rule
                    ipListStatusLabel.Text = "Status: Creating firewall rule...";
                    var ruleXml = CreateFirewallRuleXml();
                    var ruleResponse = await SendSophosRequest(client, apiUrl, ruleXml);

                    if (!ruleResponse.IsSuccessStatusCode)
                    {
                        throw new Exception($"Failed to create firewall rule: {await ruleResponse.Content.ReadAsStringAsync()}");
                    }

                    lastSyncLabel.Text = $"Last Sync: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
                    MessageBox.Show($"Successfully applied {allIPs.Count} IP addresses and created firewall rule!",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error applying to firewall: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                LogMessage($"Error applying to Sophos: {ex.Message}");
            }
            finally
            {
                applySophosButton.Enabled = true;
                applySophosButton.Text = "Apply to Sophos Firewall";
                progressBar.Visible = false;
                ipListStatusLabel.Text = "Status: Complete";
            }
        }

        private string CreateIPListXml(List<string> ipAddresses, bool isFirstBatch)
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
        <Name>IPThreatList</Name>
        <IPFamily>IPv4</IPFamily>
        <HostType>IPList</HostType>        
        <ListOfIPAddresses>{ipListString}</ListOfIPAddresses>  
    </IPHost>     
    </Set>
</Request>";
        }
        //{ipListString}




        private string CreateFirewallRuleXml()
        {
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
                            <Network>IPThreatList</Network>
                        </SourceNetworks>
                    </NetworkPolicy>
                </FirewallRule>
            </Set>
        </Request>";
        }


        private async Task<HttpResponseMessage> SendSophosRequest(HttpClient client, string apiUrl, string xmlContent)
        {
            try
            {
                LogMessage($"Sending request to Sophos: {xmlContent}");

                var formContent = new MultipartFormDataContent();
                formContent.Add(new StringContent(xmlContent), "reqxml");

                var response = await client.PostAsync(apiUrl, formContent);
                var responseContent = await response.Content.ReadAsStringAsync();
                LogMessage($"Sophos API Response: {responseContent}");

                if (responseContent.Contains("Authentication Failure"))
                {
                    throw new Exception("Authentication failed. Please check your credentials.");
                }

                // Check for other potential errors in the response
                if (responseContent.Contains("<Status>Failure</Status>") ||
                    responseContent.Contains("<Error>"))
                {
                    throw new Exception($"Sophos API Error: {responseContent}");
                }

                return response;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in SendSophosRequest: {ex.Message}");
                throw;
            }
        }

        private async void RefreshIPList(object sender, EventArgs e)
        {
            refreshIpListButton.Enabled = false;
            refreshIpListButton.Text = "Refreshing...";
            progressBar.Visible = true;

            try
            {
                var selectedItem = threatListComboBox.SelectedItem as ThreatListItem;
                if (selectedItem == null)
                {
                    MessageBox.Show("Please select a threat list level.", "Warning",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                ipListStatusLabel.Text = $"Status: Fetching threat list level {selectedItem.Level}...";

                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromMinutes(5);
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("SophosGuard/1.0");

                    // Download the selected threat list
                    var url = $"https://lists.ipthreat.net/file/ipthreat-lists/threat/threat-{selectedItem.Level}.txt";
                    var response = await client.GetStringAsync(url);
                    var ipAddresses = new HashSet<string>(); // Use HashSet for deduplication

                    using (var reader = new StringReader(response))
                    {
                        string line;
                        int processedLines = 0;
                        while ((line = reader.ReadLine()) != null)
                        {
                            processedLines++;
                            if (processedLines % 1000 == 0)
                            {
                                ipListStatusLabel.Text = $"Status: Processing line {processedLines:N0}...";
                                Application.DoEvents();
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

                    // Update the grid
                    ipListGridView.Rows.Clear();
                    var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    foreach (var ip in ipAddresses)
                    {
                        ipListGridView.Rows.Add(ip, timestamp);
                    }

                    // Save to local storage
                    SaveIPList(ipAddresses.ToList());

                    ipListStatusLabel.Text = $"Status: Loaded {ipAddresses.Count:N0} IP addresses from threat list level {selectedItem.Level}";
                    LogMessage($"Refreshed IP list from threat level {selectedItem.Level}. Found {ipAddresses.Count:N0} IPs");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error refreshing IP list: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                LogMessage($"Error in RefreshIPList: {ex.Message}");
                ipListStatusLabel.Text = "Status: Error refreshing list";
            }
            finally
            {
                refreshIpListButton.Enabled = true;
                refreshIpListButton.Text = "Refresh IP List";
                progressBar.Visible = false;
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
                    LogMessage($"IP range too large: {startIP} - {endIP}");
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
                LogMessage($"Error expanding IP range: {ex.Message}");
            }
            return result;
        }

        private void SaveIPList(List<string> ipList)
        {
            try
            {
                var ipListPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "IPList"
                );
                Directory.CreateDirectory(ipListPath);

                var data = new IPListData
                {
                    IPAddresses = ipList,
                    LastUpdated = DateTime.Now,
                    Count = ipList.Count
                };

                var filePath = Path.Combine(ipListPath, "current_ip_list.json");
                File.WriteAllText(filePath, JsonConvert.SerializeObject(data, Formatting.Indented));

                // Save backup with timestamp
                var backupPath = Path.Combine(ipListPath, $"ip_list_{DateTime.Now:yyyyMMddHHmmss}.json");
                File.Copy(filePath, backupPath);

                // Cleanup old backups (keep last 5)
                CleanupOldBackups(ipListPath);
            }
            catch (Exception ex)
            {
                LogMessage($"Error saving IP list: {ex.Message}");
                throw;
            }
        }

        private void CleanupOldBackups(string ipListPath)
        {
            try
            {
                var directory = new DirectoryInfo(ipListPath);
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
                        LogMessage($"Error deleting backup file {file.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error cleaning up old backups: {ex.Message}");
            }
        }

        private void LoadLocalIPList()
        {
            try
            {
                var ipListPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "IPList",
                    "current_ip_list.json"
                );

                if (File.Exists(ipListPath))
                {
                    var json = File.ReadAllText(ipListPath);
                    var data = JsonConvert.DeserializeObject<IPListData>(json);

                    ipListGridView.Rows.Clear();
                    foreach (var ip in data.IPAddresses)
                    {
                        ipListGridView.Rows.Add(ip, data.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss"));
                    }

                    ipListStatusLabel.Text = $"Status: Loaded {data.Count:N0} IP addresses from local storage";
                }
                else
                {
                    ipListStatusLabel.Text = "Status: No local IP list found";
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error loading local IP list: {ex.Message}");
                ipListStatusLabel.Text = "Status: Error loading local list";
            }
        }

        private void CreateServiceTab()
        {
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Padding = new Padding(10)
            };

            // Service Status Label
            serviceStatusLabel.Text = "Service Status: Checking...";
            serviceStatusLabel.AutoSize = true;
            serviceStatusLabel.Dock = DockStyle.Top;
            serviceStatusLabel.Margin = new Padding(0, 10, 0, 20);

            // Install Button
            installButton.Text = "Install Service";
            installButton.Size = new Size(200, 35);
            installButton.Click += InstallService;

            // Uninstall Button
            uninstallButton.Text = "Uninstall Service";
            uninstallButton.Size = new Size(200, 35);
            uninstallButton.Click += UninstallService;

            // Start Button
            startButton.Text = "Start Service";
            startButton.Size = new Size(200, 35);
            startButton.Click += StartService;

            // Stop Button
            stopButton.Text = "Stop Service";
            stopButton.Size = new Size(200, 35);
            stopButton.Click += StopService;

            panel.Controls.AddRange(new Control[]
            {
                serviceStatusLabel,
                installButton,
                uninstallButton,
                startButton,
                stopButton
            });

            serviceTab.Controls.Add(panel);
            
        }

        private void CreateConfigTab()
        {
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 6,
                Padding = new Padding(10)
            };

            // Column styles
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70F));

            // Add labels and controls
            panel.Controls.Add(new Label { Text = "Firewall URL:", AutoSize = true }, 0, 0);
            firewallUrlTextBox.Text = _config.FirewallUrl;
            firewallUrlTextBox.Dock = DockStyle.Fill;
            panel.Controls.Add(firewallUrlTextBox, 1, 0);

            panel.Controls.Add(new Label { Text = "Username:", AutoSize = true }, 0, 1);
            usernameTextBox.Text = _config.Username;
            usernameTextBox.Dock = DockStyle.Fill;
            panel.Controls.Add(usernameTextBox, 1, 1);

            panel.Controls.Add(new Label { Text = "Password:", AutoSize = true }, 0, 2);
            passwordTextBox.Text = _config.Password;
            passwordTextBox.Dock = DockStyle.Fill;
            panel.Controls.Add(passwordTextBox, 1, 2);

            panel.Controls.Add(new Label { Text = "Update Interval (minutes):", AutoSize = true }, 0, 3);
            updateIntervalNumeric.Minimum = 1;
            updateIntervalNumeric.Maximum = 1440;
            updateIntervalNumeric.Value = _config.UpdateIntervalMinutes;
            updateIntervalNumeric.Dock = DockStyle.Fill;
            panel.Controls.Add(updateIntervalNumeric, 1, 3);

            testConnectionButton.Text = "Test Connection";
            testConnectionButton.Click += TestConnection;
            panel.Controls.Add(testConnectionButton, 1, 4);

            saveConfigButton.Text = "Save Configuration";
            saveConfigButton.Click += SaveConfig;
            panel.Controls.Add(saveConfigButton, 1, 5);

            configTab.Controls.Add(panel);
           
        }

        private void CreateLogsTab()
        {
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 6,
                Padding = new Padding(10)
            };

            logViewerTextBox.Dock = DockStyle.Fill;
            logViewerTextBox.ReadOnly = true;
            logViewerTextBox.BackColor = Color.White;
            logViewerTextBox.Font = new Font("Consolas", 9.75F, FontStyle.Regular);
            panel.Controls.Add(logViewerTextBox, 0, 0);

            refreshLogsButton.Text = "Refresh Logs";
            refreshLogsButton.Click += RefreshLogs;
            panel.Controls.Add(refreshLogsButton, 0, 1);

            logsTab.Controls.Add(panel);
            
        }

        private void LoadInitialData()
        {
            try
            {
                RefreshLogs(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                LogMessage($"Error loading initial data: {ex.Message}");
            }
        }

        private void InstallService(object sender, EventArgs e)
        {
            if (!_isAdmin)
            {
                MessageBox.Show("Administrator rights required to install the service.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                string executablePath = Path.Combine(Application.StartupPath, "SophosGuard.exe");
                ServiceInstaller.InstallService(executablePath);
                MessageBox.Show("Service installed successfully.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error installing service: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UninstallService(object sender, EventArgs e)
        {
            if (!_isAdmin)
            {
                MessageBox.Show("Administrator rights required to uninstall the service.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                ServiceInstaller.UninstallService();
                MessageBox.Show("Service uninstalled successfully.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error uninstalling service: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartService(object sender, EventArgs e)
        {
            if (!_isAdmin)
            {
                MessageBox.Show("Administrator rights required to start the service.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                ServiceInstaller.StartService();
                MessageBox.Show("Service started successfully.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting service: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StopService(object sender, EventArgs e)
        {
            if (!_isAdmin)
            {
                MessageBox.Show("Administrator rights required to stop the service.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                ServiceInstaller.StopService();
                MessageBox.Show("Service stopped successfully.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error stopping service: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void TestConnection(object sender, EventArgs e)
        {
            testConnectionButton.Enabled = false;
            testConnectionButton.Text = "Testing...";

            try
            {
                var testConfig = new Configuration
                {
                    FirewallUrl = firewallUrlTextBox.Text,
                    Username = usernameTextBox.Text,
                    Password = passwordTextBox.Text
                };

                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
                };

                using (var client = new HttpClient(handler))
                {
                    var apiUrl = $"https://{testConfig.FirewallUrl}:4444/webconsole/APIController";

                    var testXml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
                <Request>
                    <Login>
                        <Username>{testConfig.Username}</Username>
                        <Password>{testConfig.Password}</Password>
                    </Login>
                    <Get>
                        <IPHostGroup/>
                    </Get>
                </Request>";

                    var formContent = new MultipartFormDataContent();
                    formContent.Add(new StringContent(testXml), "reqxml");

                    var response = await client.PostAsync(apiUrl, formContent);
                    var responseContent = await response.Content.ReadAsStringAsync();
                    LogMessage($"Test connection response: {responseContent}");

                    if (responseContent.Contains("Authentication Failure"))
                    {
                        throw new Exception("Authentication failed. Please check your credentials.");
                    }

                    MessageBox.Show("Successfully connected to Sophos XGS Firewall!",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error testing connection: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                testConnectionButton.Enabled = true;
                testConnectionButton.Text = "Test Connection";
            }
        }

        private void SaveConfig(object sender, EventArgs e)
        {
            try
            {
                _config.FirewallUrl = firewallUrlTextBox.Text;
                _config.Username = usernameTextBox.Text;
                _config.Password = passwordTextBox.Text;
                _config.UpdateIntervalMinutes = (int)updateIntervalNumeric.Value;

                ConfigurationManager.SaveConfiguration(_config);
                MessageBox.Show("Configuration saved successfully.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving configuration: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RefreshLogs(object sender, EventArgs e)
        {
            try
            {
                string logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "Logs",
                    $"sophosguard-{DateTime.Now:yyyy-MM-dd}.log"
                );

                if (File.Exists(logPath))
                {
                    logViewerTextBox.Text = File.ReadAllText(logPath);
                    logViewerTextBox.SelectionStart = logViewerTextBox.Text.Length;
                    logViewerTextBox.ScrollToCaret();
                }
                else
                {
                    logViewerTextBox.Text = "No logs found for today.";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading logs: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UpdateServiceStatus()
        {
            try
            {
                var status = ServiceInstaller.GetServiceStatus();
                serviceStatusLabel.Text = $"Service Status: {status}";
            }
            catch (Exception ex)
            {
                LogMessage($"Error updating service status: {ex.Message}");
                serviceStatusLabel.Text = "Service Status: Error";
            }
        }

        private void CheckAdminRights()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            _isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!_isAdmin)
            {
                MessageBox.Show(
                    "Please run this application as Administrator to manage the service.",
                    "Administrator Rights Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }

        private void LogMessage(string message)
        {
            try
            {
                var logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SophosGuard",
                    "Logs"
                );
                Directory.CreateDirectory(logPath);
                var logFile = Path.Combine(logPath, $"sophosguard-{DateTime.Now:yyyy-MM-dd}.log");
                var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";
                File.AppendAllText(logFile, logMessage);
            }
            
            catch
            {
                // Ignore logging errors
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Dispose managed resources
                _httpClient?.Dispose();
                components?.Dispose();

                // Dispose controls
                tabControl?.Dispose();
                serviceStatusLabel?.Dispose();
                installButton?.Dispose();
                uninstallButton?.Dispose();
                startButton?.Dispose();
                stopButton?.Dispose();
                firewallUrlTextBox?.Dispose();
                usernameTextBox?.Dispose();
                passwordTextBox?.Dispose();
                updateIntervalNumeric?.Dispose();
                saveConfigButton?.Dispose();
                testConnectionButton?.Dispose();
                logViewerTextBox?.Dispose();
                refreshLogsButton?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}