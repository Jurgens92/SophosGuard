using System;
using System.Configuration.Install;
using System.ServiceProcess;
using System.Diagnostics;
using System.IO;

namespace SophosGuard
{
    public static class ServiceInstaller
    {
        public static void InstallService(string executablePath)
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "sc.exe";
                    // Add /service parameter to the executable path
                    process.StartInfo.Arguments = $"create SophosGuard binpath= \"{executablePath} /service\" start= auto";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0)
                    {
                        throw new Exception($"Service installation failed: {output}");
                    }

                    // Set service description
                    process.StartInfo.Arguments = "description SophosGuard \"Manages IP threat lists for Sophos XGS Firewall\"";
                    process.Start();
                    process.WaitForExit();


                    // Set recovery options
                    // First failure: Restart after 30 seconds
                    process.StartInfo.Arguments = "failure SophosGuard reset= 86400 actions= restart/30000";
                    process.Start();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error installing service: {ex.Message}", ex);
            }
        }

        public static void UninstallService()
        {
            try
            {
                // Stop the service first
                try
                {
                    using (ServiceController sc = new ServiceController("SophosGuard"))
                    {
                        if (sc.Status == ServiceControllerStatus.Running)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                    }
                }
                catch { } // Ignore errors if service is not running

                // Delete the service
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "sc.exe";
                    process.StartInfo.Arguments = "delete SophosGuard";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0)
                    {
                        throw new Exception($"Service uninstallation failed: {output}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error uninstalling service: {ex.Message}", ex);
            }
        }

        public static ServiceControllerStatus GetServiceStatus()
        {
            try
            {
                using (ServiceController sc = new ServiceController("SophosGuard"))
                {
                    return sc.Status;
                }
            }
            catch
            {
                return ServiceControllerStatus.Stopped;
            }
        }

        public static void StartService()
        {
            try
            {
                using (ServiceController sc = new ServiceController("SophosGuard"))
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error starting service: {ex.Message}", ex);
            }
        }

        public static void StopService()
        {
            try
            {
                using (ServiceController sc = new ServiceController("SophosGuard"))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error stopping service: {ex.Message}", ex);
            }
        }
    }
}