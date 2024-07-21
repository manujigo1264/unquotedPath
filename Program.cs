using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace UnquotedPath
{
    class Program
    {
        private static string GetServiceInstallPath(string serviceName)
        {
            using (RegistryKey regkey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\services\{serviceName}"))
            {
                if (regkey == null || regkey.GetValue("ImagePath") == null)
                    return "Not Found";

                return regkey.GetValue("ImagePath").ToString();
            }
        }

        static void Main(string[] args)
        {
            List<string> vulnSvcs = new List<string>();

            try
            {
                Console.WriteLine("Starting unquoted service paths scan...");

                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();

                using (RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"))
                {
                    if (services == null)
                    {
                        Console.WriteLine("[-] Unable to access services registry key.");
                        return;
                    }

                    foreach (string service in services.GetSubKeyNames())
                    {
                        using (RegistryKey imagePath = services.OpenSubKey(service))
                        {
                            if (imagePath == null)
                                continue;

                            string path = Convert.ToString(imagePath.GetValue("ImagePath"));
                            if (!string.IsNullOrEmpty(path) && !path.Contains("\"") && path.Contains(" ") &&
                                !path.Contains("System32", StringComparison.OrdinalIgnoreCase) &&
                                !path.Contains("SysWow64", StringComparison.OrdinalIgnoreCase))
                            {
                                vulnSvcs.Add(path);
                            }
                        }
                    }
                }

                stopwatch.Stop();

                List<string> distinctPaths = vulnSvcs.Distinct().ToList();
                if (!distinctPaths.Any())
                {
                    Console.WriteLine("[-] Couldn't find any unquoted service paths.");
                }
                else
                {
                    Console.WriteLine("[+] Unquoted service paths found:");
                    foreach (string path in distinctPaths)
                    {
                        Console.WriteLine($"  - {path}");
                    }
                }

                Console.WriteLine($"\nScan completed in {stopwatch.Elapsed.TotalSeconds:F2} seconds.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] An error occurred: {ex.Message}");
            }
        }
    }
}
