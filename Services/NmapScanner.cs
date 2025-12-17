using HomeNetworkGuardian.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Orchestrates the network scanning process using a high-performance, two-phase approach:
    /// Phase 1: Rapid Host Discovery (Ping Sweep).
    /// Phase 2: Targeted Security Port & Service Version Analysis.
    /// </summary>
    public static class NmapScanner
    {
        // Targeted ports commonly associated with vulnerabilities or network services
        private const string SecurityPorts = "21,22,23,80,139,161,443,445,554,1433,3389,5900-5902,8080,9100";

        private const string DiscoveryXml = "nmap_discovery.xml";
        private const string FinalScanXml = "nmap_final_scan.xml";

        /// <summary>
        /// Main entry point for the network scan.
        /// </summary>
        /// <param name="networkRange">The subnet to scan in CIDR format (e.g., 192.168.1.0/24).</param>
        /// <returns>A collection of discovered devices with detailed service information.</returns>
        public static List<Device> ScanNetwork(string networkRange)
        {
            Debug.WriteLine($"[Scanner] Starting Phase 1: Host Discovery on {networkRange}");

            // --- Phase 1: Fast Host Discovery ---
            List<string> activeIPs = DiscoverActiveHosts(networkRange);

            if (activeIPs.Count == 0)
            {
                Debug.WriteLine("[Scanner] No active hosts found. Terminating scan.");
                return new List<Device>();
            }

            Debug.WriteLine($"[Scanner] Phase 1 Complete. Found {activeIPs.Count} active IPs. Starting Phase 2...");

            // --- Phase 2: Focused Service & Version Detection ---
            string targetIPs = string.Join(" ", activeIPs);

            // Flags explanation:
            // -sS: TCP SYN Scan (Stealthy/Fast)
            // -sV --version-intensity 0: Rapid service fingerprinting
            // -Pn -n: Skip Ping/DNS for speed
            // -T4: Aggressive timing policy
            string arguments = $"-sS -sV --version-intensity 0 -Pn -n -T4 -p {SecurityPorts} {targetIPs} -oX {FinalScanXml}";

            if (!NmapProcessRunner.ExecuteNmapProcess(arguments, FinalScanXml))
            {
                Debug.WriteLine("[Scanner Error] Phase 2 failed or timed out.");
                DataUtils.CleanupXmlFile(FinalScanXml);
                return new List<Device>();
            }

            // --- Phase 3: Data Parsing & Cleanup ---
            List<Device> finalDevices = NmapXmlParser.ParseXmlOutput(FinalScanXml);

            // Ensure temporary files are deleted after parsing
            DataUtils.CleanupXmlFile(FinalScanXml);

            Debug.WriteLine($"[Scanner] Scan fully completed. {finalDevices.Count} devices processed.");
            return finalDevices;
        }

        /// <summary>
        /// Performs a "Ping Sweep" to identify live hosts without scanning ports.
        /// </summary>
        private static List<string> DiscoverActiveHosts(string networkRange)
        {
            // -sn: Skip port scan. -PR/PE/PS/PA: Multiple discovery methods for reliability.
            string arguments = $"-sn -n -PR -PE -PS -PA -T5 {networkRange} -oX {DiscoveryXml}";

            if (!NmapProcessRunner.ExecuteNmapProcess(arguments, DiscoveryXml))
            {
                return new List<string>();
            }

            List<string> activeIPs = NmapXmlParser.ParseActiveIPsFromXml(DiscoveryXml);

            // Cleanup discovery file immediately after use
            DataUtils.CleanupXmlFile(DiscoveryXml);

            return activeIPs;
        }
    }
}