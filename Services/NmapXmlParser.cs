using HomeNetworkGuardian.Models;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Professional parser for Nmap XML output. 
    /// Transforms complex network scan data into strongly-typed C# objects.
    /// </summary>
    public static class NmapXmlParser
    {
        /// <summary>
        /// Parses detailed scan results including OS, Ports, and Service Versions.
        /// </summary>
        public static List<Device> ParseXmlOutput(string xmlPath)
        {
            var devices = new List<Device>();

            if (!File.Exists(xmlPath)) return devices;

            try
            {
                XDocument doc = XDocument.Load(xmlPath);

                var hosts = doc.Descendants("host")
                               .Where(h => h.Element("status")?.Attribute("state")?.Value == "up");

                foreach (var host in hosts)
                {
                    string ip = GetIpAddress(host);
                    string mac = GetMacAddress(host);

                    // Security Filter: Skip virtual/multicast infrastructure addresses
                    if (mac != "00:00:00:00:00:00" && NetworkUtils.IsSpecialAddress(mac))
                        continue;

                    string openPorts = GetOpenPortsString(host);
                    string os = GetOperatingSystem(host);

                    devices.Add(new Device
                    {
                        IP = ip,
                        MAC = mac,
                        OpenPorts = string.IsNullOrEmpty(openPorts) ? "No open security ports" : openPorts,
                        OS = os,
                        Vendor = "Unknown", // Assigned later via OUIService
                        DeviceType = "Unknown", // Assigned later via DeviceClassifier
                        IsSuspicious = false
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[XmlParser Error] Failed to parse results: {ex.Message}");
            }

            return devices;
        }

        /// <summary>
        /// Extracts active IPs for the initial discovery phase.
        /// </summary>
        public static List<string> ParseActiveIPsFromXml(string xmlPath)
        {
            if (!File.Exists(xmlPath)) return new List<string>();

            try
            {
                XDocument doc = XDocument.Load(xmlPath);
                return doc.Descendants("host")
                          .Where(h => h.Element("status")?.Attribute("state")?.Value == "up")
                          .Select(h => GetIpAddress(h))
                          .Where(ip => ip != "N/A")
                          .ToList();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[XmlParser Error] Discovery parsing failed: {ex.Message}");
                return new List<string>();
            }
        }

        // --- Private Extractors ---

        private static string GetIpAddress(XElement host) =>
            host.Elements("address")
                .FirstOrDefault(a => a.Attribute("addrtype")?.Value == "ipv4")
                ?.Attribute("addr")?.Value ?? "N/A";

        private static string GetMacAddress(XElement host) =>
            host.Elements("address")
                .FirstOrDefault(a => a.Attribute("addrtype")?.Value == "mac")
                ?.Attribute("addr")?.Value?.ToUpper() ?? "00:00:00:00:00:00";

        private static string GetOperatingSystem(XElement host) =>
            host.Descendants("osmatch").FirstOrDefault()?.Attribute("name")?.Value ?? "Unknown OS";

        private static string GetOpenPortsString(XElement host)
        {
            var portDetails = host.Descendants("port")
                .Where(p => {
                    var state = p.Element("state")?.Attribute("state")?.Value;
                    return state == "open" || state == "open|filtered";
                })
                .Select(FormatPortDetails);

            return string.Join(", ", portDetails);
        }

        private static string FormatPortDetails(XElement portElement)
        {
            string portId = portElement.Attribute("portid")?.Value ?? "??";
            XElement service = portElement.Element("service");

            if (service == null) return $"{portId}/Unknown";

            string name = service.Attribute("name")?.Value ?? "unknown";
            string product = service.Attribute("product")?.Value;
            string version = service.Attribute("version")?.Value;

            // Combine product and version: e.g., "Apache httpd 2.4.41"
            string versionInfo = string.Join(" ", new[] { product, version }.Where(s => !string.IsNullOrEmpty(s)));

            return string.IsNullOrEmpty(versionInfo)
                ? $"{portId}/{name}"
                : $"{portId}/{name} ({versionInfo})";
        }
    }
}