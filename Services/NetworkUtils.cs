using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Provides utility methods for network analysis, address calculation, and filtering.
    /// </summary>
    public static class NetworkUtils
    {
        /// <summary>
        /// Automatically determines the local network range in CIDR format.
        /// Identifies the active IPv4 interface and assumes a /24 subnet.
        /// </summary>
        /// <returns>A CIDR string (e.g., "192.168.1.0/24") or a loopback fallback.</returns>
        public static string FindLocalNetworkRange()
        {
            try
            {
                // Retrieve all network interfaces and find the first active non-loopback IPv4 address.
                var host = Dns.GetHostEntry(Dns.GetHostName());
                var activeIp = host.AddressList.FirstOrDefault(ip =>
                    ip.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(ip));

                if (activeIp != null)
                {
                    string ipString = activeIp.ToString();
                    int lastDotIndex = ipString.LastIndexOf('.');

                    if (lastDotIndex != -1)
                    {
                        string subnet = ipString.Substring(0, lastDotIndex) + ".0/24";
                        Debug.WriteLine($"[NetworkUtils] Detected Local Subnet: {subnet}");
                        return subnet;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NetworkUtils Error] Failed to determine network range: {ex.Message}");
            }

            // Fallback to loopback if no active network is found.
            return "127.0.0.1/32";
        }

        /// <summary>
        /// Identifies if a MAC address belongs to a reserved group (Multicast/Broadcast).
        /// These are non-device addresses used for network protocol overhead.
        /// </summary>
        public static bool IsSpecialAddress(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return true;

            // Common reserved address prefixes:
            // FF:FF:FF... - Broadcast
            // 01:00:5E... - IPv4 Multicast
            // 33:33:...    - IPv6 Multicast
            return mac.StartsWith("FF:FF:FF", StringComparison.OrdinalIgnoreCase) ||
                   mac.StartsWith("01:00:5E", StringComparison.OrdinalIgnoreCase) ||
                   mac.StartsWith("33:33", StringComparison.OrdinalIgnoreCase);
        }
    }
}
