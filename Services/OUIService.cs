using System;
using System.Collections.Generic;
using System.Linq;
using HomeNetworkGuardian.Models;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Service responsible for mapping MAC addresses to hardware vendors using an OUI database.
    /// Optimized for high-speed lookups using a pre-processed Dictionary.
    /// </summary>
    public class OUIService
    {
        private readonly Dictionary<string, string> ouiLookupMap;

        /// <summary>
        /// Initializes the service by pre-processing the OUI entries into a lookup map.
        /// </summary>
        /// <param name="ouiEntries">Raw list of OUI entries from the JSON database.</param>
        public OUIService(List<OuiEntry> ouiEntries)
        {
            ouiLookupMap = (ouiEntries ?? new List<OuiEntry>())
                .Where(e => !string.IsNullOrEmpty(e?.MacPrefix))
                .ToDictionary(
                    e => CleanAddress(e.MacPrefix),
                    e => e.VendorName,
                    StringComparer.OrdinalIgnoreCase
                );
        }

        /// <summary>
        /// Identifies the vendor associated with a given MAC address.
        /// </summary>
        /// <param name="macAddress">The raw MAC address string (e.g., "AA:BB:CC:11:22:33").</param>
        /// <returns>The vendor name or "Unknown".</returns>
        public string GetVendor(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress)) return "Unknown";

            string prefix = ExtractOuiPrefix(macAddress);

            if (ouiLookupMap.TryGetValue(prefix, out string? vendor))
            {
                return vendor.Trim();
            }

            return "Unknown";
        }

        /// <summary>
        /// Extracts the first 6 hex characters of a MAC address for OUI lookup.
        /// </summary>
        private string ExtractOuiPrefix(string macAddress)
        {
            string cleaned = CleanAddress(macAddress);
            return cleaned.Length >= 6 ? cleaned.Substring(0, 6) : cleaned;
        }

        /// <summary>
        /// Standardizes MAC address format by removing common separators.
        /// </summary>
        private static string CleanAddress(string address)
        {
            return address.Replace(":", "")
                          .Replace("-", "")
                          .Replace(".", "")
                          .ToUpper();
        }
    }
}