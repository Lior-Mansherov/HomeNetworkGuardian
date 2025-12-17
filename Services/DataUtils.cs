using HomeNetworkGuardian.Models;
using System.IO;
using System.Text.Json;
using System.Diagnostics;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Utility class for configuration loading, data management, and file I/O operations.
    /// Optimized for handling file system transient failures and JSON data integrity.
    /// </summary>
    public static class DataUtils
    {
        /// <summary>
        /// Attempts to delete a temporary XML file with retry logic.
        /// Useful when external processes (like Nmap) might still be locking the file.
        /// </summary>
        /// <param name="xmlPath">The absolute path to the XML file.</param>
        public static void CleanupXmlFile(string xmlPath)
        {
            const int MaxRetries = 3;
            const int DelayMs = 100; // Increased slightly for stability on slower drives

            if (!File.Exists(xmlPath)) return;

            for (int i = 0; i < MaxRetries; i++)
            {
                try
                {
                    File.Delete(xmlPath);
                    Debug.WriteLine($"[Cleanup] Successfully deleted: {xmlPath}");
                    return;
                }
                catch (IOException ex) when (i < MaxRetries - 1)
                {
                    // File is likely locked by Nmap process, wait and retry
                    Debug.WriteLine($"[Cleanup] File locked, retrying ({i + 1}/{MaxRetries})...");
                    Thread.Sleep(DelayMs);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[Cleanup Error] Failed to delete {xmlPath}: {ex.Message}");
                    break;
                }
            }
        }

        /// <summary>
        /// Loads and parses the OUI (MAC prefix to Vendor) database.
        /// </summary>
        /// <param name="jsonFilePath">Path to the OUI JSON database.</param>
        /// <returns>A validated list of OuiEntry objects.</returns>
        public static List<OuiEntry> LoadOuiDatabase(string jsonFilePath)
        {
            if (!File.Exists(jsonFilePath))
            {
                Debug.WriteLine($"[DataUtils] OUI database missing at: {jsonFilePath}");
                return new List<OuiEntry>();
            }

            try
            {
                string json = File.ReadAllText(jsonFilePath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                var deserializedEntries = JsonSerializer.Deserialize<List<OuiEntry>>(json, options);

                // Clean data: Remove nulls and entries with missing prefixes
                return (deserializedEntries ?? new List<OuiEntry>())
                        .Where(e => e != null && !string.IsNullOrEmpty(e.MacPrefix))
                        .ToList();
            }
            catch (JsonException ex)
            {
                Debug.WriteLine($"[DataUtils] JSON Format Error in OUI database: {ex.Message}");
                return new List<OuiEntry>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DataUtils] Unexpected error loading OUI: {ex.Message}");
                return new List<OuiEntry>();
            }
        }

        /// <summary>
        /// Loads a mapping of Vendor names to Device Types from a configuration file.
        /// </summary>
        /// <param name="jsonFilePath">Path to the vendor map JSON.</param>
        /// <returns>A dictionary for O(1) vendor lookups.</returns>
        public static Dictionary<string, string> LoadVendorMapFromJson(string jsonFilePath)
        {
            if (!File.Exists(jsonFilePath))
            {
                Debug.WriteLine($"[DataUtils] Vendor map missing at: {jsonFilePath}");
                return new Dictionary<string, string>();
            }

            try
            {
                string json = File.ReadAllText(jsonFilePath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                return JsonSerializer.Deserialize<Dictionary<string, string>>(json, options)
                       ?? new Dictionary<string, string>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DataUtils] Error loading vendor map: {ex.Message}");
                return new Dictionary<string, string>();
            }
        }
    }
}