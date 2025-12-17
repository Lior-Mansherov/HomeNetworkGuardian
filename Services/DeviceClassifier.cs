using HomeNetworkGuardian.Models;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Analyzes device attributes (Vendor, Open Ports) to intelligently classify 
    /// the device type (e.g., Printer, Camera, Workstation).
    /// </summary>
    public class DeviceClassifier
    {
        private readonly Dictionary<string, string> vendorToTypeMap;

        public DeviceClassifier(Dictionary<string, string> vendorMap)
        {
            vendorToTypeMap = vendorMap ?? new Dictionary<string, string>();
        }

        /// <summary>
        /// Classifies the device by combining Vendor lookup with Open Port analysis.
        /// Port analysis often provides more accurate results for IoT devices.
        /// </summary>
        public string DetermineDeviceType(Device device)
        {
            if (device == null) return "Unknown";

            // Normalize strings for reliable comparison
            string ports = (device.OpenPorts ?? string.Empty).ToLower();
            string vendor = (device.Vendor ?? "Unknown").Trim();

            // Step 1: Initial classification based on Vendor
            string deviceType = LookupVendor(vendor);

            // Step 2: Refine classification based on "Signature" Ports
            // This logic is crucial for devices that mask their vendor or use generic NICs.
            return RefineByTypeSignature(deviceType, ports);
        }

        /// <summary>
        /// Performs a look-up in the pre-loaded vendor dictionary.
        /// </summary>
        private string LookupVendor(string vendor)
        {
            if (vendorToTypeMap.TryGetValue(vendor, out string type))
            {
                return type;
            }
            return "General Host/Unknown";
        }

        /// <summary>
        /// Overrides or refines the device type based on specific service signatures.
        /// </summary>
        private string RefineByTypeSignature(string currentType, string ports)
        {
            // Port 9100: Standard for network printers (RAW printing)
            if (ports.Contains("9100/"))
                return "Printer";

            // Port 554: Real Time Streaming Protocol (RTSP) - High confidence for IP Cameras
            if (ports.Contains("554/rtsp"))
                return "IP Camera/DVR";

            // Port 3389: Remote Desktop Protocol (RDP) - Native to Windows Workstations
            if (ports.Contains("3389/ms-wbt-server"))
                return "Windows Workstation";

            // Port 22: SSH - Common in Linux servers and many IoT/Embedded systems
            if (ports.Contains("22/ssh") && currentType == "General Host/Unknown")
                return "Linux Server/IoT Device";

            // Port 80/443 on Router hardware: Management interface
            if (currentType.Contains("Router") && (ports.Contains("80/http") || ports.Contains("443/https")))
                return "Network Infrastructure (Gateway)";

            return currentType;
        }
    }
}