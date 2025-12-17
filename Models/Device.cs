
namespace HomeNetworkGuardian.Models
{
    public class Device
    {
        public string IP { get; set; }
        public string MAC { get; set; }
        public string Vendor { get; set; }
        public bool IsSuspicious { get; set; }
        public string OpenPorts { get; set; } = "N/A";
        public string DeviceType { get; set; }
        public int RiskScore { get; set; }
        public string OS { get; set; } = "N/A";
    }
}
