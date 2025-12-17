using System;
using System.Diagnostics;

namespace HomeNetworkGuardian.Services
{
    /// <summary>
    /// Managed execution of the external Nmap process.
    /// Handles process lifecycle, resource cleanup, and timeout enforcement.
    /// </summary>
    public static class NmapProcessRunner
    {
        // Increased timeout to 300s (5 minutes) to support heavy service versioning (-sV)
        private const int DefaultTimeoutMs = 300000;

        /// <summary>
        /// Executes an Nmap command and waits for completion or timeout.
        /// </summary>
        /// <param name="arguments">CLI arguments for Nmap.</param>
        /// <param name="logIdentifier">A string for logging purposes (e.g., filename or IP).</param>
        /// <returns>True if the process completed successfully with ExitCode 0.</returns>
        public static bool ExecuteNmapProcess(string arguments, string logIdentifier)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "nmap",
                Arguments = arguments,
                RedirectStandardOutput = true, // Prevent output from flooding the console
                RedirectStandardError = true,  // Capture errors for debugging
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (Process process = new Process { StartInfo = psi })
                {
                    Debug.WriteLine($"[NmapRunner] Starting scan for: {logIdentifier}");

                    if (!process.Start())
                    {
                        Debug.WriteLine("[NmapRunner Error] Failed to start process.");
                        return false;
                    }

                    // Enforce the timeout. WaitForExit returns false if the timeout is reached.
                    bool completed = process.WaitForExit(DefaultTimeoutMs);

                    if (!completed)
                    {
                        HandleTimeout(process, logIdentifier);
                        return false;
                    }

                    if (process.ExitCode != 0)
                    {
                        string error = process.StandardError.ReadToEnd();
                        Debug.WriteLine($"[NmapRunner Error] Nmap exited with code {process.ExitCode}. Message: {error}");
                        return false;
                    }

                    Debug.WriteLine($"[NmapRunner] Scan completed successfully for: {logIdentifier}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NmapRunner Exception] Critical error executing Nmap: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Safely terminates an Nmap process that has exceeded its allowed execution time.
        /// </summary>
        private static void HandleTimeout(Process process, string logIdentifier)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    // Ensure resources are released immediately
                    process.WaitForExit();
                }
                Debug.WriteLine($"[NmapRunner Timeout] Process for {logIdentifier} exceeded {DefaultTimeoutMs / 1000}s and was terminated.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NmapRunner Error] Failed to kill timed-out process: {ex.Message}");
            }
        }
    }
}