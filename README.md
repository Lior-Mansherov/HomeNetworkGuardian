# Home Network Guardian

A professional C#/.NET application for automated network discovery, device classification, and service fingerprinting.

## Key Technical Features
* **Two-Phase Scan Architecture:** Implemented a high-speed ARP/Ping discovery phase followed by a deep Nmap-based service inspection.
* **Smart Device Classification:** Developed a heuristic engine to identify IoT devices, cameras, and workstations using OUI databases and port analysis.
* **Asynchronous Core:** Built with `async/await` patterns to ensure a responsive UI during heavy network processing.
* **Optimized Data Structures:** Used Dictionaries for $O(1)$ vendor lookups and LINQ-to-XML for efficient report parsing.

## Tech Stack
* **Language:** C# / .NET 8
* **Frontend:** WPF (XAML)
* **Backend Tools:** Nmap Integration
* **Data Management:** JSON-based local databases

## Getting Started
1. **Prerequisites:** Ensure [Nmap](https://nmap.org/download.html) is installed and added to your system's PATH.
2. **Setup:** Clone the repository and open the `.sln` file in Visual Studio.
3. **Run:** Build and run the project. The app will automatically detect your local subnet and start the scan.

## Future Roadmap
The project is functional, with planned enhancements including:
* **Advanced Heuristics:** Implementing a scoring system for suspicious device activity based on unconventional port combinations.
* **Network Graph Visualization:** Adding a visual topology map to display device connections.
* **CVE Integration:** Automatically cross-referencing identified service versions with the NVD (National Vulnerability Database).

## License
This project is for educational purposes as part of a professional software development portfolio.
