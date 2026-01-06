# 🌐 Real-Time Network Traffic Analyzer

A powerful, linux network monitoring tool that provides deep visibility into your system's network activity with geographic insights, anomaly detection, and enhanced  visualizations.

## ✨ Features

- 🔍 **Real-Time Monitoring** - Track active TCP/UDP connections with process-level detail
- 🌍 **Geolocation** - Map connections to countries, cities, and ISPs worldwide
- 🚨 **Anomaly Detection** - Identify suspicious ports, processes, and connection patterns
- 📊 **Bandwidth Tracking** - Monitor upload/download rates in real-time
- 🗺️ **Interactive Maps** - Generate beautiful HTML visualizations of global connections
- 🎨 **Rich Terminal UI** - Clean, colorful interface powered by Rich library
- 💾 **Export Reports** - Save connection data with full geolocation details

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Reyansh00/Real-Time-Network-Traffic-Analyzer.git
cd Real-Time-Network-Traffic-Analyzer/

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt


# Run with sudo/admin privileges (required for network access)
sudo venv/bin/python main.py
```

### Basic Usage

```bash
# Interactive menu
sudo venv/bin/python main.py

# Quick scan with geolocation
sudo venv/bin/python main.py -s

# Continuous monitoring (refresh every 3 seconds)
sudo venv/bin/python main.py -c 3

# Full-featured enhanced mode
sudo venv/bin/python main.py --enhanced

# Export connections to file
sudo venv/bin/python main.py -e report.txt
```

## 📸 Screenshots

**Live Monitoring Dashboard**
```
╭──────────────────────────────────────────────╮
│  🌐 NETWORK TRAFFIC ANALYZER             
│  2026-01-06 14:30:45                         │
╰──────────────────────────────────────────────╯

📊 OVERVIEW
  Active Connections: 42
  Active Processes: 15
  Download Rate: 2.5 MB/s
  Upload Rate: 350 KB/s
```

**Geographic Analysis**
- World map showing connection endpoints
- Country-wise distribution heatmaps
- ISP and organization tracking

## 🛠️ Key Components

| Module | Description |
|--------|-------------|
| `monitor.py` | Core connection tracking engine |
| `resolver.py` | DNS resolution & IP geolocation |
| `bandwidth.py` | Network bandwidth monitoring |
| `anomaly.py` | Suspicious activity detection |
| `geo_analyser.py` | Geographic analysis & map generation |
| `display.py` | Rich terminal UI components |

## 🎯 Use Cases

- **Security Analysis** - Detect unauthorized connections and malware activity
- **Network Debugging** - Identify which apps are consuming bandwidth
- **Development** - Monitor API calls and service connections
- **System Administration** - Audit network usage across workstations
- **Education** - Learn about network protocols and system behavior

## 🔒 Security Features

- ✅ Detect connections to suspicious ports (4444, 31337, etc.)
- ✅ Flag processes running from unusual locations
- ✅ Identify high-risk country connections
- ✅ Alert on abnormal connection counts per process
- ✅ Track ISP changes and unexpected destinations

## 📋 Requirements

- Python 3.8+
- Administrator/sudo privileges (for network access)
- Dependencies: `psutil`, `requests`, `rich`

## 🌍 Geographic Data

Uses [ip-api.com](http://ip-api.com) for geolocation (45 requests/minute free tier). Data includes:
- Country, region, city
- ISP and organization
- Latitude/longitude coordinates
- Timezone information


## 📝 License

MIT License - feel free to use for personal or commercial projects.

## ⚠️ Disclaimer

This tool is for educational and legitimate network monitoring purposes only. Always obtain proper authorization before monitoring network traffic on systems you don't own.

## 👨‍💻 Author

**Reyansh**
- GitHub: [@Reyansh00](https://github.com/Reyansh00)

## 🙏 Acknowledgments

- Built with [psutil](https://github.com/giampaolo/psutil) for system monitoring
- UI powered by [Rich](https://github.com/Textualize/rich)
- Geolocation by [ip-api.com](http://ip-api.com)
- Development assisted by AI tools (e.g claude.ai,chatgpt) for brainstorming, debugging, and code refinement

---

⭐ **Star this repo if you find it useful!**
