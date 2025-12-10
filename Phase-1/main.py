"""
Network Connection Monitor - Enhanced Main Script
Monitors active network connections with bandwidth tracking, geolocation, and anomaly detection.
"""

import time
import sys
from datetime import datetime
from collections import defaultdict

# Import existing module
from src.monitor import get_active_connections

# Import new modules
try:
    from src.bandwidth import BandwidthTracker, format_bytes
    from src.resolver import IPResolver, extract_ip_from_address
    from src.display import NetworkDisplay
    ENHANCED_MODE = True
except ImportError as e:
    print(f"Warning: Could not import enhanced modules: {e}")
    print("Install requirements: pip install psutil requests rich")
    print("Falling back to basic mode...\n")
    ENHANCED_MODE = False


class AnomalyDetector:
    """Simple anomaly detection for suspicious network activity."""
    
    SUSPICIOUS_PORTS = {
        4444, 4445,      # Metasploit
        5555, 5556,      # Android Debug Bridge exploits
        6666, 6667, 6668, 6669,  # IRC botnets
        31337,           # Back Orifice
        12345,           # NetBus
        1337,            # Elite
        3389,            # RDP (can be suspicious if external)
    }
    
    def __init__(self, max_connections_per_process: int = 50):
        self.max_connections = max_connections_per_process
        self.alerts = []
    
    def analyze(self, connections: list) -> list:
        """Analyze connections for anomalies."""
        self.alerts = []
        self._check_suspicious_ports(connections)
        self._check_connection_count(connections)
        self._check_suspicious_processes(connections)
        return self.alerts
    
    def _check_suspicious_ports(self, connections: list):
        """Check for connections to suspicious ports."""
        for conn in connections:
            remote = conn.get('remote_address', '')
            if ':' in remote:
                try:
                    port = int(remote.split(':')[1])
                    if port in self.SUSPICIOUS_PORTS:
                        self.alerts.append({
                            'timestamp': datetime.now(),
                            'type': 'Suspicious Port',
                            'severity': 'high',
                            'description': f"{conn['process_name']} → {remote} (port {port})"
                        })
                except ValueError:
                    pass
    
    def _check_connection_count(self, connections: list):
        """Check for processes with unusually high connection counts."""
        process_counts = defaultdict(int)
        for conn in connections:
            process_counts[conn['process_name']] += 1
        
        for process, count in process_counts.items():
            if count > self.max_connections:
                self.alerts.append({
                    'timestamp': datetime.now(),
                    'type': 'High Connection Count',
                    'severity': 'medium',
                    'description': f"{process} has {count} connections (threshold: {self.max_connections})"
                })
    
    def _check_suspicious_processes(self, connections: list):
        """Check for processes running from suspicious locations."""
        suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'downloads']
        checked = set()
        
        for conn in connections:
            process = conn['process_name']
            if process in checked:
                continue
            checked.add(process)
            
            path = conn.get('process_path', '').lower()
            for suspicious in suspicious_paths:
                if suspicious in path:
                    self.alerts.append({
                        'timestamp': datetime.now(),
                        'type': 'Suspicious Process Path',
                        'severity': 'medium',
                        'description': f"{process} from {conn['process_path']}"
                    })
                    break


def enrich_connections(connections: list, resolver: IPResolver, limit: int = 25) -> list:
    """Add hostname and geolocation data to connections."""
    if len(connections) > limit:
        return connections  # Skip enrichment if too many connections
    
    for conn in connections:
        remote = conn.get('remote_address', '')
        if remote and remote != 'N/A':
            ip = extract_ip_from_address(remote)
            
            # Get hostname
            hostname = resolver.resolve_hostname(ip)
            conn['hostname'] = hostname if hostname != ip else ''
            
            # Get geolocation
            geo = resolver.get_geolocation(ip)
            if geo['status'] == 'success':
                conn['location'] = resolver.format_location(geo)
                conn['country'] = geo.get('country', 'Unknown')
                conn['isp'] = geo.get('isp', 'Unknown')
            elif geo['status'] == 'private':
                conn['location'] = 'Private Network'
                conn['country'] = 'Local'
                conn['isp'] = 'Private'
            else:
                conn['location'] = 'Unknown'
                conn['country'] = 'Unknown'
                conn['isp'] = 'Unknown'
    
    return connections


def enhanced_continuous_monitor(interval: int = 5, enable_geo: bool = True, 
                                enable_alerts: bool = True):
    """
    Enhanced continuous monitoring with all features.
    
    Args:
        interval: Refresh interval in seconds
        enable_geo: Enable geolocation lookups
        enable_alerts: Enable anomaly detection
    """
    if not ENHANCED_MODE:
        print("Enhanced mode not available. Install requirements: pip install psutil requests rich")
        return
    
    display = NetworkDisplay()
    bandwidth_tracker = BandwidthTracker()
    resolver = IPResolver() if enable_geo else None
    anomaly_detector = AnomalyDetector(max_connections_per_process=30) if enable_alerts else None
    
    display.print_info(f"Starting enhanced monitoring (refresh every {interval}s)")
    display.print_info(f"Geolocation: {'Enabled' if enable_geo else 'Disabled'}")
    display.print_info(f"Anomaly Detection: {'Enabled' if enable_alerts else 'Disabled'}")
    display.print_info("Press Ctrl+C to stop")
    print()
    time.sleep(2)
    
    try:
        while True:
            display.clear_screen()
            
            # Get connections
            connections = get_active_connections()
            
            # Enrich with geolocation if enabled
            if enable_geo and resolver:
                connections = enrich_connections(connections, resolver, limit=25)
            
            # Get bandwidth stats
            bandwidth_data = bandwidth_tracker.get_current_rates()
            
            # Run anomaly detection if enabled
            alerts = []
            if enable_alerts and anomaly_detector:
                alerts = anomaly_detector.analyze(connections)
            
            # Display header
            display.show_header("NETWORK TRAFFIC ANALYZER")
            
            # Status panel
            stats = {
                'connections': len(connections),
                'processes': len(set(c['process_name'] for c in connections)),
                'download_rate': bandwidth_data['download_formatted'],
                'upload_rate': bandwidth_data['upload_formatted']
            }
            display.show_status_panel(stats)
            print()
            
            # Bandwidth stats
            display.show_bandwidth_stats(bandwidth_data)
            print()
            
            # Alerts
            if alerts:
                display.show_alerts(alerts)
                print()
            
            # Process summary
            display.show_process_summary(connections)
            print()
            
            # Top connections
            if len(connections) > 5:
                display.show_top_connections(connections, limit=10)
                print()
            
            # Connections table
            show_location = enable_geo and len(connections) <= 25
            display.show_connections_table(connections, show_location=show_location)
            
            # Footer
            print()
            display.console.print(
                f"[dim]Last update: {datetime.now().strftime('%H:%M:%S')} | "
                f"Next refresh in {interval}s | Press Ctrl+C to stop[/dim]"
            )
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n")
        display.print_info("Monitoring stopped by user")
        
        # Show session statistics
        avg_down, avg_up = bandwidth_tracker.get_average_rates()
        peak_down, peak_up = bandwidth_tracker.get_peak_rates()
        
        print()
        display.console.print("[bold cyan]Session Statistics:[/bold cyan]")
        display.console.print(f"  Average Download: {format_bytes(avg_down)}/s")
        display.console.print(f"  Average Upload:   {format_bytes(avg_up)}/s")
        display.console.print(f"  Peak Download:    {format_bytes(peak_down)}/s")
        display.console.print(f"  Peak Upload:      {format_bytes(peak_up)}/s")
        display.console.print(f"  Total Received:   {bandwidth_data['total_recv_formatted']}")
        display.console.print(f"  Total Sent:       {bandwidth_data['total_sent_formatted']}")
        print()

def quick_domain_scan():
    """Quick scan showing just domains and processes."""
    if not ENHANCED_MODE:
        print("Enhanced mode required for domain resolution")
        return
    
    display = NetworkDisplay()
    resolver = IPResolver()
    
    print("\n🔍 Scanning connections and resolving domains...")
    connections = get_active_connections()
    
    # Resolve hostnames for all connections
    print(f"Found {len(connections)} connections, resolving hostnames...\n")
    
    for conn in connections:
        remote = conn.get('remote_address', '')
        if remote and remote != 'N/A' and ':' in remote:
            ip = remote.split(':')[0]
            hostname = resolver.resolve_hostname(ip)
            conn['hostname'] = hostname
            
            # Also get ISP/Org for context
            geo = resolver.get_geolocation(ip)
            if geo['status'] == 'success':
                conn['isp'] = geo.get('isp', 'Unknown')
                conn['country'] = geo.get('country', 'Unknown')
    
    # Create a clean display table
    from rich.table import Table
    from rich import box
    
    table = Table(
        title="🌐 Active Network Connections",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Process", style="green", width=18)
    table.add_column("Domain/Hostname", style="bright_yellow", width=35)
    table.add_column("IP:Port", style="cyan", width=22)
    table.add_column("Country", style="magenta", width=15)
    
    for conn in connections:
        process = conn.get('process_name', 'Unknown')[:16]
        remote = conn.get('remote_address', 'N/A')
        hostname = conn.get('hostname', '')
        country = conn.get('country', '')
        
        # Extract domain from hostname
        if hostname and hostname != remote.split(':')[0]:
            parts = hostname.split('.')
            if len(parts) > 2:
                domain = f"{parts[-2]}.{parts[-1]}"
            else:
                domain = hostname
        else:
            domain = remote.split(':')[0] if ':' in remote else remote
        
        table.add_row(
            process,
            domain[:33],
            remote,
            country
        )
    
    display.console.print(table)
    print(f"\n✅ Scan complete: {len(connections)} connections\n")

def enhanced_single_scan(enable_geo: bool = True):
    """Enhanced single scan with all features."""
    if not ENHANCED_MODE:
        print("Enhanced mode not available. Install requirements: pip install psutil requests rich")
        return
    
    display = NetworkDisplay()
    bandwidth_tracker = BandwidthTracker()
    resolver = IPResolver() if enable_geo else None
    anomaly_detector = AnomalyDetector()
    
    display.print_info("Performing enhanced network scan...")
    print()
    
    # Get connections
    connections = get_active_connections()
    
    # Enrich with geolocation
    if enable_geo and resolver:
        display.print_info("Resolving IP addresses and locations...")
        connections = enrich_connections(connections, resolver, limit=30)
        print()
    
    # Get bandwidth (need two samples)
    bandwidth_tracker.get_current_rates()
    time.sleep(1)
    bandwidth_data = bandwidth_tracker.get_current_rates()
    
    # Run anomaly detection
    alerts = anomaly_detector.analyze(connections)
    
    # Display results
    display.show_header("NETWORK SCAN RESULTS")
    
    stats = {
        'connections': len(connections),
        'processes': len(set(c['process_name'] for c in connections)),
        'download_rate': bandwidth_data['download_formatted'],
        'upload_rate': bandwidth_data['upload_formatted']
    }
    display.show_status_panel(stats)
    print()
    
    if alerts:
        display.show_alerts(alerts)
        print()
    
    display.show_process_summary(connections)
    print()
    
    if len(connections) > 5:
        display.show_top_connections(connections, limit=10)
        print()
    
    show_location = enable_geo and len(connections) <= 30
    display.show_connections_table(connections, show_location=show_location)
    print()
    
    display.print_success(f"Scan complete: {len(connections)} active connections found")


def basic_continuous_monitor(interval: int = 5):
    """Basic continuous monitoring (fallback mode)."""
    print(f"\n🔄 Starting basic monitoring (refresh every {interval}s)")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            print("\033[2J\033[H")  # Clear screen
            print("=" * 100)
            print(f"  ACTIVE NETWORK CONNECTIONS - {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 100)
            
            connections = get_active_connections()
            
            if not connections:
                print("\n  No active connections found.\n")
            else:
                print(f"\n  Total Connections: {len(connections)}\n")
                
                # Group by process
                grouped = defaultdict(list)
                for conn in connections:
                    grouped[conn['process_name']].append(conn)
                
                for process_name, conns in sorted(grouped.items()):
                    print(f"\n  📦 {process_name} ({len(conns)} connection{'s' if len(conns) > 1 else ''})")
                    print("  " + "-" * 96)
                    
                    for conn in conns:
                        pid_str = str(conn['pid']).ljust(8)
                        print(f"    PID: {pid_str} | {conn['type']:<4} | {conn['local_address']:<22} → {conn['remote_address']}")
            
            print("\n" + "=" * 100 + "\n")
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✋ Monitoring stopped by user.\n")


def basic_single_scan():
    """Basic single scan (fallback mode)."""
    print("\n🔍 Scanning for active connections...\n")
    connections = get_active_connections()
    
    print("=" * 100)
    print(f"  ACTIVE NETWORK CONNECTIONS - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not connections:
        print("\n  No active connections found.\n")
    else:
        print(f"\n  Total Connections: {len(connections)}\n")
        
        for i, conn in enumerate(connections, 1):
            print(f"\n  Connection #{i}")
            print(f"    Type:           {conn['type']}")
            print(f"    Status:         {conn['status']}")
            print(f"    Local:          {conn['local_address']}")
            print(f"    Remote:         {conn['remote_address']}")
            print(f"    PID:            {conn['pid']}")
            print(f"    Process:        {conn['process_name']}")
            print(f"    Path:           {conn['process_path']}")
            print("  " + "-" * 96)
    
    print("\n" + "=" * 100 + "\n")


def export_to_file(connections, filename='connections.txt'):
    """Export connections to a text file."""
    try:
        with open(filename, 'w') as f:
            f.write(f"Network Connections Report - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")
            
            for i, conn in enumerate(connections, 1):
                f.write(f"Connection #{i}\n")
                f.write(f"  Type:           {conn['type']}\n")
                f.write(f"  Status:         {conn['status']}\n")
                f.write(f"  Local:          {conn['local_address']}\n")
                f.write(f"  Remote:         {conn['remote_address']}\n")
                f.write(f"  PID:            {conn['pid']}\n")
                f.write(f"  Process:        {conn['process_name']}\n")
                f.write(f"  Path:           {conn['process_path']}\n")
                
                if 'hostname' in conn and conn['hostname']:
                    f.write(f"  Hostname:       {conn['hostname']}\n")
                if 'location' in conn:
                    f.write(f"  Location:       {conn['location']}\n")
                if 'isp' in conn:
                    f.write(f"  ISP:            {conn['isp']}\n")
                
                f.write("-" * 100 + "\n\n")
        
        print(f"✅ Exported {len(connections)} connections to '{filename}'")
    except Exception as e:
        print(f"❌ Error exporting to file: {e}")


def show_menu():
    """Display the main menu."""
    mode = "ENHANCED" if ENHANCED_MODE else "BASIC"
    
    print("\n" + "=" * 70)
    print(f"  NETWORK CONNECTION MONITOR ({mode} MODE)")
    print("=" * 70)
    
    if ENHANCED_MODE:
        print("\n  📊 Enhanced Scans (with bandwidth, geolocation, alerts)")
        print("    1. Quick scan (with geolocation)")
        print("    2. Quick scan (without geolocation)")
        print("    3. Continuous monitoring (full features)")
        print("    4. Continuous monitoring (no geolocation)")
        print("    5. Continuous monitoring (basic - no alerts/geo)")
        print("\n  💾 Export & Analysis")
        print("    6. Scan and export to file")
        print("    7. Export with geolocation data")
    else:
        print("\n  📊 Basic Scans")
        print("    1. Single scan")
        print("    2. Continuous monitoring")
        print("    3. Scan and export to file")
    
    print("\n  🚪 Exit")
    print("    0. Exit")
    print("\n" + "=" * 70)


def main():
    """Main entry point."""
    # Check for command-line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg in ['--help', '-h']:
            print("\n" + "=" * 70)
            print("  NETWORK CONNECTION MONITOR - Help")
            print("=" * 70)
            print("\nUsage:")
            print("  python main.py                    # Interactive menu")
            print("  python main.py -s                 # Single scan")
            print("  python main.py -c [interval]      # Continuous monitoring")
            print("  python main.py -e [filename]      # Export to file")
            print("  python main.py --enhanced         # Enhanced scan with all features")
            print("  python main.py --basic            # Basic scan (no geo/alerts)")
            print("\nExamples:")
            print("  python main.py -c 3               # Monitor every 3 seconds")
            print("  python main.py -e report.txt      # Export to report.txt")
            print("  python main.py --enhanced         # Full featured continuous monitor")
            print()
            return
        
        elif arg in ['--enhanced', '-eh'] and ENHANCED_MODE:
            enhanced_continuous_monitor(interval=5, enable_geo=True, enable_alerts=True)
            return
        
        elif arg in ['--basic', '-b']:
            if ENHANCED_MODE:
                enhanced_continuous_monitor(interval=5, enable_geo=False, enable_alerts=False)
            else:
                basic_continuous_monitor(interval=5)
            return
        
        elif arg in ['--continuous', '-c']:
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            if ENHANCED_MODE:
                enhanced_continuous_monitor(interval=interval)
            else:
                basic_continuous_monitor(interval=interval)
            return
        
        elif arg in ['--scan', '-s']:
            if ENHANCED_MODE:
                enhanced_single_scan(enable_geo=True)
            else:
                basic_single_scan()
            return
        
        elif arg in ['--export', '-e']:
            connections = get_active_connections()
            if ENHANCED_MODE:
                resolver = IPResolver()
                connections = enrich_connections(connections, resolver, limit=50)
            filename = sys.argv[2] if len(sys.argv) > 2 else 'connections.txt'
            export_to_file(connections, filename)
            return
        
        else:
            print(f"Unknown option: {arg}")
            print("Use --help for usage information")
            return
    
    # Interactive menu mode
    while True:
        show_menu()
        choice = input("\n  Enter your choice: ").strip()
        
        if choice == '0':
            print("\n  👋 Goodbye!\n")
            break
        
        elif choice == '1':
            if ENHANCED_MODE:
                enhanced_single_scan(enable_geo=True)
            else:
                basic_single_scan()
            input("\n  Press Enter to continue...")
        
        elif choice == '2':
            if ENHANCED_MODE:
                enhanced_single_scan(enable_geo=False)
            else:
                interval = input("\n  Enter refresh interval in seconds (default 5): ").strip()
                interval = int(interval) if interval.isdigit() else 5
                basic_continuous_monitor(interval=interval)
            input("\n  Press Enter to continue...")
        
        elif choice == '3':
            if ENHANCED_MODE:
                interval = input("\n  Enter refresh interval in seconds (default 5): ").strip()
                interval = int(interval) if interval.isdigit() else 5
                enhanced_continuous_monitor(interval=interval, enable_geo=True, enable_alerts=True)
            else:
                connections = get_active_connections()
                filename = input("\n  Enter filename (default 'connections.txt'): ").strip()
                filename = filename if filename else 'connections.txt'
                export_to_file(connections, filename)
            input("\n  Press Enter to continue...")
        
        elif choice == '4' and ENHANCED_MODE:
            interval = input("\n  Enter refresh interval in seconds (default 5): ").strip()
            interval = int(interval) if interval.isdigit() else 5
            enhanced_continuous_monitor(interval=interval, enable_geo=False, enable_alerts=True)
            input("\n  Press Enter to continue...")
        
        elif choice == '5' and ENHANCED_MODE:
            interval = input("\n  Enter refresh interval in seconds (default 5): ").strip()
            interval = int(interval) if interval.isdigit() else 5
            enhanced_continuous_monitor(interval=interval, enable_geo=False, enable_alerts=False)
            input("\n  Press Enter to continue...")
        
        elif choice == '6' and ENHANCED_MODE:
            connections = get_active_connections()
            filename = input("\n  Enter filename (default 'connections.txt'): ").strip()
            filename = filename if filename else 'connections.txt'
            export_to_file(connections, filename)
            input("\n  Press Enter to continue...")
        
        elif choice == '7' and ENHANCED_MODE:
            connections = get_active_connections()
            print("\n  Resolving IP addresses and locations...")
            resolver = IPResolver()
            connections = enrich_connections(connections, resolver, limit=50)
            filename = input("\n  Enter filename (default 'connections_geo.txt'): ").strip()
            filename = filename if filename else 'connections_geo.txt'
            export_to_file(connections, filename)
            input("\n  Press Enter to continue...")
        
        else:
            print("\n  ❌ Invalid choice. Please try again.")
            input("\n  Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  👋 Exiting...\n")
        sys.exit(0)