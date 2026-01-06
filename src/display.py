"""
Enhanced Console Display Module
Uses the Rich library for beautiful terminal output.

Install Rich: pip install rich
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict


console = Console()


class NetworkDisplay:
    """
    Enhanced display manager using Rich library.
    """
    
    def __init__(self):
        """Initialize the display manager."""
        self.console = Console()
        self.alerts = []
        self.max_alerts = 10
    
    def show_header(self, title: str = "NETWORK TRAFFIC ANALYZER"):
        """
        Display a styled header.
        
        Args:
            title: Header title text
        """
        self.console.print()
        self.console.print(
            Panel(
                f"[bold cyan]{title}[/bold cyan]\n"
                f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
                border_style="cyan",
                box=box.DOUBLE
            )
        )
        self.console.print()
    
    def show_connections_table(self, connections: List[Dict], 
                               show_location: bool = False):
        """
        Display active connections in a formatted table.
        
        Args:
            connections: List of connection dictionaries
            show_location: Whether to show geolocation data
        """
        if not connections:
            self.console.print("[yellow]No active connections found.[/yellow]")
            return
        
        # Create table
        table = Table(
            title=f"Active Connections ({len(connections)} total)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        
        # Add columns
        table.add_column("PID", style="cyan", justify="right", width=8)
        table.add_column("Process", style="green", width=20)
        table.add_column("Type", style="blue", width=4)
        table.add_column("Local Address", style="yellow", width=22)
        table.add_column("Remote Address", style="yellow", width=22)
        
        if show_location:
            table.add_column("Location", style="magenta", width=25)
        
        # Add rows
        for conn in connections:
            pid = str(conn.get('pid', 'N/A'))
            process = self._truncate(conn.get('process_name', 'Unknown'), 18)
            conn_type = conn.get('type', 'TCP')
            local = conn.get('local_address', 'N/A')
            remote = conn.get('remote_address', 'N/A')
            
            row = [pid, process, conn_type, local, remote]
            
            if show_location:
                location = conn.get('location', 'Unknown')
                row.append(self._truncate(location, 23))
            
            table.add_row(*row)
        
        self.console.print(table)
    
    def show_process_summary(self, connections: List[Dict]):
        """
        Display connections grouped by process.
        
        Args:
            connections: List of connection dictionaries
        """
        # Group by process
        grouped = defaultdict(list)
        for conn in connections:
            grouped[conn.get('process_name', 'Unknown')].append(conn)
        
        # Create table
        table = Table(
            title="Connections by Process",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        
        table.add_column("Process", style="green", width=25)
        table.add_column("Connections", style="cyan", justify="right", width=12)
        table.add_column("Remote IPs", style="yellow", justify="right", width=12)
        
        # Add rows
        for process, conns in sorted(grouped.items(), 
                                     key=lambda x: len(x[1]), 
                                     reverse=True):
            conn_count = len(conns)
            
            # Count unique remote IPs
            remote_ips = set()
            for conn in conns:
                remote = conn.get('remote_address', '')
                if ':' in remote:
                    ip = remote.split(':')[0]
                    remote_ips.add(ip)
            
            table.add_row(
                self._truncate(process, 23),
                str(conn_count),
                str(len(remote_ips))
            )
        
        self.console.print(table)
    
    def show_bandwidth_stats(self, bandwidth_data: Dict):
        """
        Display bandwidth statistics.
        
        Args:
            bandwidth_data: Dictionary with bandwidth metrics
        """
        table = Table(
            title="Bandwidth Statistics",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green"
        )
        
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Download", style="green", justify="right", width=15)
        table.add_column("Upload", style="yellow", justify="right", width=15)
        
        # Current rates
        table.add_row(
            "Current Rate",
            bandwidth_data.get('download_formatted', '0 B/s'),
            bandwidth_data.get('upload_formatted', '0 B/s')
        )
        
        # Total transferred
        table.add_row(
            "Total Transferred",
            bandwidth_data.get('total_recv_formatted', '0 B'),
            bandwidth_data.get('total_sent_formatted', '0 B')
        )
        
        self.console.print(table)
    
    def show_alerts(self, alerts: List[Dict]):
        """
        Display security alerts.
        
        Args:
            alerts: List of alert dictionaries
        """
        if not alerts:
            return
        
        # Keep only recent alerts
        self.alerts.extend(alerts)
        self.alerts = self.alerts[-self.max_alerts:]
        
        table = Table(
            title="🚨 Security Alerts",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold red"
        )
        
        table.add_column("Time", style="dim", width=10)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Description", style="white", width=50)
        
        for alert in self.alerts:
            timestamp = alert.get('timestamp', datetime.now())
            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime('%H:%M:%S')
            else:
                time_str = str(timestamp)
            
            alert_type = alert.get('type', 'Unknown')
            description = alert.get('description', 'No description')
            
            # Color code by severity
            severity = alert.get('severity', 'medium')
            if severity == 'high':
                alert_type = f"[bold red]{alert_type}[/bold red]"
            elif severity == 'medium':
                alert_type = f"[yellow]{alert_type}[/yellow]"
            else:
                alert_type = f"[cyan]{alert_type}[/cyan]"
            
            table.add_row(
                time_str,
                alert_type,
                self._truncate(description, 48)
            )
        
        self.console.print(table)
    
    def show_top_connections(self, connections: List[Dict], limit: int = 10):
        """
        Display top connections by remote IP frequency.
        
        Args:
            connections: List of connection dictionaries
            limit: Maximum number to show
        """
        # Count connections per remote IP
        ip_counts = defaultdict(lambda: {'count': 0, 'process': set()})
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            if ':' in remote:
                ip = remote.split(':')[0]
                ip_counts[ip]['count'] += 1
                ip_counts[ip]['process'].add(conn.get('process_name', 'Unknown'))
        
        # Sort by count
        sorted_ips = sorted(ip_counts.items(), 
                           key=lambda x: x[1]['count'], 
                           reverse=True)[:limit]
        
        if not sorted_ips:
            return
        
        table = Table(
            title=f"Top {limit} Remote IPs",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow"
        )
        
        table.add_column("Rank", style="dim", justify="right", width=6)
        table.add_column("IP Address", style="cyan", width=18)
        table.add_column("Connections", style="green", justify="right", width=12)
        table.add_column("Processes", style="magenta", width=30)
        
        for rank, (ip, data) in enumerate(sorted_ips, 1):
            processes = ', '.join(list(data['process'])[:3])
            if len(data['process']) > 3:
                processes += '...'
            
            table.add_row(
                str(rank),
                ip,
                str(data['count']),
                self._truncate(processes, 28)
            )
        
        self.console.print(table)
    
    def show_status_panel(self, stats: Dict):
        """
        Display a status panel with key metrics.
        
        Args:
            stats: Dictionary with various statistics
        """
        content = Text()
        content.append("📊 System Status\n\n", style="bold cyan")
        content.append(f"Active Connections: ", style="yellow")
        content.append(f"{stats.get('connections', 0)}\n", style="bold green")
        content.append(f"Active Processes: ", style="yellow")
        content.append(f"{stats.get('processes', 0)}\n", style="bold green")
        content.append(f"Download Rate: ", style="yellow")
        content.append(f"{stats.get('download_rate', '0 B/s')}\n", style="bold green")
        content.append(f"Upload Rate: ", style="yellow")
        content.append(f"{stats.get('upload_rate', '0 B/s')}\n", style="bold green")
        
        panel = Panel(
            content,
            border_style="cyan",
            box=box.ROUNDED
        )
        
        self.console.print(panel)
    
    def show_progress(self, description: str):
        """
        Show a progress spinner.
        
        Args:
            description: Description text
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            progress.add_task(description, total=None)
    
    def clear_screen(self):
        """Clear the console screen."""
        self.console.clear()
    
    def print_success(self, message: str):
        """Print a success message."""
        self.console.print(f"[bold green]✓[/bold green] {message}")
    
    def print_error(self, message: str):
        """Print an error message."""
        self.console.print(f"[bold red]✗[/bold red] {message}")
    
    def print_warning(self, message: str):
        """Print a warning message."""
        self.console.print(f"[bold yellow]⚠[/bold yellow] {message}")
    
    def print_info(self, message: str):
        """Print an info message."""
        self.console.print(f"[bold cyan]ℹ[/bold cyan] {message}")
    
    def _truncate(self, text: str, max_length: int) -> str:
        """
        Truncate text to maximum length.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."


# Example usage and testing
if __name__ == "__main__":
    display = NetworkDisplay()
    
    # Test header
    display.show_header()
    
    # Test connections table
    sample_connections = [
        {
            'pid': 1234,
            'process_name': 'chrome.exe',
            'type': 'TCP',
            'local_address': '192.168.1.10:54321',
            'remote_address': '142.250.185.46:443',
            'location': 'Mountain View, US'
        },
        {
            'pid': 5678,
            'process_name': 'firefox.exe',
            'type': 'TCP',
            'local_address': '192.168.1.10:54322',
            'remote_address': '1.1.1.1:443',
            'location': 'San Francisco, US'
        }
    ]
    
    display.show_connections_table(sample_connections, show_location=True)
    console.print()
    
    # Test bandwidth stats
    bandwidth_data = {
        'download_formatted': '2.5 MB/s',
        'upload_formatted': '350 KB/s',
        'total_recv_formatted': '1.2 GB',
        'total_sent_formatted': '450 MB'
    }
    
    display.show_bandwidth_stats(bandwidth_data)
    console.print()
    
    # Test alerts
    sample_alerts = [
        {
            'timestamp': datetime.now(),
            'type': 'Unusual Port',
            'severity': 'high',
            'description': 'Connection to port 4444 detected from chrome.exe'
        },
        {
            'timestamp': datetime.now(),
            'type': 'High Connection Count',
            'severity': 'medium',
            'description': 'Process svchost.exe has 150 active connections'
        }
    ]
    
    display.show_alerts(sample_alerts)
    console.print()
    
    # Test process summary
    display.show_process_summary(sample_connections)
    console.print()
    
    # Test status panel
    stats = {
        'connections': 42,
        'processes': 15,
        'download_rate': '2.5 MB/s',
        'upload_rate': '350 KB/s'
    }
    
    display.show_status_panel(stats)