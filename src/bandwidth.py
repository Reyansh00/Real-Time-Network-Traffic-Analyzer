"""
Bandwidth Tracking Module
Monitors network bandwidth usage over time.
"""

import psutil
import time
from typing import Dict, Tuple, Optional
from collections import deque


class BandwidthTracker:
    """
    Tracks network bandwidth usage by taking periodic snapshots
    and calculating the rate of data transfer.
    """
    
    def __init__(self, history_size: int = 60):
        """
        Initialize the bandwidth tracker.
        
        Args:
            history_size: Number of historical samples to keep (default 60)
        """
        self.history_size = history_size
        self.history_down = deque(maxlen=history_size)
        self.history_up = deque(maxlen=history_size)
        self.last_snapshot = None
        self.last_timestamp = None
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0
        
    def take_snapshot(self) -> Dict:
        """
        Take a snapshot of current network I/O counters.
        
        Returns:
            Dictionary with current network stats
        """
        try:
            stats = psutil.net_io_counters()
            current_time = time.time()
            
            snapshot = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout,
                'timestamp': current_time
            }
            
            return snapshot
        except Exception as e:
            print(f"Error taking snapshot: {e}")
            return None
    
    def calculate_rates(self, current_snapshot: Dict) -> Tuple[float, float]:
        """
        Calculate upload and download rates since last snapshot.
        
        Args:
            current_snapshot: Current network stats
            
        Returns:
            Tuple of (download_rate_bps, upload_rate_bps) in bytes per second
        """
        if self.last_snapshot is None:
            self.last_snapshot = current_snapshot
            self.last_timestamp = current_snapshot['timestamp']
            return (0.0, 0.0)
        
        # Calculate time delta
        time_delta = current_snapshot['timestamp'] - self.last_timestamp
        
        if time_delta == 0:
            return (0.0, 0.0)
        
        # Calculate byte deltas
        bytes_recv_delta = current_snapshot['bytes_recv'] - self.last_snapshot['bytes_recv']
        bytes_sent_delta = current_snapshot['bytes_sent'] - self.last_snapshot['bytes_sent']
        
        # Calculate rates (bytes per second)
        download_rate = bytes_recv_delta / time_delta
        upload_rate = bytes_sent_delta / time_delta
        
        # Update totals
        self.total_bytes_recv += bytes_recv_delta
        self.total_bytes_sent += bytes_sent_delta
        
        # Store in history
        self.history_down.append(download_rate)
        self.history_up.append(upload_rate)
        
        # Update last snapshot
        self.last_snapshot = current_snapshot
        self.last_timestamp = current_snapshot['timestamp']
        
        return (download_rate, upload_rate)
    
    def get_current_rates(self) -> Dict:
        """
        Get current bandwidth rates.
        
        Returns:
            Dictionary with download/upload rates and formatted strings
        """
        snapshot = self.take_snapshot()
        
        if snapshot is None:
            return {
                'download_bps': 0.0,
                'upload_bps': 0.0,
                'download_formatted': '0 B/s',
                'upload_formatted': '0 B/s',
                'total_recv': 0,
                'total_sent': 0
            }
        
        download_rate, upload_rate = self.calculate_rates(snapshot)
        
        return {
            'download_bps': download_rate,
            'upload_bps': upload_rate,
            'download_formatted': format_bytes(download_rate) + '/s',
            'upload_formatted': format_bytes(upload_rate) + '/s',
            'total_recv': self.total_bytes_recv,
            'total_sent': self.total_bytes_sent,
            'total_recv_formatted': format_bytes(self.total_bytes_recv),
            'total_sent_formatted': format_bytes(self.total_bytes_sent)
        }
    
    def get_average_rates(self, seconds: Optional[int] = None) -> Tuple[float, float]:
        """
        Get average rates over a time period.
        
        Args:
            seconds: Number of seconds to average (None = all history)
            
        Returns:
            Tuple of (avg_download_bps, avg_upload_bps)
        """
        if seconds is None:
            samples_down = list(self.history_down)
            samples_up = list(self.history_up)
        else:
            samples_down = list(self.history_down)[-seconds:]
            samples_up = list(self.history_up)[-seconds:]
        
        if not samples_down or not samples_up:
            return (0.0, 0.0)
        
        avg_down = sum(samples_down) / len(samples_down)
        avg_up = sum(samples_up) / len(samples_up)
        
        return (avg_down, avg_up)
    
    def get_peak_rates(self) -> Tuple[float, float]:
        """
        Get peak download and upload rates from history.
        
        Returns:
            Tuple of (peak_download_bps, peak_upload_bps)
        """
        if not self.history_down or not self.history_up:
            return (0.0, 0.0)
        
        peak_down = max(self.history_down)
        peak_up = max(self.history_up)
        
        return (peak_down, peak_up)
    
    def get_interface_stats(self) -> Dict:
        """
        Get per-interface network statistics.
        
        Returns:
            Dictionary of interface names to their stats
        """
        try:
            stats = psutil.net_io_counters(pernic=True)
            interface_data = {}
            
            for interface, iostat in stats.items():
                interface_data[interface] = {
                    'bytes_sent': iostat.bytes_sent,
                    'bytes_recv': iostat.bytes_recv,
                    'packets_sent': iostat.packets_sent,
                    'packets_recv': iostat.packets_recv,
                    'bytes_sent_formatted': format_bytes(iostat.bytes_sent),
                    'bytes_recv_formatted': format_bytes(iostat.bytes_recv)
                }
            
            return interface_data
        except Exception as e:
            print(f"Error getting interface stats: {e}")
            return {}


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes into human-readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB", "500 KB")
    """
    if bytes_value < 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    
    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(bytes_value)} {units[unit_index]}"
    else:
        return f"{bytes_value:.2f} {units[unit_index]}"


# Example usage and testing
if __name__ == "__main__":
    print("Testing Bandwidth Tracker...\n")
    tracker = BandwidthTracker()
    
    print("Monitoring bandwidth for 10 seconds...\n")
    
    for i in range(10):
        rates = tracker.get_current_rates()
        
        print(f"Sample {i+1}:")
        print(f"  Download: {rates['download_formatted']}")
        print(f"  Upload:   {rates['upload_formatted']}")
        print(f"  Total RX: {rates['total_recv_formatted']}")
        print(f"  Total TX: {rates['total_sent_formatted']}")
        print()
        
        time.sleep(1)
    
    # Show averages
    avg_down, avg_up = tracker.get_average_rates()
    peak_down, peak_up = tracker.get_peak_rates()
    
    print("Statistics:")
    print(f"  Average Download: {format_bytes(avg_down)}/s")
    print(f"  Average Upload:   {format_bytes(avg_up)}/s")
    print(f"  Peak Download:    {format_bytes(peak_down)}/s")
    print(f"  Peak Upload:      {format_bytes(peak_up)}/s")