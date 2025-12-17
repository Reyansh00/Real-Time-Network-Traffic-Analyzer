"""
Enhanced Anomaly Detection Module
Detects suspicious network activity with configurable rules
"""

from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Set


class AnomalyDetector:
    """Enhanced anomaly detection for suspicious network activity."""
    
    # Standard ports that are typically safe
    STANDARD_PORTS = {
        20, 21,      # FTP
        22,          # SSH
        23,          # Telnet
        25,          # SMTP
        53,          # DNS
        80,          # HTTP
        110,         # POP3
        143,         # IMAP
        443,         # HTTPS
        465,         # SMTPS
        587,         # SMTP (submission)
        993,         # IMAPS
        995,         # POP3S
        3306,        # MySQL
        5432,        # PostgreSQL
        6379,        # Redis
        8080,        # HTTP Alt
        8443,        # HTTPS Alt
    }
    
    # Known suspicious/malicious ports
    SUSPICIOUS_PORTS = {
        4444, 4445,      # Metasploit
        5555, 5556,      # Android Debug Bridge exploits
        6666, 6667, 6668, 6669,  # IRC botnets
        31337,           # Back Orifice
        12345,           # NetBus
        1337,            # Elite/Leet
        3389,            # RDP (can be suspicious if external)
        1234,            # SubSeven
        9999,            # Various trojans
        27374,           # SubSeven
        54321,           # Back Orifice 2000
    }
    
    # High-risk countries (optional - can be customized)
    HIGH_RISK_COUNTRIES = {
        'CN',  # China
        'RU',  # Russia
        'KP',  # North Korea
        'IR',  # Iran
        # Add more as needed based on your threat model
    }
    
    def __init__(self, 
                 max_connections_per_process: int = 50,
                 enable_geographic_checks: bool = True,
                 enable_unusual_port_checks: bool = True):
        """
        Initialize anomaly detector with configurable thresholds.
        
        Args:
            max_connections_per_process: Alert when process exceeds this many connections
            enable_geographic_checks: Check for high-risk countries
            enable_unusual_port_checks: Check for non-standard ports
        """
        self.max_connections = max_connections_per_process
        self.enable_geo_checks = enable_geographic_checks
        self.enable_port_checks = enable_unusual_port_checks
        self.alerts = []
        
        # Track statistics for reporting
        self.stats = {
            'total_checks': 0,
            'suspicious_ports_found': 0,
            'unusual_ports_found': 0,
            'high_connections_found': 0,
            'suspicious_paths_found': 0,
            'high_risk_countries_found': 0
        }
    
    def analyze(self, connections: List[Dict]) -> List[Dict]:
        """
        Analyze connections for anomalies.
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of alert dictionaries
        """
        self.alerts = []
        self.stats['total_checks'] += 1
        
        # Run all checks
        self._check_suspicious_ports(connections)
        if self.enable_port_checks:
            self._check_unusual_ports(connections)
        self._check_connection_count(connections)
        self._check_suspicious_processes(connections)
        if self.enable_geo_checks:
            self._check_geographic_anomalies(connections)
        
        # Sort alerts by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.alerts.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return self.alerts
    
    def _check_suspicious_ports(self, connections: List[Dict]):
        """Check for connections to known malicious ports."""
        seen = set()  # Avoid duplicate alerts
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            if ':' in remote:
                try:
                    port = int(remote.split(':')[1])
                    alert_key = (conn['process_name'], port)
                    
                    if port in self.SUSPICIOUS_PORTS and alert_key not in seen:
                        seen.add(alert_key)
                        self.stats['suspicious_ports_found'] += 1
                        self.alerts.append({
                            'timestamp': datetime.now(),
                            'type': 'Suspicious Port',
                            'severity': 'critical',
                            'description': f"{conn['process_name']} → {remote} (KNOWN MALICIOUS PORT {port})",
                            'details': {
                                'process': conn['process_name'],
                                'pid': conn['pid'],
                                'port': port,
                                'remote': remote,
                                'path': conn.get('process_path', 'Unknown')
                            }
                        })
                except (ValueError, IndexError):
                    pass
    
    def _check_unusual_ports(self, connections: List[Dict]):
        """Check for connections to unusual/non-standard ports."""
        unusual_ports = defaultdict(list)
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            if ':' in remote:
                try:
                    port = int(remote.split(':')[1])
                    # Skip if it's a standard port or already flagged as suspicious
                    if port not in self.STANDARD_PORTS and port not in self.SUSPICIOUS_PORTS:
                        # Only flag ports that might be unusual (e.g., > 1024 and not common)
                        if port > 1024 or port < 20:
                            unusual_ports[conn['process_name']].append((remote, port))
                except (ValueError, IndexError):
                    pass
        
        # Alert if a process has multiple unusual ports
        for process, port_list in unusual_ports.items():
            if len(port_list) >= 3:  # At least 3 unusual ports
                self.stats['unusual_ports_found'] += 1
                ports_str = ', '.join([str(p[1]) for p in port_list[:5]])
                if len(port_list) > 5:
                    ports_str += f' (+{len(port_list)-5} more)'
                
                self.alerts.append({
                    'timestamp': datetime.now(),
                    'type': 'Unusual Ports',
                    'severity': 'medium',
                    'description': f"{process} using unusual ports: {ports_str}",
                    'details': {
                        'process': process,
                        'unusual_port_count': len(port_list),
                        'ports': [p[1] for p in port_list]
                    }
                })
    
    def _check_connection_count(self, connections: List[Dict]):
        """Check for processes with unusually high connection counts."""
        process_counts = defaultdict(int)
        process_pids = defaultdict(set)
        
        for conn in connections:
            process = conn['process_name']
            process_counts[process] += 1
            process_pids[process].add(conn['pid'])
        
        for process, count in process_counts.items():
            if count > self.max_connections:
                self.stats['high_connections_found'] += 1
                severity = 'high' if count > self.max_connections * 2 else 'medium'
                
                self.alerts.append({
                    'timestamp': datetime.now(),
                    'type': 'High Connection Count',
                    'severity': severity,
                    'description': f"{process} has {count} connections (threshold: {self.max_connections})",
                    'details': {
                        'process': process,
                        'connection_count': count,
                        'threshold': self.max_connections,
                        'pids': list(process_pids[process])
                    }
                })
    
    def _check_suspicious_processes(self, connections: List[Dict]):
        """Check for processes running from suspicious locations."""
        suspicious_paths = [
            'temp', 'tmp', 
            'appdata\\local\\temp', 
            'downloads',
            '\\temp\\',
            '/tmp/',
            'recycle',
            'programdata',
        ]
        
        suspicious_names = [
            'svchost',  # If not from System32
            'rundll32',
            'powershell',
            'cmd',
            'wscript',
            'cscript',
        ]
        
        checked = set()
        
        for conn in connections:
            process = conn['process_name'].lower()
            if process in checked:
                continue
            checked.add(process)
            
            path = conn.get('process_path', '').lower()
            
            # Check for suspicious paths
            for suspicious in suspicious_paths:
                if suspicious in path:
                    self.stats['suspicious_paths_found'] += 1
                    self.alerts.append({
                        'timestamp': datetime.now(),
                        'type': 'Suspicious Process Path',
                        'severity': 'high',
                        'description': f"{conn['process_name']} running from suspicious location",
                        'details': {
                            'process': conn['process_name'],
                            'path': conn['process_path'],
                            'pid': conn['pid'],
                            'suspicious_indicator': suspicious
                        }
                    })
                    break
            
            # Check for suspicious process names not in system directories
            for suspicious_name in suspicious_names:
                if suspicious_name in process:
                    if 'system32' not in path and 'windows' not in path:
                        self.stats['suspicious_paths_found'] += 1
                        self.alerts.append({
                            'timestamp': datetime.now(),
                            'type': 'Suspicious Process Location',
                            'severity': 'high',
                            'description': f"{conn['process_name']} not running from system directory",
                            'details': {
                                'process': conn['process_name'],
                                'path': conn['process_path'],
                                'pid': conn['pid']
                            }
                        })
                        break
    
    def _check_geographic_anomalies(self, connections: List[Dict]):
        """Check for connections to high-risk countries."""
        if not self.enable_geo_checks:
            return
        
        high_risk_conns = defaultdict(list)
        
        for conn in connections:
            country_code = conn.get('country_code', '')
            country = conn.get('country', '')
            
            if country_code in self.HIGH_RISK_COUNTRIES:
                high_risk_conns[conn['process_name']].append({
                    'remote': conn.get('remote_address', 'Unknown'),
                    'country': country,
                    'country_code': country_code
                })
        
        for process, risk_conns in high_risk_conns.items():
            self.stats['high_risk_countries_found'] += 1
            countries = ', '.join(set([c['country'] for c in risk_conns]))
            
            self.alerts.append({
                'timestamp': datetime.now(),
                'type': 'Geographic Anomaly',
                'severity': 'medium',
                'description': f"{process} connecting to high-risk country: {countries}",
                'details': {
                    'process': process,
                    'connections': risk_conns,
                    'country_count': len(risk_conns)
                }
            })
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset all statistics."""
        self.stats = {
            'total_checks': 0,
            'suspicious_ports_found': 0,
            'unusual_ports_found': 0,
            'high_connections_found': 0,
            'suspicious_paths_found': 0,
            'high_risk_countries_found': 0
        }


# Example usage and testing
if __name__ == "__main__":
    # Test with sample connections
    test_connections = [
        {
            'process_name': 'malware.exe',
            'pid': 1234,
            'remote_address': '192.168.1.100:4444',
            'process_path': 'C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe'
        },
        {
            'process_name': 'chrome.exe',
            'pid': 5678,
            'remote_address': '142.250.185.46:443',
            'process_path': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'country': 'United States',
            'country_code': 'US'
        },
        {
            'process_name': 'suspicious.exe',
            'pid': 9999,
            'remote_address': '45.33.32.156:31337',
            'process_path': 'C:\\Windows\\Temp\\suspicious.exe'
        }
    ]
    
    detector = AnomalyDetector(max_connections_per_process=10)
    alerts = detector.analyze(test_connections)
    
    print("\n=== Anomaly Detection Test ===\n")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['type']}")
        print(f"  {alert['description']}")
        print(f"  Time: {alert['timestamp'].strftime('%H:%M:%S')}")
        print()
    
    print("Statistics:", detector.get_statistics())