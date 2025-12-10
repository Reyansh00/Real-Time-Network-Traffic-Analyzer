"""
IP Resolution and Geolocation Module
Performs reverse DNS lookups and IP geolocation with caching.
"""

import socket
import requests
import time
from typing import Dict, Optional, Tuple
from functools import lru_cache
import json


class ResolverCache:
    """
    Cache for DNS and geolocation lookups to minimize API calls.
    """
    
    def __init__(self, ttl: int = 3600):
        """
        Initialize the cache.
        
        Args:
            ttl: Time-to-live for cache entries in seconds (default 1 hour)
        """
        self.dns_cache = {}
        self.geo_cache = {}
        self.ttl = ttl
    
    def get_dns(self, ip: str) -> Optional[str]:
        """Get cached DNS result."""
        if ip in self.dns_cache:
            hostname, timestamp = self.dns_cache[ip]
            if time.time() - timestamp < self.ttl:
                return hostname
            else:
                del self.dns_cache[ip]
        return None
    
    def set_dns(self, ip: str, hostname: str):
        """Cache DNS result."""
        self.dns_cache[ip] = (hostname, time.time())
    
    def get_geo(self, ip: str) -> Optional[Dict]:
        """Get cached geolocation result."""
        if ip in self.geo_cache:
            geo_data, timestamp = self.geo_cache[ip]
            if time.time() - timestamp < self.ttl:
                return geo_data
            else:
                del self.geo_cache[ip]
        return None
    
    def set_geo(self, ip: str, geo_data: Dict):
        """Cache geolocation result."""
        self.geo_cache[ip] = (geo_data, time.time())
    
    def clear(self):
        """Clear all cached data."""
        self.dns_cache.clear()
        self.geo_cache.clear()


class IPResolver:
    """
    Resolves IP addresses to hostnames and geographic locations.
    """
    
    def __init__(self, cache_ttl: int = 3600, timeout: int = 2):
        """
        Initialize the IP resolver.
        
        Args:
            cache_ttl: Cache time-to-live in seconds
            timeout: Timeout for DNS/API requests in seconds
        """
        self.cache = ResolverCache(ttl=cache_ttl)
        self.timeout = timeout
        self.api_calls = 0
        self.api_limit = 45  # ip-api.com free tier limit per minute
        self.api_reset_time = time.time() + 60
    
    def resolve_hostname(self, ip: str) -> str:
        """
        Resolve IP address to hostname using reverse DNS.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Hostname or original IP if resolution fails
        """
        # Check if it's a private IP
        if self._is_private_ip(ip):
            return ip
        
        # Check cache first
        cached = self.cache.get_dns(ip)
        if cached is not None:
            return cached
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.cache.set_dns(ip, hostname)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            # Resolution failed, cache the IP itself
            self.cache.set_dns(ip, ip)
            return ip
        except Exception as e:
            return ip
    
    def get_geolocation(self, ip: str) -> Dict:
        """
        Get geographic location of an IP address using ip-api.com.
        
        Args:
            ip: IP address to geolocate
            
        Returns:
            Dictionary with location data or error info
        """
        # Check if it's a private IP
        if self._is_private_ip(ip):
            return {
                'status': 'private',
                'ip': ip,
                'country': 'Private Network',
                'city': 'Local',
                'isp': 'Private',
                'org': 'Private Network'
            }
        
        # Check cache first
        cached = self.cache.get_geo(ip)
        if cached is not None:
            return cached
        
        # Check API rate limit
        if not self._check_rate_limit():
            return {
                'status': 'rate_limited',
                'ip': ip,
                'message': 'API rate limit exceeded'
            }
        
        try:
            # Use ip-api.com free API
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    geo_data = {
                        'status': 'success',
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip': data.get('zip', ''),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'timezone': data.get('timezone', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', '')
                    }
                else:
                    geo_data = {
                        'status': 'failed',
                        'ip': ip,
                        'message': data.get('message', 'Unknown error')
                    }
                
                self.cache.set_geo(ip, geo_data)
                return geo_data
            else:
                return {
                    'status': 'error',
                    'ip': ip,
                    'message': f'API returned status {response.status_code}'
                }
        
        except requests.Timeout:
            return {
                'status': 'timeout',
                'ip': ip,
                'message': 'Request timed out'
            }
        except requests.RequestException as e:
            return {
                'status': 'error',
                'ip': ip,
                'message': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'ip': ip,
                'message': str(e)
            }
    
    def get_full_info(self, ip: str) -> Dict:
        """
        Get both hostname and geolocation for an IP.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Dictionary with hostname and geolocation data
        """
        hostname = self.resolve_hostname(ip)
        geo_data = self.get_geolocation(ip)
        
        return {
            'ip': ip,
            'hostname': hostname,
            'geo': geo_data
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if IP is private/local.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if private, False otherwise
        """
        # Common private IP ranges
        private_ranges = [
            ('127.', True),      # Loopback
            ('10.', True),       # Class A private
            ('172.16.', True),   # Class B private
            ('172.17.', True),
            ('172.18.', True),
            ('172.19.', True),
            ('172.20.', True),
            ('172.21.', True),
            ('172.22.', True),
            ('172.23.', True),
            ('172.24.', True),
            ('172.25.', True),
            ('172.26.', True),
            ('172.27.', True),
            ('172.28.', True),
            ('172.29.', True),
            ('172.30.', True),
            ('172.31.', True),
            ('192.168.', True),  # Class C private
            ('169.254.', True),  # Link-local
            ('0.0.0.0', True),   # Unspecified
        ]
        
        for prefix, _ in private_ranges:
            if ip.startswith(prefix):
                return True
        
        return False
    
    def _check_rate_limit(self) -> bool:
        """
        Check if we're within API rate limits.
        
        Returns:
            True if we can make a request, False otherwise
        """
        current_time = time.time()
        
        # Reset counter if minute has passed
        if current_time >= self.api_reset_time:
            self.api_calls = 0
            self.api_reset_time = current_time + 60
        
        # Check if under limit
        if self.api_calls < self.api_limit:
            self.api_calls += 1
            return True
        
        return False
    
    def format_location(self, geo_data: Dict) -> str:
        """
        Format geolocation data into a readable string.
        
        Args:
            geo_data: Geolocation dictionary
            
        Returns:
            Formatted location string
        """
        if geo_data.get('status') != 'success':
            return geo_data.get('message', 'Unknown')
        
        city = geo_data.get('city', 'Unknown')
        region = geo_data.get('region', '')
        country = geo_data.get('country', 'Unknown')
        
        if region and region != city:
            return f"{city}, {region}, {country}"
        else:
            return f"{city}, {country}"


def extract_ip_from_address(address: str) -> str:
    """
    Extract IP address from "IP:PORT" format.
    
    Args:
        address: Address string in "IP:PORT" format
        
    Returns:
        IP address only
    """
    if ':' in address:
        return address.split(':')[0]
    return address


# Example usage and testing
if __name__ == "__main__":
    print("Testing IP Resolver...\n")
    
    resolver = IPResolver()
    
    # Test IPs (public examples)
    test_ips = [
        "8.8.8.8",           # Google DNS
        "1.1.1.1",           # Cloudflare DNS
        "142.250.185.46",    # Google
        "127.0.0.1",         # Localhost
        "192.168.1.1"        # Private IP
    ]
    
    for ip in test_ips:
        print(f"Resolving {ip}...")
        
        # Hostname resolution
        hostname = resolver.resolve_hostname(ip)
        print(f"  Hostname: {hostname}")
        
        # Geolocation
        geo = resolver.get_geolocation(ip)
        if geo['status'] == 'success':
            location = resolver.format_location(geo)
            print(f"  Location: {location}")
            print(f"  ISP: {geo.get('isp', 'Unknown')}")
        else:
            print(f"  Location: {geo.get('message', 'Unknown')}")
        
        print()
        
        # Small delay to avoid rate limiting
        time.sleep(1.5)
    
    print(f"API calls made: {resolver.api_calls}")