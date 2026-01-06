"""
IP Resolution and Geolocation Module - FIXED VERSION
Performs reverse DNS lookups and IP geolocation with caching.
"""

import socket
import requests
import time
from typing import Dict, Optional
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
    
    def __init__(self, cache_ttl: int = 3600, timeout: int = 3):
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
        self.last_api_call = 0
        self.min_delay = 1.5  # Minimum delay between API calls (40 per minute max)
    
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
            # Set socket timeout
            socket.setdefaulttimeout(self.timeout)
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
                'countryCode': 'LOCAL',
                'city': 'Local',
                'isp': 'Private',
                'org': 'Private Network',
                'lat': 0,
                'lon': 0
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
                'country': 'Rate Limited',
                'countryCode': '',
                'message': 'API rate limit exceeded, try again in a moment'
            }
        
        # Enforce minimum delay between API calls
        current_time = time.time()
        time_since_last = current_time - self.last_api_call
        if time_since_last < self.min_delay:
            time.sleep(self.min_delay - time_since_last)
        
        try:
            # Use ip-api.com free API with all available fields
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            
            response = requests.get(url, timeout=self.timeout)
            self.last_api_call = time.time()
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    geo_data = {
                        'status': 'success',
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'countryCode': data.get('countryCode', ''),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip': data.get('zip', ''),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'timezone': data.get('timezone', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', ''),
                        'query': data.get('query', ip)
                    }
                    
                    self.cache.set_geo(ip, geo_data)
                    return geo_data
                else:
                    # API returned fail status
                    error_msg = data.get('message', 'Unknown error')
                    geo_data = {
                        'status': 'failed',
                        'ip': ip,
                        'country': 'Unknown',
                        'countryCode': '',
                        'message': error_msg
                    }
                    self.cache.set_geo(ip, geo_data)
                    return geo_data
            else:
                return {
                    'status': 'error',
                    'ip': ip,
                    'country': 'Error',
                    'countryCode': '',
                    'message': f'API returned status {response.status_code}'
                }
        
        except requests.Timeout:
            return {
                'status': 'timeout',
                'ip': ip,
                'country': 'Timeout',
                'countryCode': '',
                'message': 'Request timed out'
            }
        except requests.RequestException as e:
            return {
                'status': 'error',
                'ip': ip,
                'country': 'Error',
                'countryCode': '',
                'message': f'Request error: {str(e)}'
            }
        except Exception as e:
            return {
                'status': 'error',
                'ip': ip,
                'country': 'Error',
                'countryCode': '',
                'message': f'Unexpected error: {str(e)}'
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
        try:
            # Split IP into octets
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            # Convert to integers
            octets = [int(p) for p in parts]
            
            # Check various private ranges
            # 127.0.0.0/8 - Loopback
            if octets[0] == 127:
                return True
            
            # 10.0.0.0/8 - Class A private
            if octets[0] == 10:
                return True
            
            # 172.16.0.0/12 - Class B private
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            
            # 192.168.0.0/16 - Class C private
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # 169.254.0.0/16 - Link-local
            if octets[0] == 169 and octets[1] == 254:
                return True
            
            # 0.0.0.0/8 - Current network
            if octets[0] == 0:
                return True
            
            # 224.0.0.0/4 - Multicast
            if octets[0] >= 224 and octets[0] <= 239:
                return True
            
            # 240.0.0.0/4 - Reserved
            if octets[0] >= 240:
                return True
            
            return False
            
        except (ValueError, IndexError):
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
        if geo_data.get('status') == 'private':
            return 'Private Network'
        
        if geo_data.get('status') != 'success':
            return geo_data.get('message', 'Unknown')
        
        city = geo_data.get('city', '')
        region = geo_data.get('region', '')
        country = geo_data.get('country', 'Unknown')
        
        # Build location string
        parts = []
        if city and city != 'Unknown':
            parts.append(city)
        if region and region != 'Unknown' and region != city:
            parts.append(region)
        if country and country != 'Unknown':
            parts.append(country)
        
        return ', '.join(parts) if parts else 'Unknown'
    
    def get_stats(self) -> Dict:
        """Get resolver statistics."""
        return {
            'dns_cache_size': len(self.cache.dns_cache),
            'geo_cache_size': len(self.cache.geo_cache),
            'api_calls': self.api_calls,
            'api_limit': self.api_limit,
            'time_until_reset': max(0, int(self.api_reset_time - time.time()))
        }


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
    print("=" * 70)
    print("  TESTING IP RESOLVER WITH GEOLOCATION")
    print("=" * 70)
    print()
    
    resolver = IPResolver()
    
    # Test IPs (public examples)
    test_cases = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("142.250.185.46", "Google"),
        ("13.107.42.14", "Microsoft"),
        ("127.0.0.1", "Localhost (Private)"),
        ("192.168.1.1", "Private Network"),
    ]
    
    for ip, description in test_cases:
        print(f"Testing: {description}")
        print(f"IP: {ip}")
        print("-" * 70)
        
        # Hostname resolution
        hostname = resolver.resolve_hostname(ip)
        print(f"  Hostname: {hostname}")
        
        # Geolocation
        geo = resolver.get_geolocation(ip)
        print(f"  Status: {geo.get('status', 'unknown')}")
        
        if geo['status'] == 'success':
            location = resolver.format_location(geo)
            print(f"  Location: {location}")
            print(f"  Country: {geo.get('country', 'Unknown')} ({geo.get('countryCode', 'N/A')})")
            print(f"  City: {geo.get('city', 'Unknown')}")
            print(f"  ISP: {geo.get('isp', 'Unknown')}")
            print(f"  Coordinates: {geo.get('lat', 0)}, {geo.get('lon', 0)}")
        elif geo['status'] == 'private':
            print(f"  Location: {geo.get('country', 'Private Network')}")
        else:
            print(f"  Error: {geo.get('message', 'Unknown error')}")
        
        print()
        
        # Delay to respect rate limits
        if ip not in ['127.0.0.1', '192.168.1.1']:
            time.sleep(1.5)
    
    # Show statistics
    stats = resolver.get_stats()
    print("=" * 70)
    print("RESOLVER STATISTICS")
    print("=" * 70)
    print(f"  DNS Cache Size: {stats['dns_cache_size']}")
    print(f"  Geo Cache Size: {stats['geo_cache_size']}")
    print(f"  API Calls Made: {stats['api_calls']}/{stats['api_limit']}")
    print(f"  Time Until Reset: {stats['time_until_reset']}s")
    print()
    
    # Test cache
    print("=" * 70)
    print("TESTING CACHE (should be instant)")
    print("=" * 70)
    
    start_time = time.time()
    cached_geo = resolver.get_geolocation("8.8.8.8")
    elapsed = time.time() - start_time
    
    print(f"  Cached lookup took: {elapsed:.4f} seconds")
    print(f"  Result: {resolver.format_location(cached_geo)}")
    print()