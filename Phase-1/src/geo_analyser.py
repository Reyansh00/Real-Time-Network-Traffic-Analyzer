"""
Geographic Analysis and Map Visualization Module
Analyzes connection patterns and creates interactive maps
"""

from collections import Counter, defaultdict
from typing import Dict, List
import json


class GeographicAnalyzer:
    """Analyze geographic patterns in network connections."""
    
    # Define risk levels for countries (customize based on your threat model)
    COUNTRY_RISK_LEVELS = {
        'CN': 'high',      # China
        'RU': 'high',      # Russia
        'KP': 'critical',  # North Korea
        'IR': 'high',      # Iran
        'SY': 'high',      # Syria
        'BY': 'medium',    # Belarus
        'VE': 'medium',    # Venezuela
    }
    
    # Unusual countries for typical user traffic
    UNUSUAL_COUNTRIES = {
        'KP', 'SY', 'IR', 'CU', 'SD', 'SO', 'AF', 'YE', 'LY', 'IQ'
    }
    
    def __init__(self):
        self.country_stats = Counter()
        self.city_stats = Counter()
        self.isp_stats = Counter()
        self.connection_locations = []
        self.process_country_map = defaultdict(set)
        self.alerts = []
    
    def analyze_connections(self, connections: List[Dict]) -> Dict:
        """
        Perform comprehensive geographic analysis.
        
        Args:
            connections: List of connection dictionaries with geo data
            
        Returns:
            Analysis report dictionary
        """
        self.country_stats.clear()
        self.city_stats.clear()
        self.isp_stats.clear()
        self.connection_locations.clear()
        self.process_country_map.clear()
        self.alerts.clear()
        
        for conn in connections:
            country = conn.get('country', 'Unknown')
            country_code = conn.get('country_code', '')
            
            if country and country not in ['Unknown', 'Private Network', 'Local']:
                # Update statistics
                self.country_stats[country] += 1
                
                city = conn.get('city', 'Unknown')
                if city and city != 'Unknown':
                    self.city_stats[f"{city}, {country}"] += 1
                
                isp = conn.get('isp', 'Unknown')
                if isp and isp != 'Unknown':
                    self.isp_stats[isp] += 1
                
                # Track which processes connect to which countries
                process = conn.get('process_name', 'Unknown')
                self.process_country_map[process].add(country)
                
                # Store location data for mapping
                lat = conn.get('lat', 0)
                lon = conn.get('lon', 0)
                if lat and lon:
                    self.connection_locations.append({
                        'lat': lat,
                        'lon': lon,
                        'country': country,
                        'city': city,
                        'process': process,
                        'remote': conn.get('remote_address', ''),
                        'isp': isp
                    })
                
                # Check for unusual/risky connections
                self._check_unusual_country(conn, country_code, process)
                self._check_risk_level(conn, country_code, process)
        
        return self._generate_report()
    
    def _check_unusual_country(self, conn: Dict, country_code: str, process: str):
        """Check if connection is to an unusual country."""
        if country_code in self.UNUSUAL_COUNTRIES:
            self.alerts.append({
                'type': 'Unusual Country',
                'severity': 'medium',
                'country': conn['country'],
                'country_code': country_code,
                'process': process,
                'remote': conn.get('remote_address', ''),
                'description': f"{process} → {conn['country']} (unusual destination)"
            })
    
    def _check_risk_level(self, conn: Dict, country_code: str, process: str):
        """Check risk level of country."""
        risk = self.COUNTRY_RISK_LEVELS.get(country_code)
        if risk:
            self.alerts.append({
                'type': 'High-Risk Country',
                'severity': risk,
                'country': conn['country'],
                'country_code': country_code,
                'process': process,
                'remote': conn.get('remote_address', ''),
                'description': f"{process} → {conn['country']} ({risk.upper()} risk)"
            })
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive geographic report."""
        # Calculate diversity metrics
        total_connections = sum(self.country_stats.values())
        unique_countries = len(self.country_stats)
        
        return {
            'total_connections': total_connections,
            'total_countries': unique_countries,
            'total_cities': len(self.city_stats),
            'total_isps': len(self.isp_stats),
            'top_countries': self.country_stats.most_common(10),
            'top_cities': self.city_stats.most_common(10),
            'top_isps': self.isp_stats.most_common(10),
            'connection_locations': self.connection_locations,
            'process_countries': dict(self.process_country_map),
            'alerts': self.alerts,
            'country_distribution': dict(self.country_stats),
        }
    
    def print_report(self, report: Dict):
        """Print formatted geographic analysis report."""
        print("\n" + "=" * 80)
        print("  GEOGRAPHIC ANALYSIS REPORT")
        print("=" * 80)
        
        print(f"\n📊 OVERVIEW")
        print(f"  Total Connections Analyzed: {report['total_connections']}")
        print(f"  Unique Countries: {report['total_countries']}")
        print(f"  Unique Cities: {report['total_cities']}")
        print(f"  Unique ISPs: {report['total_isps']}")
        
        # Top Countries
        if report['top_countries']:
            print(f"\n🌍 TOP COUNTRIES")
            for i, (country, count) in enumerate(report['top_countries'], 1):
                percentage = (count / report['total_connections']) * 100
                bar = '█' * int(percentage / 2)
                print(f"  {i:2d}. {country:20s} {count:4d} connections {bar} {percentage:.1f}%")
        
        # Top Cities
        if report['top_cities']:
            print(f"\n🏙️  TOP CITIES")
            for i, (city, count) in enumerate(report['top_cities'][:5], 1):
                print(f"  {i}. {city:35s} {count:4d} connections")
        
        # Top ISPs
        if report['top_isps']:
            print(f"\n🌐 TOP ISPs/ORGANIZATIONS")
            for i, (isp, count) in enumerate(report['top_isps'][:5], 1):
                print(f"  {i}. {isp:40s} {count:4d} connections")
        
        # Process-Country mapping
        if report['process_countries']:
            print(f"\n📱 PROCESS GEOGRAPHIC REACH")
            for process, countries in sorted(report['process_countries'].items()):
                if len(countries) > 1:
                    countries_str = ', '.join(sorted(countries)[:5])
                    if len(countries) > 5:
                        countries_str += f' (+{len(countries)-5} more)'
                    print(f"  {process:20s} → {countries_str}")
        
        # Alerts
        if report['alerts']:
            print(f"\n⚠️  GEOGRAPHIC ALERTS ({len(report['alerts'])})")
            for alert in report['alerts'][:10]:
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(alert['severity'], '⚪')
                print(f"  {severity_icon} {alert['description']}")
        
        print("\n" + "=" * 80 + "\n")


class MapVisualizer:
    """Create HTML map visualization of connections."""
    
    @staticmethod
    def create_world_map(connections: List[Dict], output_file: str = 'connection_map.html') -> str:
        """
        Create interactive world map showing all connections.
        
        Args:
            connections: List of connections with lat/lon data
            output_file: Output HTML file path
            
        Returns:
            Path to created HTML file
        """
        
        # Extract location data
        locations = []
        for conn in connections:
            lat = conn.get('lat', 0)
            lon = conn.get('lon', 0)
            if lat and lon:
                locations.append({
                    'lat': lat,
                    'lon': lon,
                    'country': conn.get('country', 'Unknown'),
                    'city': conn.get('city', 'Unknown'),
                    'process': conn.get('process_name', 'Unknown'),
                    'remote': conn.get('remote_address', ''),
                    'isp': conn.get('isp', 'Unknown')
                })
        
        # Generate HTML with embedded map
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Connection Map</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        #map {{
            position: absolute;
            top: 60px;
            left: 0;
            right: 0;
            bottom: 0;
        }}
        .header {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            z-index: 1000;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }}
        .stats {{
            font-size: 14px;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
        }}
        .leaflet-popup-content {{
            margin: 15px;
            min-width: 250px;
        }}
        .popup-title {{
            font-size: 16px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 2px solid #667eea;
        }}
        .popup-row {{
            margin: 6px 0;
            font-size: 13px;
        }}
        .popup-label {{
            font-weight: 600;
            color: #555;
            display: inline-block;
            width: 80px;
        }}
        .popup-value {{
            color: #333;
        }}
        .marker-cluster {{
            background-color: rgba(102, 126, 234, 0.6);
            border-radius: 50%;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🌍 Network Connection Map</h1>
        <div class="stats">
            <strong>{len(locations)}</strong> connections
            <span style="margin: 0 10px;">|</span>
            <strong>{len(set(loc['country'] for loc in locations))}</strong> countries
        </div>
    </div>
    <div id="map"></div>

    <script>
        // Initialize map centered on world
        var map = L.map('map').setView([20, 0], 2);

        // Add tile layer
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18,
        }}).addTo(map);

        // Connection data
        var locations = {json.dumps(locations)};

        // Add markers for each connection
        locations.forEach(function(loc) {{
            var marker = L.circleMarker([loc.lat, loc.lon], {{
                radius: 8,
                fillColor: '#667eea',
                color: '#fff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.7
            }});

            var popupContent = `
                <div class="popup-title">${{loc.country}}</div>
                <div class="popup-row">
                    <span class="popup-label">City:</span>
                    <span class="popup-value">${{loc.city}}</span>
                </div>
                <div class="popup-row">
                    <span class="popup-label">Process:</span>
                    <span class="popup-value">${{loc.process}}</span>
                </div>
                <div class="popup-row">
                    <span class="popup-label">IP:Port:</span>
                    <span class="popup-value">${{loc.remote}}</span>
                </div>
                <div class="popup-row">
                    <span class="popup-label">ISP:</span>
                    <span class="popup-value">${{loc.isp}}</span>
                </div>
            `;

            marker.bindPopup(popupContent);
            marker.addTo(map);
        }});

        // Fit map to markers if we have locations
        if (locations.length > 0) {{
            var bounds = locations.map(loc => [loc.lat, loc.lon]);
            map.fitBounds(bounds, {{padding: [50, 50]}});
        }}
    </script>
</body>
</html>"""
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_file
        except Exception as e:
            print(f"Error creating map: {e}")
            return None
    
    @staticmethod
    def create_country_heatmap(connections: List[Dict], output_file: str = 'country_heatmap.html') -> str:
        """
        Create a heatmap showing connection density by country.
        
        Args:
            connections: List of connections with geo data
            output_file: Output HTML file path
            
        Returns:
            Path to created HTML file
        """
        # Count connections per country
        country_counts = Counter()
        country_coords = {}
        
        for conn in connections:
            country = conn.get('country', 'Unknown')
            if country and country not in ['Unknown', 'Private Network', 'Local']:
                country_counts[country] += 1
                if country not in country_coords:
                    lat = conn.get('lat', 0)
                    lon = conn.get('lon', 0)
                    if lat and lon:
                        country_coords[country] = (lat, lon)
        
        # Create HTML
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Connection Heatmap</title>
    <meta charset="utf-8" />
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #667eea;
            margin-bottom: 30px;
        }}
        .country-row {{
            display: flex;
            align-items: center;
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .country-name {{
            width: 200px;
            font-weight: 600;
        }}
        .bar-container {{
            flex: 1;
            height: 25px;
            background: #e0e0e0;
            border-radius: 3px;
            overflow: hidden;
            margin: 0 15px;
        }}
        .bar {{
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s ease;
        }}
        .count {{
            width: 80px;
            text-align: right;
            font-weight: bold;
            color: #667eea;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🗺️ Connection Distribution by Country</h1>
        <p>Total connections: <strong>{sum(country_counts.values())}</strong> across <strong>{len(country_counts)}</strong> countries</p>
        <div style="margin-top: 30px;">
"""
        
        max_count = max(country_counts.values()) if country_counts else 1
        
        for country, count in country_counts.most_common():
            percentage = (count / max_count) * 100
            html_content += f"""
            <div class="country-row">
                <div class="country-name">{country}</div>
                <div class="bar-container">
                    <div class="bar" style="width: {percentage}%"></div>
                </div>
                <div class="count">{count}</div>
            </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_file
        except Exception as e:
            print(f"Error creating heatmap: {e}")
            return None


# Example usage
if __name__ == "__main__":
    # Test data
    test_connections = [
        {
            'country': 'United States',
            'country_code': 'US',
            'city': 'Mountain View',
            'lat': 37.386,
            'lon': -122.084,
            'isp': 'Google LLC',
            'process_name': 'chrome.exe',
            'remote_address': '142.250.185.46:443'
        },
        {
            'country': 'Ireland',
            'country_code': 'IE',
            'city': 'Dublin',
            'lat': 53.3498,
            'lon': -6.2603,
            'isp': 'Amazon',
            'process_name': 'firefox.exe',
            'remote_address': '52.18.232.1:443'
        },
        {
            'country': 'China',
            'country_code': 'CN',
            'city': 'Beijing',
            'lat': 39.9042,
            'lon': 116.4074,
            'isp': 'China Telecom',
            'process_name': 'suspicious.exe',
            'remote_address': '123.125.115.110:8080'
        }
    ]
    
    # Test analyzer
    analyzer = GeographicAnalyzer()
    report = analyzer.analyze_connections(test_connections)
    analyzer.print_report(report)
    
    # Test map creation
    print("\nCreating maps...")
    map_file = MapVisualizer.create_world_map(test_connections)
    if map_file:
        print(f"✅ World map created: {map_file}")
    
    heatmap_file = MapVisualizer.create_country_heatmap(test_connections)
    if heatmap_file:
        print(f"✅ Heatmap created: {heatmap_file}")    