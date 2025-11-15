import requests
import json
import socket
from datetime import datetime

class IPLookup:
    def __init__(self):
        self.results = {}

    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def lookup(self, ip):
        """
        Lookup IP using ip-api.com (FREE, NO KEY)
        Provides: geolocation, ISP, proxy detection
        """
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    return data
                else:
                    return None
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def analyze(self, ip):
        """Perform comprehensive IP analysis"""
        print(f"\n{'='*70}")
        print(f"  🌐 IP GEOLOCATION OSINT")
        print(f"{'='*70}\n")

        if not self.validate_ip(ip):
            print("❌ Invalid IP address format!")
            return None

        print(f"🔍 Looking up: {ip}...\n")

        data = self.lookup(ip)
        if not data:
            print("❌ Could not get IP information. Check your internet connection.")
            return None

        hostname = self.get_hostname(ip)

        results = {
            'ip': ip,
            'analysis_date': datetime.now().isoformat(),
            'location': {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
            },
            'network': {
                'isp': data.get('isp'),
                'organization': data.get('org'),
                'as_number': data.get('as'),
                'hostname': hostname,
            },
            'security': {
                'is_mobile': data.get('mobile', False),
                'is_proxy': data.get('proxy', False),
                'is_hosting': data.get('hosting', False),
            },
            'maps_url': f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}"
        }

        # Display results
        print("📍 LOCATION:")
        print(f"   Country: {results['location']['country']} ({results['location']['country_code']})")
        print(f"   Region: {results['location']['region']}")
        print(f"   City: {results['location']['city']}")
        print(f"   Coordinates: {results['location']['latitude']}, {results['location']['longitude']}")
        print(f"   Timezone: {results['location']['timezone']}")

        print(f"\n🌐 NETWORK:")
        print(f"   ISP: {results['network']['isp']}")
        print(f"   Organization: {results['network']['organization']}")
        print(f"   AS Number: {results['network']['as_number']}")
        print(f"   Hostname: {results['network']['hostname'] or 'N/A'}")

        print(f"\n🔒 SECURITY:")
        print(f"   Mobile: {'Yes' if results['security']['is_mobile'] else 'No'}")
        print(f"   Proxy/VPN: {'Yes ⚠️' if results['security']['is_proxy'] else 'No ✓'}")
        print(f"   Hosting: {'Yes' if results['security']['is_hosting'] else 'No'}")

        print(f"\n🗺️  Google Maps:")
        print(f"   {results['maps_url']}")

        self.results = results
        return results

    def export(self):
        """Export analysis report to JSON"""
        if not self.results:
            return None

        ip_formatted = self.results['ip'].replace('.', '_')
        filename = f"ip_osint_{ip_formatted}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n✅ Report exported to: {filename}")
        return filename

def get_my_ip():
    """Get public IP address of the current machine"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return None

def main():
    print("\n" + "="*70)
    print("     🌐 IP GEOLOCATION TOOL")
    print("     FREE - NO API KEY NEEDED")
    print("="*70)

    print("\nOptions:")
    print("1. Analyze a specific IP address")
    print("2. Analyze my public IP")

    choice = input("\nSelect option (1/2): ").strip()

    if choice == '2':
        print("\n🔍 Fetching your public IP...")
        ip = get_my_ip()
        if not ip:
            print("Error: Could not fetch your public IP")
            return
        print(f"Your public IP: {ip}")
    else:
        ip = input("\nEnter IP address: ").strip()

    if not ip:
        print("Error: IP address cannot be empty!")
        return

    tool = IPLookup()
    results = tool.analyze(ip)

    if results:
        choice = input("\nExport report? (y/n): ").strip().lower()
        if choice == 'y':
            tool.export()

        print("\n✅ Done!\n")

if __name__ == "__main__":
    main()