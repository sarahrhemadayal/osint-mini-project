import requests
import dotenv
import json
import re
import hashlib
import socket
import time
from datetime import datetime


class ImprovedEmailOSINT:
    def __init__(self):
        self.results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def get_domain(self, email):
        """Extract domain from email"""
        return email.split('@')[1] if '@' in email else ''

    def get_username(self, email):
        """Extract username from email"""
        return email.split('@')[0] if '@' in email else ''

    def safe_get(self, url, timeout=5):
        """Safe GET request with error handling"""
        try:
            response = requests.get(url, headers=self.headers, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

    # IMPROVED: Check Gravatar
    def check_gravatar(self, email):
        """
        Gravatar - Gets social profiles linked to email
        """
        print("  ✓ Gravatar (checking for social links)...")
        try:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            url = f"https://www.gravatar.com/{email_hash}.json"
            data = self.safe_get(url, timeout=3)

            if data and 'entry' in data and len(data['entry']) > 0:
                entry = data['entry'][0]
                urls = entry.get('urls', [])
                social_profiles = [u['value'] for u in urls if 'value' in u]

                return {
                    'source': 'Gravatar',
                    'found': True,
                    'name': entry.get('displayName'),
                    'photo': entry.get('photos', [{}])[0].get('value') if entry.get('photos') else None,
                    'location': entry.get('currentLocation'),
                    'bio': entry.get('aboutMe'),
                    'social_profiles': social_profiles
                }
            return {
                'source': 'Gravatar',
                'found': False,
                'social_profiles': []
            }
        except Exception as e:
            return {
                'source': 'Gravatar',
                'found': False,
                'error': str(e)
            }

    # NEW: Check common social platforms with username
    def check_social_platforms(self, email):
        """
        Check if username exists on common social platforms
        """
        print("  ✓ Checking social platforms...")
        username = self.get_username(email)

        platforms = {
            'GitHub': f'https://api.github.com/users/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Instagram': f'https://instagram.com/{username}/',
            'Dev.to': f'https://dev.to/api/users/by_username?url={username}',
        }

        found_profiles = []

        for platform, url in platforms.items():
            try:
                if platform == 'GitHub':
                    response = requests.get(url, headers=self.headers, timeout=3)
                    if response.status_code == 200:
                        found_profiles.append({
                            'platform': platform,
                            'url': f'https://github.com/{username}',
                            'status': 'found'
                        })

                elif platform == 'Dev.to':
                    response = requests.get(url, headers=self.headers, timeout=3)
                    if response.status_code == 200:
                        found_profiles.append({
                            'platform': platform,
                            'url': f'https://dev.to/{username}',
                            'status': 'found'
                        })

                elif platform == 'Twitter':
                    # Just add as potential (Twitter blocks scraping)
                    found_profiles.append({
                        'platform': platform,
                        'url': f'https://twitter.com/{username}',
                        'status': 'potential'
                    })

                elif platform == 'LinkedIn':
                    # Just add as potential
                    found_profiles.append({
                        'platform': platform,
                        'url': f'https://linkedin.com/in/{username}',
                        'status': 'potential'
                    })

                elif platform == 'Instagram':
                    # Just add as potential
                    found_profiles.append({
                        'platform': platform,
                        'url': f'https://instagram.com/{username}/',
                        'status': 'potential'
                    })
            except:
                pass

        return {
            'source': 'SocialCheck',
            'username': username,
            'found_profiles': found_profiles
        }

    # API 1: EmailRep.io - NO KEY NEEDED
    def check_emailrep(self, email):
        """
        Check email reputation using PureChecker single-check API (header auth).
        Requires PURECHECKER_USER and PURECHECKER_SECRET in your .env file.
        Uses a 3 second timeout and always waits 3 seconds after the call.
        """
        print("  ✓ PureChecker (reputation check)...")
        dotenv.load_dotenv()
        user_id = dotenv.get_key('.env', 'PURECHECKER_USER')
        secret_key = dotenv.get_key('.env', 'PURECHECKER_SECRET')
        if not user_id or not secret_key:
            return {'source': 'PureChecker', 'error': 'API credentials not found in .env'}

        url = f'https://purechecker.com/api/v1/single-check?email={email}'
        headers = {
            'Content-Type': 'application/json',
            'x-user-id': user_id,
            'x-secret-key': secret_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', result)
                return {
                    'source': 'PureChecker',
                    'valid_syntax':   data.get('isValidSyntax'),
                    'valid_domain':   data.get('isValidDomain'),
                    'domain':         data.get('domain'),
                    'reason':         data.get('reason'),
                    'risk_level':     data.get('riskLevel'),
                    'disposable':     data.get('isDisposable'),
                    'exists':         data.get('isExist'),
                    'free':           data.get('free'),
                    'role':           data.get('role'),
                    'first_name':     data.get('firstName'),
                    'last_name':      data.get('lastName'),
                    'mx_records':     data.get('mxRecords'),
                    'raw_response':   data
                }
            else:
                return {'source': 'PureChecker', 'error': response.text}
        except Exception as e:
            return {'source': 'PureChecker', 'error': str(e)}





    # API 2: Domain Check - NO KEY NEEDED
    def check_domain(self, email):
        """DNS/Domain check"""
        print("  ✓ Domain DNS lookup...")
        try:
            domain = self.get_domain(email)
            ip = socket.gethostbyname(domain)

            return {
                'source': 'DNS',
                'domain': domain,
                'ip': ip,
                'reachable': True
            }
        except:
            try:
                domain = self.get_domain(email)
                return {
                    'source': 'DNS',
                    'domain': domain,
                    'ip': None,
                    'reachable': False
                }
            except:
                return None

    # API 3: Simple Validation - NO KEY NEEDED
    def check_format(self, email):
        """Email format check"""
        print("  ✓ Email format validation...")
        try:
            return {
                'source': 'Format',
                'valid': self.validate_email(email),
                'has_plus': '+' in email,
                'domain': self.get_domain(email)
            }
        except:
            return None

    # API 4: Breach Check
    def check_breaches(self, email):
        dotenv.load_dotenv()
        api_key = dotenv.get_key('.env', 'LEAK_LOOKUP_API_KEY')
        """Count every returned site as a breached site, regardless of empty data."""
        import time
        try:
            url = "https://leak-lookup.com/api/search"
            data = {
                'key': api_key,
                'type': 'email_address',
                'query': email
            }
            start = time.time()
            response = requests.post(url, data=data, headers=self.headers, timeout=30)
            elapsed = time.time() - start
            if elapsed < 10:
                time.sleep(10 - elapsed)

            print("\n--- FULL Leak-Lookup API Response ---")
            print("Status code:", response.status_code)
            print("Headers:", response.headers)
            print("Text:", response.text)
            print("--- END OF API Response ---\n")

            if response.status_code == 200:
                resp_json = response.json()
                if resp_json.get('error') == "false":
                    sites = list(resp_json.get('message', {}).keys())
                    breached_sites_count = len(sites)
                    return {
                        'source': 'LeakLookup',
                        'breach_check_passed': True,  # Always true for public; sites returned
                        'breached_sites': breached_sites_count,
                        'site_names': sites,
                        'raw_response': resp_json
                    }
                else:
                    return {
                        'source': 'LeakLookup',
                        'breach_check_passed': False,
                        'breached_sites': 0,
                        'error': resp_json.get('message'),
                        'raw_response': resp_json
                    }
            else:
                return {
                    'source': 'LeakLookup',
                    'breach_check_passed': False,
                    'breached_sites': 0,
                    'error': response.text
                }
        except Exception as e:
            return {
                'source': 'LeakLookup',
                'breach_check_passed': False,
                'breached_sites': 0,
                'error': str(e)
            }




    def analyze(self, email):
        """Run email OSINT analysis"""
        print(f"\n{'='*70}")
        print(f"  🔍 EMAIL OSINT ANALYSIS")
        print(f"{'='*70}\n")

        if not self.validate_email(email):
            print("❌ Invalid email format!")
            return None

        print(f"📧 Analyzing: {email}\n")
        print("Checking APIs and social platforms...\n")

        results = {
            'email': email,
            'username': self.get_username(email),
            'analysis_date': datetime.now().isoformat(),
        }

        # Check all APIs
        print("[1/6] Email reputation...")
        emailrep = self.check_emailrep(email)
        if emailrep:
            print("\nEMAIL REPUTATION (PureChecker):")
            print(f"   Valid Syntax: {emailrep.get('valid_syntax')}")
            print(f"   Valid Domain: {emailrep.get('valid_domain')}")
            print(f"   Reason: {emailrep.get('reason', 'N/A')}")
            print(f"   Risk Level: {emailrep.get('risk_level', 'N/A')}")
            print(f"   Disposable: {emailrep.get('disposable')}")
            print(f"   Exists: {emailrep.get('exists')}")
            print(f"   Free Provider: {emailrep.get('free')}")
            print(f"   Role: {emailrep.get('role', 'N/A')}")
            print(f"   First Name: {emailrep.get('first_name', '')}")
            print(f"   Last Name: {emailrep.get('last_name', '')}")
            print(f"   MX Records: {[mx['exchange'] for mx in (emailrep.get('mx_records') or [])]}")

        print("[2/6] Social platforms (GitHub, Twitter, etc)...")
        social = self.check_social_platforms(email)
        if social:
            results['social_check'] = social

        print("[3/6] Gravatar profiles...")
        gravatar = self.check_gravatar(email)
        if gravatar:
            results['gravatar'] = gravatar

        print("[4/6] Domain info...")
        domain = self.check_domain(email)
        if domain:
            results['domain'] = domain

        print("[5/6] Email format...")
        fmt = self.check_format(email)
        if fmt:
            results['format'] = fmt

        print("[6/6] Breach check...")
        breach = self.check_breaches(email)
        if breach:
            print(f"\n🔴 BREACH CHECK:")
            print(f"   {breach.get('breached_sites', 0)} breached sites checked by Leak-Lookup.")
            if breach.get('breached_sites', 0) > 0:
                print(f"   (Site names: {', '.join(breach.get('site_names', [])[:10])}...)")  # Print first 10


        # Display results
        print(f"\n{'='*70}")
        print(f"  📊 RESULTS")
        print(f"{'='*70}\n")

        # Email Rep
        if emailrep:
            print(f"📧 EMAIL REPUTATION (EmailRep):")
            print(f"   Reputation: {emailrep.get('reputation', 'N/A')}")
            print(f"   Suspicious: {'Yes ⚠️' if emailrep.get('suspicious') else 'No ✓'}")
            print(f"   DB References: {emailrep.get('references', 0)}")
            if emailrep.get('seen_credentials'):
                print(f"   Credentials in breaches: YES ⚠️")

        # Social Platforms
        if social and social.get('found_profiles'):
            print(f"\n👥 SOCIAL PLATFORMS (Username: {social.get('username')}):")
            if social.get('found_profiles'):
                for profile in social.get('found_profiles'):
                    status = "✓ Found" if profile.get('status') == 'found' else "📌 Potential"
                    print(f"   {status} - {profile['platform']}: {profile['url']}")
            else:
                print(f"   No profiles found for username '{social.get('username')}'")

        # Domain
        if domain:
            print(f"\n🌐 DOMAIN INFO:")
            print(f"   Domain: {domain.get('domain')}")
            print(f"   IP: {domain.get('ip', 'Not resolved')}")
            print(f"   Reachable: {'Yes ✓' if domain.get('reachable') else 'No ❌'}")

        # Format
        if fmt:
            print(f"\n✓ EMAIL FORMAT:")
            print(f"   Valid format: {'Yes ✓' if fmt.get('valid') else 'No ❌'}")
            if fmt.get('has_plus'):
                print(f"   Gmail alias: Yes (+ detected)")

        # Breach
        if breach:
            print(f"\n🔴 BREACH CHECK:")
            if breach.get('found'):
                print(f"   Found in {breach.get('leaks', 0)} breaches")
            else:
                print(f"   No known breaches found ✓")

        # Gravatar
        if gravatar and gravatar.get('found'):
            print(f"\n👤 GRAVATAR PROFILE:")
            if gravatar.get('name'):
                print(f"   Name: {gravatar.get('name')}")
            if gravatar.get('location'):
                print(f"   Location: {gravatar.get('location')}")
            if gravatar.get('social_profiles'):
                print(f"   Social profiles from Gravatar:")
                for profile in gravatar.get('social_profiles'):
                    print(f"     - {profile}")

        print(f"\n{'='*70}")
        print(f"Analysis complete!")
        print(f"{'='*70}\n")

        self.results = results
        return results

    def export(self):
        """Export to JSON"""
        if not self.results:
            return None

        email = self.results['email'].replace('@', '_at_')
        filename = f"email_osint_{email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"✅ Report saved: {filename}\n")
        return filename

def main():

    email = input("\nEnter email to analyze: ").strip()

    if not email:
        print("Error: Email cannot be empty!")
        return

    tool = ImprovedEmailOSINT()
    results = tool.analyze(email)

    if results:
        print("\n" + "="*70)
        print("  📊 RESULTS")
        print("="*70 + "\n")

        # Show PureChecker reputation
        emailrep = results.get('emailrep')
        if emailrep:
            print("\nEMAIL REPUTATION (PureChecker):")
            print(f"   Valid: {emailrep.get('valid', 'N/A')}")
            print(f"   Score: {emailrep.get('score', 'N/A')}")
            print(f"   Reason: {emailrep.get('reason', 'N/A')}")
            print(f"   Risk Level: {emailrep.get('risk_level', 'N/A')}")
            print(f"   Disposable: {emailrep.get('disposable', 'N/A')}")
            print(f"   Role: {emailrep.get('role', 'N/A')}")
            print(f"   MX Record Found: {emailrep.get('mx_found', 'N/A')}")
            print(f"   SMTP Check Passed: {emailrep.get('smtp_check', 'N/A')}")

        # Social platform reporting, domain info, format, etc.
        social = results.get('social_check')
        if social and social.get('found_profiles'):
            print(f"\nSOCIAL PLATFORMS (Username: {social.get('username')}):")
            for profile in social.get('found_profiles'):
                status = "Found" if profile.get('status') == 'found' else "Potential"
                print(f"   {status} - {profile['platform']}: {profile['url']}")
        else:
            print("\nNo social profiles found.")

        domain = results.get('domain')
        if domain:
            print(f"\nDOMAIN INFO:")
            print(f"   Domain: {domain.get('domain')}")
            print(f"   IP: {domain.get('ip', 'Not resolved')}")
            print(f"   Reachable: {'Yes' if domain.get('reachable') else 'No'}")

        fmt = results.get('format')
        if fmt:
            print(f"\nEMAIL FORMAT:")
            print(f"   Valid format: {'Yes' if fmt.get('valid') else 'No'}")
            if fmt.get('has_plus'):
                print(f"   Gmail alias: Yes (+ detected)")

        breach = results.get('breach')
        if breach:
            print(f"\nBREACH CHECK:")
            print(f"   {breach.get('breached_sites', 0)} breached sites checked by Leak-Lookup.")
            site_names = breach.get('site_names', [])
            if site_names:
                print("   (Sample sites: " + ', '.join(site_names[:10]) + "...)")


        gravatar = results.get('gravatar')
        if gravatar and gravatar.get('found'):
            print("\nGRAVATAR PROFILE:")
            if gravatar.get('name'):
                print(f"   Name: {gravatar.get('name')}")
            if gravatar.get('location'):
                print(f"   Location: {gravatar.get('location')}")
            if gravatar.get('social_profiles'):
                print(f"   Social profiles from Gravatar:")
                for profile in gravatar.get('social_profiles'):
                    print(f"     - {profile}")

        # End user/interactivity section
        choice = input("Export to JSON? (y/n): ").strip().lower()
        if choice == 'y':
            tool.export()

        print("✅ Done!\n")


if __name__ == "__main__":
    main()
