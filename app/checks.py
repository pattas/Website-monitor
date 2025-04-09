import socket
import ssl
import whois
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ipwhois import IPWhois
import dns.resolver
import subprocess
import platform

def get_ssl_expiry(hostname: str) -> Optional[datetime]:
    """Gets the SSL certificate expiry date for a given hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                # Use not_valid_after (returns naive datetime in UTC)
                return cert.not_valid_after
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError) as e:
        print(f"SSL check failed for {hostname}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error during SSL check for {hostname}: {e}")
        return None

def get_domain_expiry(domain: str) -> Optional[datetime]:
    """Gets the domain expiry date using python-whois. Converts to naive UTC."""
    try:
        # Add timeout to whois query
        w = whois.whois(domain)
        exp_dates = w.expiration_date
        if not exp_dates:
            return None

        # Ensure we have a list
        if not isinstance(exp_dates, list):
            exp_dates = [exp_dates]

        naive_utc_dates = []
        for dt in exp_dates:
            if isinstance(dt, datetime):
                if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
                    # Convert aware datetime to UTC, then make naive
                    naive_utc_dates.append(dt.astimezone(timezone.utc).replace(tzinfo=None))
                else:
                    # Assume naive datetime is already UTC (or close enough)
                    naive_utc_dates.append(dt)

        # Return the earliest valid date
        return min(naive_utc_dates) if naive_utc_dates else None

    except whois.parser.PywhoisError as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        return None
    except socket.timeout:
        print(f"WHOIS lookup timed out for {domain}")
        return None
    except Exception as e:
        print(f"Unexpected error during WHOIS lookup for {domain}: {e}")
        return None

def run_advanced_checks_for_url(url_obj):
    """Runs SSL and Domain expiry checks for a MonitoredURL object and updates its fields.
       Returns True if data was updated, False otherwise.
    """
    print(f"Running advanced checks for {url_obj.url}...")
    updated = False
    parsed_url = urlparse(url_obj.url)
    hostname = parsed_url.netloc
    # Basic domain extraction - might fail for complex TLDs like .co.uk
    parts = hostname.split('.')
    domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    # --- Check SSL Expiry (only for https) ---
    new_ssl_expiry = None
    if parsed_url.scheme == 'https':
        new_ssl_expiry = get_ssl_expiry(hostname)
        if new_ssl_expiry:
            print(f"  SSL Expiry for {hostname}: {new_ssl_expiry}")
            if url_obj.ssl_expiry_date != new_ssl_expiry:
                 url_obj.ssl_expiry_date = new_ssl_expiry
                 updated = True
        else:
             print(f"  SSL Check failed for {hostname}")
             # Decide if failure should clear the date
             # if url_obj.ssl_expiry_date is not None:
             #    url_obj.ssl_expiry_date = None
             #    updated = True
    elif url_obj.ssl_expiry_date is not None:
        # Clear date if URL is no longer HTTPS
        url_obj.ssl_expiry_date = None
        updated = True

    # --- Check Domain Expiry ---
    new_domain_expiry = get_domain_expiry(domain)
    if new_domain_expiry:
        print(f"  Domain Expiry for {domain}: {new_domain_expiry}")
        if url_obj.domain_expiry_date != new_domain_expiry:
            url_obj.domain_expiry_date = new_domain_expiry
            updated = True
    else:
        print(f"  Domain Check failed for {domain}")
        # Decide if failure should clear the date
        # if url_obj.domain_expiry_date is not None:
        #     url_obj.domain_expiry_date = None
        #     updated = True

    if updated:
        url_obj.last_advanced_check = datetime.now(timezone.utc)

    return updated

# --- New Functions for Full Scan ---

def get_ip_address(hostname: str) -> Optional[str]:
    """Gets the primary IP address for a hostname."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_rdap_info(ip_address: str) -> Optional[Dict[str, Any]]:
    """Gets RDAP information for an IP address."""
    if not ip_address:
        return None
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)
        return results
    except Exception as e:
        print(f"RDAP lookup failed for {ip_address}: {e}")
        return None

def get_dns_records(hostname: str) -> Dict[str, List[str]]:
    """Gets common DNS records for a hostname."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for record_type in record_types:
        try:
            answers = resolver.resolve(hostname, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            records[record_type] = [] # Record not found or error
        except Exception as e:
            print(f"DNS lookup for {record_type} failed for {hostname}: {e}")
            records[record_type] = [f"Error: {e}"]
    return records

def run_traceroute(hostname: str) -> str:
    """Runs traceroute/tracert command and returns the output."""
    command = []
    system = platform.system()

    if system == "Windows":
        command = ["tracert", "-d", "-w", "1000", hostname] # -d avoids resolving names, -w 1sec timeout
    elif system == "Linux":
        # Use -q 1 to send only one probe per hop, -w 1 for 1sec wait, -n to avoid resolving names
        command = ["traceroute", "-q", "1", "-w", "1", "-n", hostname]
    elif system == "Darwin": # macOS
        command = ["traceroute", "-q", "1", "-w", "1", "-n", hostname]
    else:
        return f"Traceroute command not available for system: {system}"

    try:
        # Run the command with a timeout (e.g., 30 seconds)
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            return f"Traceroute command failed (Exit Code: {result.returncode}):\n{result.stderr}"
        return result.stdout
    except FileNotFoundError:
        return f"Error: '{command[0]}' command not found. Please install it."
    except subprocess.TimeoutExpired:
        return "Error: Traceroute command timed out."
    except Exception as e:
        return f"Error running traceroute: {e}" 