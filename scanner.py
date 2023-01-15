import socket
import json
import requests
import dns.resolver

# Target domain
target = "sariyam.com"

# Get IP addresses for target domain
ip_addresses = []
try:
    ip_addresses = [ip for ip in socket.gethostbyname_ex(target)[2]]
except:
    pass

# Get subdomains for target domain
subdomains = []
try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    subdomains = resolver.query(target, 'NS')
except:
    pass

# Get open ports for target IP addresses
open_ports = []
for ip in ip_addresses:
    for port in range(1, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

# Get DNS records for target domain
dns_records = {}
try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    dns_records["A"] = [a.address for a in resolver.query(target, 'A')]
    dns_records["MX"] = [mx.exchange for mx in resolver.query(target, 'MX')]
    dns_records["NS"] = [ns.target for ns in resolver.query(target, 'NS')]
    dns_records["SOA"] = [soa.mname for soa in resolver.query(target, 'SOA')]
except:
    pass

# Get WHOIS information for target domain
whois = {}
try:
    whois_url = "https://whois.domaintools.com/"+target+".json"
    response = requests.get(whois_url)
    whois = json.loads(response.text)
except:
    pass

# Print gathered information
print("IP addresses: ", ip_addresses)
print("Subdomains: ", subdomains)
print("Open ports: ", open_ports)
print("DNS records: ", dns_records)
print("WHOIS information: ", whois)

