import argparse
import nmap
from jinja2 import Template

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automated Network Scanner")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("-s", "--scan", choices=["basic", "advanced", "stealth"], default="basic",
                        help="Type of scan to perform (default: basic)")
    parser.add_argument("-o", "--output", help="Output file for the results", default="scan_results.txt")
    return parser.parse_args()

def run_basic_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sS")
    return nm

def run_advanced_scan(target):
    nm = nmap.PortScanner()
    # Advanced scan with version detection and OS detection
    nm.scan(target, arguments="-sV -A")
    return nm

def run_stealth_scan(target):
    nm = nmap.PortScanner()
    # Stealth scan with various evasion techniques
    nm.scan(target, arguments="-sS -f -D RND:10 --randomize-hosts -T2 --source-port 53")
    return nm

def enumerate_services(scan_result):
    services = []
    for host in scan_result.all_hosts():
        for proto in scan_result[host].all_protocols():
            ports = scan_result[host][proto].keys()
            for port in ports:
                service = {
                    "host": host,
                    "port": port,
                    "name": scan_result[host][proto][port]['name'],
                    "state": scan_result[host][proto][port]['state'],
                    "product": scan_result[host][proto][port].get('product', '')
                }
                services.append(service)
    return services

def parse_nmap_results(scan_result):
    parsed_data = []
    for host in scan_result.all_hosts():
        for proto in scan_result[host].all_protocols():
            for port in scan_result[host][proto].keys():
                service = {
                    'host': host,
                    'port': port,
                    'protocol': proto,
                    'name': scan_result[host][proto][port]['name'],
                    'state': scan_result[host][proto][port]['state'],
                    'product': scan_result[host][proto][port].get('product', '')
                }
                parsed_data.append(service)
    return parsed_data

def generate_text_report(parsed_data, output_file):
    with open(output_file, 'w') as f:
        f.write("Nmap Scan Report\n")
        f.write("================\n\n")
        for service in parsed_data:
            f.write(f"Host: {service['host']}\n")
            f.write(f"Port: {service['port']}\n")
            f.write(f"Protocol: {service['protocol']}\n")
            f.write(f"Service Name: {service['name']}\n")
            f.write(f"Product: {service['product']}\n")
            f.write(f"State: {service['state']}\n")
            f.write("----------------------\n")

if __name__ == "__main__":
    args = parse_arguments()

    if args.scan == "basic":
        scan_result = run_basic_scan(args.target)
    elif args.scan == "advanced":
        scan_result = run_advanced_scan(args.target)
    elif args.scan == "stealth":
        scan_result = run_stealth_scan(args.target)
    
    # Parse the scan results
    parsed_data = parse_nmap_results(scan_result)
    
    # Save the parsed results to a text file
    with open(args.output, "w") as f:
        for service in parsed_data:
            f.write(f"{service['host']}:{service['port']} - {service['protocol']} - {service['name']} - {service['state']} - {service['product']}\n")
    
    # Generate a text report
    generate_text_report(parsed_data, args.output)
    print(f"Scan complete. Report saved to {args.output}")
