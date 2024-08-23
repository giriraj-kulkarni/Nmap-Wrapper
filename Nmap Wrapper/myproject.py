import argparse
import nmap
from jinja2 import Template

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automated Network Scanner")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("-s", "--scan", choices=["basic", "advanced"], default="basic",
                        help="Type of scan to perform (default: basic)")
    parser.add_argument("-o", "--output", help="Output file for the results", default="scan_results.txt")
    return parser.parse_args()

def run_basic_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sS")
    return nm

def run_advanced_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV -A")
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

def generate_html_report(parsed_data, output_file):
    template = Template("""
    <html>
    <head><title>Nmap Scan Report</title></head>
    <body>
    <h1>Nmap Scan Report</h1>
    <table border="1">
    <tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service Name</th><th>Product</th></tr>
    {% for service in services %}
    <tr>
        <td>{{ service.host }}</td>
        <td>{{ service.port }}</td>
        <td>{{ service.protocol }}</td>
        <td>{{ service.name }}</td>
        <td>{{ service.product }}</td>
    </tr>
    {% endfor %}
    </table>
    </body>
    </html>
    """)
    with open(output_file, 'w') as f:
        f.write(template.render(services=parsed_data))

if __name__ == "__main__":
    args = parse_arguments()

    if args.scan == "basic":
        scan_result = run_basic_scan(args.target)
    elif args.scan == "advanced":
        scan_result = run_advanced_scan(args.target)
    
    # Parse the scan results
    parsed_data = parse_nmap_results(scan_result)
    
    # Save the parsed results to a text file
    with open(args.output, "w") as f:
        for service in parsed_data:
            f.write(f"{service['host']}:{service['port']} - {service['protocol']} - {service['name']} - {service['state']} - {service['product']}\n")
    
    # Generate an HTML report
    generate_html_report(parsed_data, "scan_report.html")
    print(f"Scan complete. Report saved to scan_report.html")
