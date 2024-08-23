Overview
This project is an Automated Network Scanner designed to perform basic and advanced network scans using Nmap. It leverages Python's nmap module for network scanning and jinja2 for generating HTML reports.

Features
Basic Scan: Performs a SYN scan to identify open ports on the target.
Advanced Scan: Executes a version detection scan and aggressive scan for detailed information about services and hosts.
HTML Report Generation: Creates a formatted HTML report of the scan results.
Text Report Output: Saves scan results in a text file.
Requirements
Python 3.x
Nmap: Ensure that Nmap is installed and accessible in your system's PATH.
Python Packages: python-nmap, jinja2













Run the script with the desired options:

python myproject.py <target> -s <scan_type> -o <output_file>
