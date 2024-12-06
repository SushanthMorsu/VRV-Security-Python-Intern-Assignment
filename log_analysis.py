
## VRV Security's Python Intern Assignment

# Importing Libraries
import re
import csv
from collections import Counter

# Path to Files
log_file = "sample.log"
output_file = "log_analysis_results.csv"


### Parsing the log file and extracting information

# Function to Parse Log File
def parse_log_file(log_file):
    log_entries = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+).+?"(GET|POST) (.+?) HTTP.+?" (\d+)', line)
            if match:
                ip, method, endpoint, status_code = match.groups()
                log_entries.append({
                    "IP" : ip,
                    "Endpoint" : endpoint,
                    "Status_Code" : status_code,
                })
    return log_entries


### Count Requests per IP Address

# Function to Count Requests per IP Address
def count_requests_per_ip(log_entries):
    ip_counter = Counter(entry["IP"] for entry in log_entries)
    return ip_counter.most_common()


### Most Frequently Accessed Endpoint

# Function to Identify Most Frequently Accessed Endpoint
def most_accessed_endpoint(log_entries):
    endpoint_counter = Counter(entry["Endpoint"] for entry in log_entries)
    return endpoint_counter.most_common(1)[0]


### Detect Suspicious Activity

# Function to Detect Suspicious Activity
def detect_suspicious_activity(log_entries, threshold = 10):
    failed_attempts = Counter(entry["IP"] for entry in log_entries if entry["Status_Code"] == 401 or 'Invalid credentials')
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips


### Output Results

# Saving Results to CSV
def save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file = "log_analysis_results.csv"):
    with open(output_file, 'w', newline  = '') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request count"])
        for ip, count in ip_counts:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


### Main Function

def main():
    log_entries = parse_log_file(log_file)

    # Count Requests per IP
    ip_counts = count_requests_per_ip(log_entries)
    print("IP Address       Request Count")
    for ip, count in ip_counts:
        print(f"{ip:20} {count}")

    # Most Frequently Accessed Endpoint
    most_accessed = most_accessed_endpoint(log_entries)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect Suspicious Activity
    suspicious_ips = detect_suspicious_activity(log_entries)

    if suspicious_ips:  # Check if there are any suspicious IPs
        print("\nSuspicious Activity Detected:")
        print("IP Address       Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:20} {count}")
    else:
        print("\nNo Suspicious Activity Detected.")


    # Output Results
    save_to_csv(ip_counts, most_accessed, suspicious_ips)

if __name__ == "__main__":
    main()


