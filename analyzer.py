
import sys
import ipaddress
import csv
from datetime import datetime


# Phase 1: Analyze the log file
def analyze_logs(log_file):
    ip_count = {}
    username_count = {}
    success_count = 0
    failed_count = 0
    total_lines = 0

    with open(log_file, "r") as file:
        for line in file:
            total_lines += 1
            words = line.split()

            if "Failed" in line:
                failed_count += 1

                for i in range(len(words) - 1):
                    if words[i] == "from":
                        ip = words[i + 1]

                        try:
                            ipaddress.IPv4Address(ip)
                            ip_count[ip] = ip_count.get(ip, 0) + 1
                        except ipaddress.AddressValueError:
                            print(f"Skipping invalid IP address: {ip}")

                    if words[i] == "for":
                        username = words[i + 1]
                        username_count[username] = (
                            username_count.get(username, 0) + 1
                        )

            elif "Accepted" in line:
                success_count += 1

    return (
        ip_count,
        username_count,
        success_count,
        failed_count,
        total_lines
    )


# Phase 2: Find the IP with the highest number of failures
def find_top_ip(ip_count):
    if not ip_count:
        return None, 0

    top_ip = max(ip_count, key=ip_count.get)
    return top_ip, ip_count[top_ip]


# Phase 3: Save suspicious IP addresses
def save_suspicious_ips(ip_count, threshold):
    suspicious_count = 0

    with open("suspicious_ips.txt", "w") as file:
        file.write("===== SUSPICIOUS IP ADDRESSES =====\n")
        file.write(f"Alert threshold: {threshold}\n\n")

        for ip, count in sorted(
            ip_count.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            if count >= threshold:
                file.write(f"IP Address: {ip}\n")
                file.write(f"Failed Attempts: {count}\n")
                file.write("Status: Suspicious activity\n\n")
                suspicious_count += 1

        if suspicious_count == 0:
            file.write("No IP addresses reached the threshold.\n")

    print(f"Suspicious IP addresses detected: {suspicious_count}")
    print("Suspicious IP report saved to suspicious_ips.txt")


# Phase 4: Export results to CSV
def export_csv(ip_count, username_count):
    with open("security_report.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Category", "Value", "Failed Attempts"])

        for ip, count in sorted(
            ip_count.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            writer.writerow(["IP Address", ip, count])

        for username, count in sorted(
            username_count.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            writer.writerow(["Username", username, count])

    print("CSV report saved to security_report.csv")


# Phase 5: Generate the main security report
def generate_report(
    ip_count,
    username_count,
    success_count,
    failed_count,
    total_lines,
    top_ip,
    top_count,
    threshold
):
    current_time = datetime.now()
    total_logins = success_count + failed_count

    if total_logins > 0:
        failure_percentage = (failed_count / total_logins) * 100
    else:
        failure_percentage = 0

    if any(count >= threshold for count in ip_count.values()):
        security_status = "REVIEW REQUIRED"
    else:
        security_status = "NORMAL"

    with open("report.txt", "w") as report:
        report.write("===== SECURITY LOG REPORT =====\n")
        report.write(f"Report Generated: {current_time}\n")
        report.write(f"Security Status: {security_status}\n\n")

        report.write(f"Total Log Lines: {total_lines}\n")
        report.write(f"Successful Logins: {success_count}\n")
        report.write(f"Failed Logins: {failed_count}\n")
        report.write(f"Total Login Events: {total_logins}\n")
        report.write(f"Failure Percentage: {failure_percentage:.2f}%\n\n")

        report.write("Failed Login Attempts by IP:\n")

        for ip, count in sorted(
            ip_count.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            report.write(f"{ip} -> {count} attempts\n")

            if count >= threshold:
                report.write("WARNING: Possible brute-force activity\n")

        report.write("\nFailed Attempts by Username:\n")

        for username, count in sorted(
            username_count.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            report.write(f"{username} -> {count} attempts\n")

        report.write("\n")
        report.write(f"IP with highest failed attempts: {top_ip}\n")
        report.write(f"Number of attempts: {top_count}\n")


# Phase 6: Read command-line arguments

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 analyzer.py <logfile> [threshold]")
        return 1

    log_file = sys.argv[1]
    threshold = 5

    if len(sys.argv) == 3:
        try:
            threshold = int(sys.argv[2])

            if threshold < 1:
                print("Error: Threshold must be at least 1.")
                return 1

        except ValueError:
            print("Error: Threshold must be a number.")
            return 1

    try:
        (
            ip_count,
            username_count,
            success_count,
            failed_count,
            total_lines
        ) = analyze_logs(log_file)

        top_ip, top_count = find_top_ip(ip_count)

        save_suspicious_ips(ip_count, threshold)
        export_csv(ip_count, username_count)

        generate_report(
            ip_count,
            username_count,
            success_count,
            failed_count,
            total_lines,
            top_ip,
            top_count,
            threshold
        )

        print("\nAnalysis complete.")
        print("Report saved to report.txt")

        with open("report.txt", "r") as report:
            print(report.read())

    except FileNotFoundError:
        print(f"Error: The file '{log_file}' was not found.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())


