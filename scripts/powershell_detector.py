import re

# powershell suspicious activity detector
# scans powershell_log.txt for dangerous commands and recon activity
# based on known attack patterns from lectures

def detect_suspicious_powershell(log_path):
    # keywords that indicate malicious powershell usage
    suspicious_keywords = [
        "-EncodedCommand",
        "-ExecutionPolicy Bypass",
        "Invoke-WebRequest",
        "DownloadString",
        "Invoke-Expression",
        "IEX",
        "-WindowStyle Hidden"
    ]

    # keywords that indicate reconnaissance commands
    recon_keywords = [
        "whoami",
        "ipconfig",
        "net user",
        "net localgroup",
        "systeminfo"
    ]

    results = []

    # read the powershell log file
    with open(log_path, "r") as f:
        lines = f.readlines()

    # go through each line and check for suspicious stuff
    for i in range(len(lines)):
        line = lines[i].strip()

        # skip empty lines and comments
        if line == "" or line.startswith("#"):
            continue

        line_lower = line.lower()

        # check for high severity suspicious keywords first
        for keyword in suspicious_keywords:
            if keyword.lower() in line_lower:
                # figure out the severity
                if "encodedcommand" in line_lower or "executionpolicy bypass" in line_lower:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                results.append({
                    "line_number": i + 1,
                    "command": line,
                    "keyword": keyword,
                    "severity": severity,
                    "type": "suspicious_command"
                })
                break  # only flag once per line

        # check for recon commands
        for keyword in recon_keywords:
            if keyword.lower() in line_lower:
                results.append({
                    "line_number": i + 1,
                    "command": line,
                    "keyword": keyword,
                    "severity": "LOW",
                    "type": "reconnaissance"
                })
                break  # only flag once per line

    return results


# test the detector if we run this file directly
if __name__ == "__main__":
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    log_path = os.path.join(project_dir, "ProjectDataset", "powershell_log.txt")

    print("=== PowerShell Suspicious Activity Test ===")
    results = detect_suspicious_powershell(log_path)
    print("Found %d suspicious events\n" % len(results))

    for r in results:
        print("[%s] Line %d: %s" % (r["severity"], r["line_number"], r["keyword"]))
        print("  Command: %s\n" % r["command"])
