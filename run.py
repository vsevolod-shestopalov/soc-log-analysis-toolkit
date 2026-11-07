import os
import sys
import datetime

# Security Investigation Tool - main script
# runs all detectors and generates the investigation report
# Student: B00170627, TU Dublin

# add the scripts folder so we can import our modules
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, "scripts"))

from brute_force_detector import detect_brute_force
from powershell_detector import detect_suspicious_powershell
from ioc_matcher import load_iocs, match_iocs
from exfiltration_detector import detect_exfiltration


def generate_report(report_path, brute_results, ps_results, ioc_results, exfil_results):
    # get current timestamp for the report header
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # figure out the overall risk level
    overall_risk = "LOW"

    # check brute force results
    for r in brute_results:
        if r["severity"] == "HIGH":
            overall_risk = "HIGH"
        elif r["severity"] == "MEDIUM" and overall_risk != "HIGH":
            overall_risk = "MEDIUM"

    # check powershell results
    for r in ps_results:
        if r["severity"] == "HIGH":
            overall_risk = "HIGH"
        elif r["severity"] == "MEDIUM" and overall_risk != "HIGH":
            overall_risk = "MEDIUM"

    # check IOC results
    if len(ioc_results["ip_matches"]) > 0 or len(ioc_results["path_matches"]) > 0:
        overall_risk = "HIGH"

    # check exfiltration results
    if exfil_results["exfil_detected"]:
        overall_risk = "HIGH"

    # write the report to file
    with open(report_path, "w") as report:

        # ---- HEADER ----
        report.write("=" * 60 + "\n")
        report.write("        SECURITY INVESTIGATION REPORT\n")
        report.write("=" * 60 + "\n")
        report.write("Date: %s\n" % now)
        report.write("Tool: Security Investigation Tool v1.0\n")
        report.write("Student: B00170627\n")
        report.write("Module: Advanced Scripting for Cybersecurity\n")
        report.write("=" * 60 + "\n\n")

        # ---- EXECUTIVE SUMMARY ----
        report.write("-" * 60 + "\n")
        report.write("EXECUTIVE SUMMARY\n")
        report.write("-" * 60 + "\n\n")

        report.write("Brute Force Attacks:      %d IPs flagged\n" % len(brute_results))
        report.write("Suspicious PowerShell:    %d events detected\n" % len(ps_results))

        total_ioc = len(ioc_results["ip_matches"]) + len(ioc_results["path_matches"])
        report.write("IOC Matches:              %d matches found\n" % total_ioc)

        if exfil_results["exfil_detected"]:
            report.write("Data Exfiltration:        DETECTED\n")
        else:
            report.write("Data Exfiltration:        Not detected\n")

        report.write("\nOverall Risk Level:       [%s]\n\n" % overall_risk)

        # ---- SECTION 1: BRUTE FORCE ----
        report.write("=" * 60 + "\n")
        report.write("SECTION 1: BRUTE FORCE DETECTION\n")
        report.write("=" * 60 + "\n")
        report.write("Source: auth.log\n")
        report.write("Threshold: 5+ failed login attempts from same IP\n")
        report.write("Severity: HIGH (20+), MEDIUM (10-19), LOW (5-9)\n\n")

        if len(brute_results) == 0:
            report.write("No brute force attacks detected.\n\n")
        else:
            for r in brute_results:
                report.write("[%s] IP: %s\n" % (r["severity"], r["ip"]))
                report.write("  Failed attempts: %d\n\n" % r["count"])

        # ---- SECTION 2: SUSPICIOUS POWERSHELL ----
        report.write("=" * 60 + "\n")
        report.write("SECTION 2: SUSPICIOUS POWERSHELL ACTIVITY\n")
        report.write("=" * 60 + "\n")
        report.write("Source: powershell_log.txt\n")
        report.write("Detection: Keyword matching for known attack patterns\n\n")

        if len(ps_results) == 0:
            report.write("No suspicious PowerShell activity detected.\n\n")
        else:
            for r in ps_results:
                report.write("[%s] Line %d - %s\n" % (r["severity"], r["line_number"], r["type"]))
                report.write("  Matched keyword: %s\n" % r["keyword"])
                report.write("  Command: %s\n\n" % r["command"])

        # ---- SECTION 3: IOC MATCHING ----
        report.write("=" * 60 + "\n")
        report.write("SECTION 3: IOC (INDICATORS OF COMPROMISE) MATCHING\n")
        report.write("=" * 60 + "\n")
        report.write("Source: ioc.txt cross-checked against access.log, auth.log\n\n")

        # IP matches
        report.write("--- Malicious IP Matches ---\n")
        if len(ioc_results["ip_matches"]) == 0:
            report.write("No malicious IP matches found.\n\n")
        else:
            for m in ioc_results["ip_matches"]:
                report.write("[%s] IP: %s found in %s (line %d)\n" % (
                    m["severity"], m["ip"], m["log_source"], m["line_number"]
                ))
                report.write("  Detail: %s\n\n" % m["detail"])

        # path matches
        report.write("--- Malicious Path Matches ---\n")
        if len(ioc_results["path_matches"]) == 0:
            report.write("No malicious path matches found.\n\n")
        else:
            for m in ioc_results["path_matches"]:
                report.write("[%s] Path: %s (matched IOC: %s)\n" % (
                    m["severity"], m["path"], m["ioc_path"]
                ))
                report.write("  From IP: %s in %s (line %d)\n\n" % (
                    m["ip"], m["log_source"], m["line_number"]
                ))

        # ---- SECTION 4: DATA EXFILTRATION ----
        report.write("=" * 60 + "\n")
        report.write("SECTION 4: DATA EXFILTRATION DETECTION\n")
        report.write("=" * 60 + "\n")
        report.write("Source: powershell_log.txt\n")
        report.write("Detection: Archive creation followed by network upload\n\n")

        if exfil_results["severity"] == "NONE":
            report.write("No exfiltration indicators found.\n\n")
        else:
            report.write("Exfiltration Pattern: %s\n" % (
                "CONFIRMED" if exfil_results["exfil_detected"] else "PARTIAL"
            ))
            report.write("Severity: [%s]\n\n" % exfil_results["severity"])

            report.write("Archive creation events:\n")
            for e in exfil_results["archive_events"]:
                report.write("  Line %d: %s\n" % (e["line_number"], e["command"]))

            report.write("\nUpload/transfer events:\n")
            for e in exfil_results["upload_events"]:
                report.write("  Line %d: %s\n" % (e["line_number"], e["command"]))

            report.write("\n")

        # ---- FOOTER ----
        report.write("=" * 60 + "\n")
        report.write("END OF REPORT\n")
        report.write("=" * 60 + "\n")


def main():

    # set up file paths
    dataset_dir = os.path.join(script_dir, "ProjectDataset")
    access_log = os.path.join(dataset_dir, "access.log")
    auth_log = os.path.join(dataset_dir, "auth.log")
    powershell_log = os.path.join(dataset_dir, "powershell_log.txt")
    ioc_file = os.path.join(dataset_dir, "ioc.txt")
    report_path = os.path.join(script_dir, "investigation_report.txt")

    # check that the dataset files exist
    for path in [access_log, auth_log, powershell_log, ioc_file]:
        if not os.path.exists(path):
            print("[ERROR] File not found: %s" % path)
            print("Make sure the ProjectDataset folder is in the same directory as run.py")
            sys.exit(1)

    # --- run detection 1: brute force ---
    print("[*] Running brute force detection on auth.log...")
    brute_results = detect_brute_force(auth_log)
    print("    Found %d IPs with suspicious login attempts" % len(brute_results))

    # --- run detection 2: suspicious powershell ---
    print("[*] Running PowerShell analysis on powershell_log.txt...")
    ps_results = detect_suspicious_powershell(powershell_log)
    print("    Found %d suspicious events" % len(ps_results))

    # --- run detection 3: IOC matching ---
    print("[*] Loading IOCs from ioc.txt...")
    ioc_ips, ioc_paths = load_iocs(ioc_file)
    print("    Loaded %d malicious IPs and %d malicious paths" % (len(ioc_ips), len(ioc_paths)))

    print("[*] Matching IOCs against access.log and auth.log...")
    ioc_results = match_iocs(access_log, auth_log, ioc_ips, ioc_paths)
    total_ioc = len(ioc_results["ip_matches"]) + len(ioc_results["path_matches"])
    print("    Found %d IOC matches" % total_ioc)

    # --- run detection 4: exfiltration ---
    print("[*] Running exfiltration detection on powershell_log.txt...")
    exfil_results = detect_exfiltration(powershell_log)
    if exfil_results["exfil_detected"]:
        print("    WARNING: Data exfiltration pattern detected!")
    else:
        print("    No exfiltration pattern found")

    # --- generate the report ---
    print("\n[*] Generating investigation report...")
    generate_report(report_path, brute_results, ps_results, ioc_results, exfil_results)
    print("[+] Report saved to: %s" % report_path)

    print("\n" + "=" * 50)
    print("  Investigation complete!")
    print("=" * 50)


# run the main function
if __name__ == "__main__":
    main()
