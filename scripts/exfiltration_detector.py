import re

# data exfiltration detector
# looks for signs that someone created an archive (zip/tar/rar)
# and then uploaded it somewhere - thats a classic exfiltration pattern

def detect_exfiltration(log_path):
    # keywords that suggest creating an archive
    archive_keywords = ["compress-archive", ".zip", ".tar", ".rar", ".7z"]

    # keywords that suggest uploading data
    upload_keywords = ["upload", "invoke-webrequest", "curl", "wget", "send-mailmessage"]

    # store what we find
    archive_events = []
    upload_events = []

    # read the powershell log
    with open(log_path, "r") as f:
        lines = f.readlines()

    for i in range(len(lines)):
        line = lines[i].strip()

        # skip empty lines and comments
        if line == "" or line.startswith("#"):
            continue

        line_lower = line.lower()

        # check for archive creation
        for keyword in archive_keywords:
            if keyword in line_lower:
                archive_events.append({
                    "line_number": i + 1,
                    "command": line,
                    "keyword": keyword
                })
                break

        # check for upload activity
        for keyword in upload_keywords:
            if keyword in line_lower:
                upload_events.append({
                    "line_number": i + 1,
                    "command": line,
                    "keyword": keyword
                })
                break

    # determine if exfiltration pattern exists
    # archive creation should happen BEFORE upload
    exfil_detected = False

    if len(archive_events) > 0 and len(upload_events) > 0:
        # check if any archive event comes before any upload event
        earliest_archive = archive_events[0]["line_number"]
        latest_upload = upload_events[-1]["line_number"]

        if earliest_archive < latest_upload:
            exfil_detected = True

    # figure out severity
    if exfil_detected:
        severity = "HIGH"
    elif len(upload_events) > 0:
        severity = "MEDIUM"
    elif len(archive_events) > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "exfil_detected": exfil_detected,
        "severity": severity,
        "archive_events": archive_events,
        "upload_events": upload_events
    }


# test the detector if we run this file directly
if __name__ == "__main__":
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    log_path = os.path.join(project_dir, "ProjectDataset", "powershell_log.txt")

    print("=== Exfiltration Detection Test ===")
    results = detect_exfiltration(log_path)

    print("Exfiltration detected: %s" % str(results["exfil_detected"]))
    print("Severity: %s\n" % results["severity"])

    print("Archive events: %d" % len(results["archive_events"]))
    for e in results["archive_events"]:
        print("  Line %d: %s" % (e["line_number"], e["command"]))

    print("\nUpload events: %d" % len(results["upload_events"]))
    for e in results["upload_events"]:
        print("  Line %d: %s" % (e["line_number"], e["command"]))
