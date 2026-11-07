import re

# IOC (Indicators of Compromise) matching script
# loads malicious IPs and paths from ioc.txt
# then checks access.log and auth.log for matches

def load_iocs(ioc_path):
    # lists to store the IOCs we find
    ioc_ips = []
    ioc_paths = []

    # read the ioc file
    with open(ioc_path, "r") as f:
        for line in f:
            line = line.strip()

            # skip empty lines and comments
            if line == "" or line.startswith("#"):
                continue

            # check if it looks like an IP address
            ip_match = re.match(r"^\d+\.\d+\.\d+\.\d+$", line)
            if ip_match:
                ioc_ips.append(line)
            # check if it looks like a web path
            elif line.startswith("/"):
                ioc_paths.append(line)

    return ioc_ips, ioc_paths


def match_iocs(access_log_path, auth_log_path, ioc_ips, ioc_paths):
    # store all our matches here
    ip_matches = []
    path_matches = []

    # --- scan access.log for IOC IPs and paths ---
    with open(access_log_path, "r") as f:
        line_num = 0
        for line in f:
            line_num = line_num + 1
            line = line.strip()

            if line == "":
                continue

            # get the IP address (first thing in the line)
            parts = line.split()
            if len(parts) < 1:
                continue
            ip = parts[0]

            # try to get the requested path from the log entry
            # format is like: "GET /path HTTP/1.1"
            path_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD) (\S+)', line)
            request_path = ""
            if path_match:
                request_path = path_match.group(1)

            # check if the IP is in our IOC list
            if ip in ioc_ips:
                ip_matches.append({
                    "ip": ip,
                    "line_number": line_num,
                    "log_source": "access.log",
                    "detail": line[:200],  # keep first 200 chars so its not too long
                    "severity": "HIGH"
                })

            # check if the requested path matches any IOC path
            if request_path != "":
                for ioc_path in ioc_paths:
                    # check for exact match or if path starts with the IOC path
                    if request_path == ioc_path or request_path.startswith(ioc_path + "/"):
                        path_matches.append({
                            "path": request_path,
                            "ioc_path": ioc_path,
                            "ip": ip,
                            "line_number": line_num,
                            "log_source": "access.log",
                            "severity": "HIGH"
                        })
                        break  # dont match same line twice

    # --- scan auth.log for IOC IPs ---
    with open(auth_log_path, "r") as f:
        line_num = 0
        for line in f:
            line_num = line_num + 1

            # check if any IOC IP appears in this line
            for ioc_ip in ioc_ips:
                if ioc_ip in line:
                    ip_matches.append({
                        "ip": ioc_ip,
                        "line_number": line_num,
                        "log_source": "auth.log",
                        "detail": line.strip()[:200],
                        "severity": "HIGH"
                    })

    return {
        "ip_matches": ip_matches,
        "path_matches": path_matches
    }


# test the IOC matcher if we run this file directly
if __name__ == "__main__":
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    dataset_dir = os.path.join(project_dir, "ProjectDataset")

    ioc_path = os.path.join(dataset_dir, "ioc.txt")
    access_log = os.path.join(dataset_dir, "access.log")
    auth_log = os.path.join(dataset_dir, "auth.log")

    print("=== IOC Matching Test ===")

    # load the IOCs first
    ioc_ips, ioc_paths = load_iocs(ioc_path)
    print("Loaded %d malicious IPs: %s" % (len(ioc_ips), str(ioc_ips)))
    print("Loaded %d malicious paths: %s\n" % (len(ioc_paths), str(ioc_paths)))

    # run the matching
    results = match_iocs(access_log, auth_log, ioc_ips, ioc_paths)

    print("IP matches found: %d" % len(results["ip_matches"]))
    for m in results["ip_matches"]:
        print("  [%s] %s in %s (line %d)" % (m["severity"], m["ip"], m["log_source"], m["line_number"]))

    print("\nPath matches found: %d" % len(results["path_matches"]))
    for m in results["path_matches"]:
        print("  [%s] %s matched IOC %s (line %d)" % (m["severity"], m["path"], m["ioc_path"], m["line_number"]))
