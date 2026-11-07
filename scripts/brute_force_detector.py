import re

# brute force detection script
# looks for repeated failed SSH login attempts in auth.log
# if an IP has 5 or more failed attempts, it gets flagged

def detect_brute_force(log_path):
    # dictionary to count failed attempts per IP
    failed_counts = {}

    # open the auth log and read line by line
    with open(log_path, "r") as f:
        for line in f:
            # first check for "message repeated X times" lines
            # these show up when sshd logs the same failure multiple times
            # we need to check this BEFORE the normal pattern so we dont double count
            repeated_match = re.search(
                r"message repeated (\d+) times:.+Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
                line
            )

            if repeated_match:
                # get how many times it repeated and the IP address
                times = int(repeated_match.group(1))
                ip = repeated_match.group(2)

                # add the count to our dictionary
                if ip in failed_counts:
                    failed_counts[ip] = failed_counts[ip] + times
                else:
                    failed_counts[ip] = times

            else:
                # check for normal "Failed password" lines
                failed_match = re.search(
                    r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
                    line
                )

                if failed_match:
                    ip = failed_match.group(1)

                    if ip in failed_counts:
                        failed_counts[ip] = failed_counts[ip] + 1
                    else:
                        failed_counts[ip] = 1

    # now filter out IPs that have 5 or more failed attempts
    results = []

    for ip in failed_counts:
        count = failed_counts[ip]

        if count >= 5:
            # assign severity based on how many attempts
            if count >= 20:
                severity = "HIGH"
            elif count >= 10:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            results.append({
                "ip": ip,
                "count": count,
                "severity": severity
            })

    # sort by count so the worst offenders are first
    results.sort(key=lambda x: x["count"], reverse=True)

    return results


# test the detector if we run this file directly
if __name__ == "__main__":
    import os
    # go up one folder to find ProjectDataset
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    log_path = os.path.join(project_dir, "ProjectDataset", "auth.log")

    print("=== Brute Force Detection Test ===")
    results = detect_brute_force(log_path)
    print("Found %d IPs with 5+ failed attempts\n" % len(results))

    for r in results:
        print("[%s] IP: %s - %d failed attempts" % (r["severity"], r["ip"], r["count"]))
