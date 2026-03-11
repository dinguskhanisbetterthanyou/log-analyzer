import re
from datetime import datetime
from collections import defaultdict

LOG_FILE = "auth.log"
FAIL_THRESHOLD = 5
OFF_HOURS_START = 0
OFF_HOURS_END = 6
REPORT_FILE = "report.html"

failed_attempts = defaultdict(list)
off_hours_logins = []
targeted_users = defaultdict(int)

print("Reading log file...")

try:
    with open(LOG_FILE, "r") as f:
        for line in f:
            if "Failed password" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                time_match = re.search(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
                user_match = re.search(r"for (\w+) from", line)
                if ip_match and time_match:
                    ip = ip_match.group(1)
                    failed_attempts[ip].append(time_match.group(1))
                if user_match:
                    targeted_users[user_match.group(1)] += 1

            if "Accepted password" in line or "Accepted publickey" in line:
                time_match = re.search(r"^(\w+\s+\d+\s+(\d+):\d+:\d+)", line)
                user_match = re.search(r"for (\w+) from", line)
                if time_match and user_match:
                    hour = int(time_match.group(2))
                    if OFF_HOURS_START <= hour < OFF_HOURS_END:
                        off_hours_logins.append({
                            "user": user_match.group(1),
                            "time": time_match.group(1)
                        })

except FileNotFoundError:
    print(f"Log file not found at: {LOG_FILE}")
    exit()

suspects = {ip: times for ip, times in failed_attempts.items() if len(times) >= FAIL_THRESHOLD}


# Build HTML sections
brute_rows = ""
for ip, times in suspects.items():
    brute_rows += f"<tr><td>{ip}</td><td>{len(times)}</td><td>{times[0]}</td><td>{times[-1]}</td></tr>"

user_rows = ""
for user, count in sorted(targeted_users.items(), key=lambda x: x[1], reverse=True):
    user_rows += f"<tr><td>{user}</td><td>{count}</td></tr>"

offhours_rows = ""
for e in off_hours_logins:
    offhours_rows += f"<tr><td>{e['user']}</td><td>{e['time']}</td></tr>"

brute_section = brute_rows if brute_rows else "<tr><td colspan='4'>No brute force activity detected.</td></tr>"
user_section = user_rows if user_rows else "<tr><td colspan='2'>No targeted users found.</td></tr>"
offhours_section = offhours_rows if offhours_rows else "<tr><td colspan='2'>No off-hours logins detected.</td></tr>"

generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

html = """<!DOCTYPE html>
<html>
<head>
<title>Log Analysis Report</title>
<style>
body { font-family: Arial, sans-serif; background: #0f0f0f; color: #e0e0e0; padding: 40px; }
h1 { color: #00ff99; }
h2 { color: #00bfff; }
table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
th { background: #1a1a1a; color: #00ff99; padding: 10px; text-align: left; }
td { padding: 10px; border-bottom: 1px solid #2a2a2a; }
</style>
</head>
<body>
<h1>Log Analysis Report</h1>
<p>Generated: """ + generated + """</p>
<h2>Brute Force Suspects</h2>
<table><tr><th>IP Address</th><th>Failed Attempts</th><th>First Seen</th><th>Last Seen</th></tr>""" + brute_section + """</table>
<h2>Most Targeted Usernames</h2>
<table><tr><th>Username</th><th>Times Targeted</th></tr>""" + user_section + """</table>
<h2>Off-Hours Logins (12am - 6am)</h2>
<table><tr><th>Username</th><th>Time</th></tr>""" + offhours_section + """</table>
</body>
</html>"""

with open(REPORT_FILE, "w") as f:
    f.write(html)

print("Done! Open report.html in your Downloads folder to see the report.")