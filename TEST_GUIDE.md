
### View Juice Shop Report Summary
```fish
set latest_js (ls -t reports/juice-shop-report-*.json | head -1)
cat $latest_js | jq '{totalTests: .summary.totalTests, passed: .summary.passed, failed: .summary.failed, findings: .findings | length}'
cat $latest_js | jq '.findings[] | {id: .id, type: .type, severity: .severity, endpoint: .endpoint}'
```

### Stop Running Containers
```fish
# Stop just the two test containers
docker stop dvwa juice-shop && docker rm dvwa juice-shop

# Or stop ALL containers (nuclear)
docker stop $(docker ps -q) && docker rm $(docker ps -aq)
```

---

## Prerequisites
- Docker running
- Maven installed (`mvn -v` works)
- Java 17+ installed
- Fish shell (commands below use fish syntax)

---

## 1. Start DVWA Container

```fish
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
```

**Wait ~30 seconds** for DVWA to fully initialize (database setup, Apache start).

Verify it's up:
```fish
curl -s http://localhost:8080/login.php | grep -q "DVWA" && echo "DVWA ready"
```

Set security level to **Low** (required for vulns to be exploitable):
```fish
curl -s -c /tmp/dvwa_cookies.txt http://localhost:8080/login.php
curl -s -b /tmp/dvwa_cookies.txt -d "username=admin&password=password&Login=Login" http://localhost:8080/login.php
curl -s -b /tmp/dvwa_cookies.txt -d "security=low&seclev_submit=Submit" http://localhost:8080/security.php
```

---

## 2. Start OWASP Juice Shop Container

```fish
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

**Wait ~30-60 seconds** for Juice Shop to fully start.

Verify it's up:
```fish
curl -s http://localhost:3000 | grep -q "Juice Shop" && echo "Juice Shop ready"
```

---

## 3. Build the Fuzzer (if not already built)

```fish
cd ~/api-fuzzer-basic
mvn clean compile -q
```

---

## 4. Run Fuzzer Against DVWA

```fish
set timestamp (date +%F-%H%M)
mvn exec:java -Dexec.mainClass=com.apifuzzer.FuzzerRunner -Dexec.args="demo-dvwa.json reports/dvwa-report-$timestamp.json" -q
```

**Expected runtime:** ~30-60 seconds (200 requests @ 5 req/s)

---

## 5. Run Fuzzer Against Juice Shop

```fish
set timestamp (date +%F-%H%M)
mvn exec:java -Dexec.mainClass=com.apifuzzer.FuzzerRunner -Dexec.args="demo-juice-shop.json reports/juice-shop-report-$timestamp.json" -q
```

**Expected runtime:** ~60-90 seconds (800 requests @ 15 req/s)

---

## 6. View Report Summaries

### DVWA Report
```fish
# Find latest DVWA report
set latest_dvwa (ls -t reports/dvwa-report-*.json | head -1)
echo "Latest: $latest_dvwa"

# Summary stats
cat $latest_dvwa | jq '{totalTests: .summary.totalTests, passed: .summary.passed, failed: .summary.failed, findings: .findings | length}'

# Show findings (vulnerabilities detected)
cat $latest_dvwa | jq '.findings[] | {id: .id, type: .type, severity: .severity, endpoint: .endpoint, evidence: .evidence}'
```

### Juice Shop Report
```fish
# Find latest Juice Shop report
set latest_js (ls -t reports/juice-shop-report-*.json | head -1)
echo "Latest: $latest_js"

# Summary stats
cat $latest_js | jq '{totalTests: .summary.totalTests, passed: .summary.passed, failed: .summary.failed, findings: .findings | length}'

# Show findings grouped by type
cat $latest_js | jq '.findings | group_by(.type) | map({type: .[0].type, count: length, examples: .[0:3] | map({id: .id, severity: .severity, endpoint: .endpoint})})'
```

### Pretty HTML Report (if supported)
```fish
# Check if HTML report was generated
ls -la reports/*.html 2>/dev/null || echo "No HTML reports found"
```

---

## 7. Stop and Remove Containers

### Stop DVWA
```fish
docker stop dvwa
docker rm dvwa
```

### Stop Juice Shop
```fish
docker stop juice-shop
docker rm juice-shop
```

### Nuclear Option (stop ALL containers)
```fish

```

---

## 8. Quick One-Liner for Full Run (Copy-Paste)

```fish
# Start both
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

# Wait for startup
sleep 45

# Set DVWA security to low
curl -s -c /tmp/dvwa_cookies.txt http://localhost:8080/login.php
curl -s -b /tmp/dvwa_cookies.txt -d "username=admin&password=password&Login=Login" http://localhost:8080/login.php
curl -s -b /tmp/dvwa_cookies.txt -d "security=low&seclev_submit=Submit" http://localhost:8080/security.php

# Build & run fuzzer
cd ~/api-fuzzer-basic
mvn clean compile -q

set ts (date +%F-%H%M)
mvn exec:java -Dexec.mainClass=com.apifuzzer.FuzzerRunner -Dexec.args="demo-dvwa.json reports/dvwa-report-$ts.json" -q

set ts (date +%F-%H%M)
mvn exec:java -Dexec.mainClass=com.apifuzzer.FuzzerRunner -Dexec.args="demo-juice-shop.json reports/juice-shop-report-$ts.json" -q

# View results
set latest_dvwa (ls -t reports/dvwa-report-*.json | head -1)
set latest_js (ls -t reports/juice-shop-report-*.json | head -1)
echo "=== DVWA ==="; cat $latest_dvwa | jq '{totalTests: .summary.totalTests, findings: .findings | length}'
echo "=== Juice Shop ==="; cat $latest_js | jq '{totalTests: .summary.totalTests, findings: .findings | length}'

# Cleanup
docker stop dvwa juice-shop && docker rm dvwa juice-shop
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Connection refused` | Container not ready yet — `sleep 30` and retry |
| `jq: command not found` | `sudo pacman -S jq` (Arch) / `apt install jq` (Debian) |
| DVWA login fails | Check cookie file path, ensure security=low was set |
| Juice Shop 500 errors | Normal for some fuzzed endpoints — check findings, not HTTP codes |
| Maven exec plugin missing | Run `mvn dependency:resolve` first |
| Port already in use | `docker ps` to check, `docker stop <container>` to free |

---

## Report Structure Reference

Each report JSON contains:
```json
{
  "summary": { "totalTests": 200, "passed": 180, "failed": 20 },
  "findings": [
    { "id": "sqli-get", "type": "SQL_INJECTION", "severity": "HIGH", "endpoint": "/vulnerabilities/sqli/", "evidence": "...", "payload": "..." }
  ],
  "config": { ... }
}
```
