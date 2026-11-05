
Prerequisites (Run Once)
bash
cd /home/hardik/api-fuzzer-basic
mvn clean package -DskipTests




Step 1: Start Juice Shop (Separate Terminal)
bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
Wait 15 seconds for startup
sleep 15


Step 2: Verify Juice Shop is Running
bash
Check homepage
curl -s http://localhost:3000/ | head -1

Test API endpoint
curl -s http://localhost:3000/rest/products/search?q=apple | jq '.status'
Should output: "success"




Step 3: Create Config File
bash
cd /home/hardik/api-fuzzer-basic
cat > demo-juice-shop.json << 'EOF'
{
  "portalHostname": "localhost:3000",
  "protocol": "http",
  "approvedPathPrefixes": [
    "/rest",
    "/api",
    "/assets"
  ],
  "approvedMethods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
  "maxRequestsPerSession": 300,
  "requestsPerSecond": 10,
  "requestTimeoutSeconds": 15,
  "testHeaders": {
    "Accept": "application/json",
    "Content-Type": "application/json"
  },
  "testAccount": {
    "profileName": "juice-shop",
    "authType": "NONE",
    "credential": "none"
  },
  "demoSeeds": [
    { "id": "get-products-search", "method": "GET", "path": "/rest/products/search?q=apple" },
    { "id": "get-product-by-id", "method": "GET", "path": "/rest/products/1" },
    { "id": "user-login", "method": "POST", "path": "/rest/user/login", "body": "{\"email\":\"test@juice-sh.op\",\"password\": \"***\"}" },
    { "id": "submit-feedback", "method": "POST", "path": "/api/Feedbacks/", "body": "{\"comment\":\"Great service!\",\"rating\":5}" },
    { "id": "get-basket", "method": "GET", "path": "/rest/basket/1" },
    { "id": "file-upload", "method": "POST", "path": "/file-upload", "body": "{\"file\":\"test.txt\"}" },
    { "id": "track-order", "method": "POST", "path": "/api/TrackOrder/", "body": "{\"id\":\"1\"}" }
  ]
}
EOF




Step 4: Run the Fuzzer
bash
cd /home/hardik/api-fuzzer-basic
mvn exec:java -Dexec.mainClass=com.apifuzzer.FuzzerRunner \
  -Dexec.args="demo-juice-shop.json reports/demo-report-$(date +%F-%H%M).json" \
  -q


Expected runtime: 30-60 seconds

Expected output:

[INFO] Loading config from: demo-juice-shop.json
[INFO] Loaded 7 seed requests
[INFO] Starting fuzzing session...
[INFO] Report will be written to: reports/demo-report-2026-11-04-163045.json
[DEBUG] Executing mutation: get-products-search-query_missing_q (strategy: MUTATION:QUERY_MISSING_q)
[DEBUG]   URL: http://localhost:3000/rest/products/search
[DEBUG]   Baseline status: 200
[DEBUG]   Actual status: 200, error: null
...
[DEBUG] Executing mutation: get-products-search-struct-... (strategy: STRUCTURAL_MUTATOR_QUERY_PARAMS)
[DEBUG]   URL: http://localhost:3000/rest/products/search?q=apple'
[DEBUG]   Baseline status: 200
[DEBUG]   Actual status: 500, error: null
[DEBUG]   FINDINGS: 1
    STATUS_ORACLE: New server error introduced by mutation
...

=== SESSION COMPLETE ===
State: COMPLETED
Total requests: ~300
Observations: ~350
Findings: ~40-50
Strategy scores: {QUERY=-1.0, BASELINE=-140.0, ...}

[INFO] Report written to: reports/demo-report-2026-11-04-163045.json
[INFO] Report size: 15000 bytes




Step 5: View the Report & Summary

Find the report file:
bash
ls -la reports/demo-report-*.json


View Summary (Instant Executive View):
bash
cat reports/demo-report-*.json | jq '.summary'


Expected output:
json
{
  "totalFindings": 55,
  "byOracleType": {
    "RESPONSE_ANOMALY_ORACLE": "25",
    "STATUS_ORACLE": "30"
  },
  "bySeverity": {
    "LOW": "32",
    "INFO": "23"
  },
  "byConfidence": {
    "LOW": "55"
  },
  "byOracleTypeAndSeverity": {
    "RESPONSE_ANOMALY_ORACLE|INFO": "23",
    "RESPONSE_ANOMALY_ORACLE|LOW": "2",
    "STATUS_ORACLE|LOW": "30"
  }
}


View Key Findings (SQL Injection):
bash
cat reports/demo-report-*.json | jq '.findings[] | select(.mutationStrategy | contains("QUERY_PARAMS") and .url | contains("apple")) | {title, severity, mutationStrategy, url, httpStatus, baselineStatus}'


View Full Report (Pretty):
bash
cat reports/demo-report-*.json | jq '.'


Generate HTML Report (Open in Browser):
bash
cat > /tmp/json2html.py << 'EOF'
import json, sys
data = json.load(open(sys.argv[1]))
html = f"""<!DOCTYPE html>
<html><head><title>API Fuzzer Report</title>
<style>
body {{font-family: monospace; margin: 20px;}}
table {{border-collapse: collapse; width: 100%;}}
th, td {{border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px;}}
th {{background: #333; color: white;}}
tr:nth-child(even) {{background: #f9f9f9;}}
.severity-HIGH {{background: #ffcccc;}}
.severity-MEDIUM {{background: #fff3cc;}}
.severity-LOW {{background: #e6ffe6;}}
.severity-INFO {{background: #cce5ff;}}
.url {{max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;}}
.evidence {{max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;}}
</style></head><body>
<h1>API Fuzzer Security Report</h1>
<p>Generated: {data['generatedAt']} | Total Findings: {data['findingCount']}</p>
<table>
<tr><th>ID</th><th>Seed</th><th>Strategy</th><th>Method</th><th>URL</th><th>Status</th><th>Severity</th><th>Evidence</th></tr>
"""
for f in data['findings']:
    html += f"""<tr>
    <td>{f['id'][:8]}</td>
    <td>{f['seedRequestId']}</td>
    <td>{f['mutationStrategy']}</td>
    <td>{f['method']}</td>
    <td class="url">{f['url']}</td>
    <td>{f['httpStatus']}/{f['baselineStatus']}</td>
    <td class="severity-{f['severity']}">{f['severity']}</td>
    <td class="evidence">{f['evidence'][:120]}</td>
</tr>"""
html += "</table></body></html>"
with open(sys.argv[2], 'w') as f:
    f.write(html)
print(f"Written to {sys.argv[2]}")
EOF

python3 /tmp/json2html.py reports/demo-report-*.json /tmp/report.html
xdg-open /tmp/report.html  # Linux
open /tmp/report.html  # macOS




Step 6: Cleanup
bash
docker stop juice-shop && docker rm juice-shop



































