"""
NTUSF test runner — OWASP Juice Shop @ localhost:3000
Bypasses the Scrapy step (SPA) by building the endpoint CSV directly
from discovered API routes, then runs ML + all scanning modules.
"""
import sys, os, time, json, requests, warnings
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
warnings.filterwarnings("ignore")

TARGET = "http://localhost:3000"
BASE_URL = "localhost:3000"

DF_DIR  = f"results/{BASE_URL}/DF/"
IMG_DIR = f"results/{BASE_URL}/IMG/"
os.makedirs(DF_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)

# ─── 1. Collect endpoints ────────────────────────────────────────────────────
print("\n[*] Phase 1 — Endpoint discovery")
t0 = time.time()

def get(path, **kw):
    try:
        return requests.get(TARGET + path, timeout=8, verify=False, **kw)
    except Exception:
        return None

# Known Juice Shop REST + API endpoints (based on official challenge list)
# Format: (path, method, get_params_dict, post_params_dict)
ENDPOINTS = [
    # ── Products / search (SQLi, reflected XSS)
    ("/rest/products/search",        "GET",  {"q": "apple"},         {}),
    ("/api/Products",                "GET",  {},                     {}),
    ("/api/Products/1",              "GET",  {},                     {}),
    # ── Users / auth (SQLi in email)
    ("/api/Users",                   "GET",  {},                     {}),
    ("/api/Users/1",                 "GET",  {},                     {}),
    ("/rest/user/whoami",            "GET",  {},                     {}),
    ("/rest/user/change-password",   "GET",  {"current":"x","new":"y","repeat":"y"}, {}),
    # ── Login (POST SQLi)
    ("/rest/user/login",             "POST", {}, {"email":"user@test.com","password":"test"}),
    ("/api/Users/login",             "POST", {}, {"email":"user@test.com","password":"test"}),
    # ── Registration
    ("/api/Users/",                  "POST", {}, {"email":"test@test.com","password":"Test1234!","passwordRepeat":"Test1234!","securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},"securityAnswer":"test"}),
    # ── Feedback (stored XSS)
    ("/api/Feedbacks",               "GET",  {},                     {}),
    ("/api/Feedbacks/",              "POST", {}, {"comment":"test feedback","rating":5}),
    ("/api/Feedbacks/1",             "GET",  {},                     {}),
    # ── Basket / orders
    ("/api/BasketItems",             "GET",  {},                     {}),
    ("/api/BasketItems/",            "POST", {}, {"ProductId":1,"BasketId":1,"quantity":1}),
    ("/rest/basket/1",               "GET",  {},                     {}),
    ("/rest/basket/1/checkout",      "POST", {}, {}),
    # ── Recycles
    ("/api/Recycles",                "GET",  {},                     {}),
    ("/api/Recycles/",               "POST", {}, {"AddressId":1,"quantity":1000,"isPickup":True}),
    # ── Address
    ("/api/Addresss",                "GET",  {},                     {}),
    ("/api/Addresss/",               "POST", {}, {"country":"DE","fullName":"Test User","mobileNum":"0151000","zipCode":"12345","streetAddress":"Teststrasse 1","city":"Berlin","state":"Berlin"}),
    # ── Delivery
    ("/api/Deliverys",               "GET",  {},                     {}),
    # ── Challenges
    ("/api/Challenges",              "GET",  {},                     {}),
    # ── SecurityQuestions
    ("/api/SecurityQuestions",       "GET",  {},                     {}),
    # ── File upload (path traversal endpoint)
    ("/file-upload",                 "POST", {}, {}),
    # ── FTP directory (path traversal)
    ("/ftp",                         "GET",  {},                     {}),
    ("/ftp/",                        "GET",  {},                     {}),
    # ── Profile image upload
    ("/profile/image/url",           "POST", {}, {"imageUrl":"http://placekitten.com/400/400"}),
    # ── Track order
    ("/rest/track-order/5267-f73d",  "GET",  {},                     {}),
    # ── Admin panel
    ("/administration",              "GET",  {},                     {}),
    ("/rest/admin/application-configuration", "GET", {}, {}),
    # ── Complaints
    ("/api/Complaints",              "POST", {}, {"message":"test","fileUpload":""}),
    # ── Redirect (open redirect)
    ("/redirect",                    "GET",  {"to":"https://github.com/juice-shop"}, {}),
    # ── Page not found (404 with reflection — XSS)
    ("/some-page-that-does-not-exist", "GET", {}, {}),
    # ── Coupon
    ("/rest/basket/1/coupon/WMNSDY2019", "PUT", {}, {}),
    # ── Wallet
    ("/api/Wallets/1",               "GET",  {},                     {}),
    # ── Image captcha
    ("/rest/image-captcha/",         "GET",  {},                     {}),
    # ── 2FA
    ("/rest/2fa/setup",              "GET",  {},                     {}),
    # ── Memories (SSRF via imageUrl)
    ("/api/Memorys",                 "GET",  {},                     {}),
    ("/api/Memorys/",                "POST", {}, {"caption":"test","imageUrl":"http://placekitten.com/400/400"}),
]

rows = []
discovered = 0
for path, method, get_params, post_params in ENDPOINTS:
    url = TARGET + path
    if get_params:
        from urllib.parse import urlencode
        full_url = url + "?" + urlencode(get_params)
    else:
        full_url = url

    rows.append({
        "URL": full_url,
        "Method": method,
        "GET Params": json.dumps(get_params) if get_params else "{}",
        "POST Params": json.dumps(post_params) if post_params else "{}",
        "base_url": BASE_URL,
    })
    discovered += 1

# Also quick-crawl the HTML homepage for any extra links
try:
    resp = get("/")
    if resp and resp.text:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") and not any(x in href for x in ["logout","#","javascript"]):
                rows.append({
                    "URL": TARGET + href,
                    "Method": "GET",
                    "GET Params": "{}",
                    "POST Params": "{}",
                    "base_url": BASE_URL,
                })
                discovered += 1
except Exception:
    pass

df_endpoints = pd.DataFrame(rows).drop_duplicates(subset=["URL","Method"])
crawled_path = DF_DIR + f"{BASE_URL}_crawled_endpoints.csv"
df_endpoints.to_csv(crawled_path, index=False)

t_crawl = time.time() - t0
print(f"    {len(df_endpoints)} endpoints collected in {t_crawl:.1f}s")
print(f"    Saved to: {crawled_path}")

# ─── 2. ML Classification ────────────────────────────────────────────────────
print("\n[*] Phase 2 — ML Classification (XGBoost)")
t1 = time.time()
try:
    from ML.ml import URLClassifier
    classifier = URLClassifier(base_url=BASE_URL, threshold=0.3, n_estimators=500)
    classifier.run()
    t_ml = time.time() - t1
    filtered_path = DF_DIR + f"{BASE_URL}_filtered_data.csv"
    df_filtered = pd.read_csv(filtered_path)
    print(f"    ML done in {t_ml:.1f}s")
    print(f"    {len(df_endpoints)} endpoints → {len(df_filtered)} after ML filter")
except Exception as e:
    print(f"    ML error: {e} — using all endpoints as fallback")
    df_endpoints.to_csv(DF_DIR + f"{BASE_URL}_filtered_data.csv", index=False)
    df_filtered = df_endpoints
    t_ml = 0.0

# ─── 3. Scanning modules ─────────────────────────────────────────────────────
filtered_path = DF_DIR + f"{BASE_URL}_filtered_data.csv"

MODULES = [
    ("XSSscanner",          "modules.xss.xss",      "XSS"),
    ("SQLscanner",          "modules.sql",           "SQLi"),
    ("CSRFscanner",         "modules.csrf",          "CSRF"),
    ("Traversalscanner",    "modules.path_traversal","Path_Traversal"),
    ("OpenRedirectScanner", "modules.open_redirect", "Open_Redirect"),
    ("SSRFscanner",         "modules.ssrf",          "SSRF"),
    ("SSTIscanner",         "modules.ssti",          "SSTI"),
    ("CMDInjectionscanner", "modules.cmd_injection", "CMD_Injection"),
]

scan_times = {}
scan_findings = {}

print("\n[*] Phase 3 — Vulnerability scanning")
print(f"    Scanning {len(df_filtered)} endpoints with {len(MODULES)} modules\n")

for class_name, module_path, col in MODULES:
    t_s = time.time()
    try:
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        scanner = cls(
            base_url=BASE_URL,
            proxies=None,
            cookies=None,
            dataframe=filtered_path,
            threads=10,
            timeout=12,
        )
        scanner.start_scanning()
        elapsed = time.time() - t_s

        # Count findings
        result_csv = DF_DIR + f"{BASE_URL}_{col.lower()}.csv"
        # map col name to actual CSV col
        col_map = {
            "XSS": "XSS", "SQLi": "SQLi", "CSRF": "CSRF",
            "Path_Traversal": "Path_Traversal",
            "Open_Redirect": "Open_Redirect", "SSRF": "SSRF",
            "SSTI": "SSTI", "CMD_Injection": "CMD_Injection",
        }
        csv_files = {
            "XSS": DF_DIR + f"{BASE_URL}_xss.csv",
            "SQLi": DF_DIR + f"{BASE_URL}_sqli.csv",
            "CSRF": DF_DIR + f"{BASE_URL}_csrf.csv",
            "Path_Traversal": DF_DIR + f"{BASE_URL}_path_traversal.csv",
            "Open_Redirect": DF_DIR + f"{BASE_URL}_open_redirect.csv",
            "SSRF": DF_DIR + f"{BASE_URL}_ssrf.csv",
            "SSTI": DF_DIR + f"{BASE_URL}_ssti.csv",
            "CMD_Injection": DF_DIR + f"{BASE_URL}_cmd_injection.csv",
        }
        try:
            r_df = pd.read_csv(csv_files[col])
            if col in r_df.columns:
                count = int(r_df[col].sum())
            else:
                count = 0
        except Exception:
            count = 0

        scan_times[class_name] = elapsed
        scan_findings[col] = count
        status = f"✓ {count} finding(s)" if count > 0 else "  0 findings"
        print(f"    [{elapsed:5.1f}s] {class_name:<25} {status}")
    except Exception as e:
        elapsed = time.time() - t_s
        scan_times[class_name] = elapsed
        scan_findings[col] = 0
        print(f"    [{elapsed:5.1f}s] {class_name:<25} ERROR: {e}")

# ─── 4. Merge results + HTML report ─────────────────────────────────────────
print("\n[*] Phase 4 — Merging results & generating report")

csv_map = {
    "SQLi":           ("SQLi",          DF_DIR + f"{BASE_URL}_sqli.csv"),
    "CSRF":           ("CSRF",          DF_DIR + f"{BASE_URL}_csrf.csv"),
    "Path_Traversal": ("Path_Traversal",DF_DIR + f"{BASE_URL}_path_traversal.csv"),
    "Open_Redirect":  ("Open_Redirect", DF_DIR + f"{BASE_URL}_open_redirect.csv"),
    "SSRF":           ("SSRF",          DF_DIR + f"{BASE_URL}_ssrf.csv"),
    "SSTI":           ("SSTI",          DF_DIR + f"{BASE_URL}_ssti.csv"),
    "CMD_Injection":  ("CMD_Injection", DF_DIR + f"{BASE_URL}_cmd_injection.csv"),
}

try:
    merged = pd.read_csv(DF_DIR + f"{BASE_URL}_xss.csv")
    for col, (csv_col, path) in csv_map.items():
        try:
            tmp = pd.read_csv(path)
            if csv_col in tmp.columns:
                merged = merged.merge(tmp[["URL", csv_col]], on="URL", how="left")
        except Exception:
            pass
    merged.to_csv(DF_DIR + f"{BASE_URL}_merged_results.csv", index=False)

    from modules.report import generate_report
    report_path = f"results/{BASE_URL}/report.html"
    generate_report(BASE_URL, merged, report_path)
    print(f"    Report saved to: {report_path}")
except Exception as e:
    print(f"    Report error: {e}")

# ─── 5. Performance summary ──────────────────────────────────────────────────
total_time = time.time() - t0
total_findings = sum(scan_findings.values())

print("\n" + "═" * 60)
print("  NTUSF — Juice Shop Evaluation Summary")
print("═" * 60)
print(f"  Target           : {TARGET}")
print(f"  Endpoints found  : {len(df_endpoints)}")
print(f"  After ML filter  : {len(df_filtered)}")
print(f"  Total findings   : {total_findings}")
print(f"  Total time       : {total_time:.0f}s  (crawl {t_crawl:.0f}s | ML {t_ml:.0f}s)")
print()
print(f"  {'Module':<28} {'Time':>6}  {'Findings':>8}")
print(f"  {'-'*28} {'-'*6}  {'-'*8}")
for class_name, _, col in MODULES:
    t = scan_times.get(class_name, 0)
    f = scan_findings.get(col, 0)
    print(f"  {class_name:<28} {t:>5.1f}s  {f:>8}")
print("═" * 60)
print(f"\n  HTML report: results/{BASE_URL}/report.html\n")
