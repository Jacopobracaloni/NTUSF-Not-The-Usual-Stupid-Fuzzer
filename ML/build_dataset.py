"""
Build Training_data_v2.csv — purpose-built for NTUSF endpoint interest classification.

Label semantics (backward-compatible with URLClassifier filter direction):
  0 = INTERESTING endpoint worth scanning  → model gives low prob → filter KEEPS it
  1 = BORING / static endpoint             → model gives high prob → filter DROPS it

The training data includes:
  - URL      : full URL string
  - Method   : GET or POST
  - POST Params: JSON string of body params (or "{}" if none)
  - classification: 0 or 1
"""

import os
import sys
import json
import random
import pandas as pd

random.seed(42)

BASE = "http://placeholder.local"

SECLISTS = "/usr/share/seclists/Discovery/Web-Content"

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".webp", ".bmp", ".tiff", ".avif",
}

BORING_EXTENSIONS = {
    ".txt", ".xml", ".json", ".conf", ".cfg", ".ini",
    ".bak", ".old", ".zip", ".tar", ".gz", ".pdf",
    ".html", ".htm",
}

SENSITIVE_PARAMS = {
    "password", "passwd", "pass", "pwd", "token", "secret",
    "key", "api_key", "apikey", "auth", "authorization",
    "username", "user", "email", "userid", "user_id",
    "id", "admin", "redirect", "next", "return", "url",
    "goto", "target", "dest", "file", "path", "src",
    "callback", "session", "csrf", "nonce",
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def url(path):
    return BASE + path


def post_params(*pairs):
    return json.dumps(dict(pairs))


# ─── INTERESTING examples (label=0) ──────────────────────────────────────────

interesting_rows = []

# 1. REST API endpoints with numeric IDs
for n in list(range(1, 150)) + [1000, 9999]:
    interesting_rows += [
        {"URL": url(f"/api/users/{n}"),           "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/api/products/{n}"),         "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/api/orders/{n}"),           "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/api/basket/{n}/checkout"),  "Method": "POST", "POST Params": post_params(("couponCode", ""))},
        {"URL": url(f"/api/complaints/{n}"),       "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/api/feedbacks/{n}"),        "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/api/recycles/{n}"),         "Method": "GET",  "POST Params": "{}"},
        {"URL": url(f"/rest/user/{n}"),            "Method": "GET",  "POST Params": "{}"},
    ]

# 2. Auth / user management endpoints
AUTH_ENDPOINTS = [
    ("/login",                    "POST", post_params(("email", "test@test.com"), ("password", "test"))),
    ("/register",                 "POST", post_params(("email", "x@x.com"), ("password", "x"), ("username", "x"))),
    ("/logout",                   "GET",  "{}"),
    ("/signin",                   "POST", post_params(("username", "admin"), ("password", "admin"))),
    ("/signup",                   "POST", post_params(("email", "a@b.com"), ("password", "pass123"))),
    ("/forgot-password",          "POST", post_params(("email", "user@example.com"))),
    ("/reset-password",           "POST", post_params(("token", "abc"), ("password", "newpass"))),
    ("/change-password",          "POST", post_params(("current", "old"), ("new", "new"), ("repeat", "new"))),
    ("/api/Users/login",          "POST", post_params(("email", "admin@juice-sh.op"), ("password", "admin123"))),
    ("/api/Users/register",       "POST", post_params(("email", "x@x.com"), ("password", "x"), ("username", "x"))),
    ("/api/Users/1",              "GET",  "{}"),
    ("/rest/user/whoami",         "GET",  "{}"),
    ("/rest/user/change-password","GET",  "{}"),
    ("/api/login",                "POST", post_params(("username", "admin"), ("password", "password"))),
    ("/api/auth/token",           "POST", post_params(("grant_type", "password"), ("username", "user"))),
    ("/api/auth/refresh",         "POST", post_params(("refresh_token", "xyz"))),
    ("/api/auth/logout",          "POST", "{}"),
    ("/oauth/token",              "POST", post_params(("grant_type", "client_credentials"))),
]
for path, method, params in AUTH_ENDPOINTS:
    for _ in range(8):
        interesting_rows.append({"URL": url(path), "Method": method, "POST Params": params})

# 3. Admin / management endpoints
ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/products", "/admin/orders",
    "/admin/settings", "/admin/logs", "/admin/reports",
    "/management", "/dashboard", "/console",
    "/api/admin/users", "/api/admin/products",
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    "/metrics", "/health", "/actuator", "/actuator/env",
    "/actuator/beans", "/api/config", "/api/settings",
    "/graphql", "/gql", "/v1/graphql",
]
for path in ADMIN_PATHS:
    for _ in range(5):
        interesting_rows.append({"URL": url(path), "Method": "GET", "POST Params": "{}"})

# 4. Search / filter endpoints with query params
SEARCH_TERMS = ["admin", "test", "apple", "'; DROP TABLE", "1=1", "<script>", "../../etc/passwd", "null", "undefined", "true"]
for term in SEARCH_TERMS:
    for prefix in ["/api/products/search", "/rest/products/search", "/search", "/api/search", "/api/users/search"]:
        interesting_rows.append({"URL": url(f"{prefix}?q={term}"), "Method": "GET", "POST Params": "{}"})
    interesting_rows.append({"URL": url(f"/api/users?email={term}"), "Method": "GET", "POST Params": "{}"})
    interesting_rows.append({"URL": url(f"/api/users?username={term}"), "Method": "GET", "POST Params": "{}"})

# 5. Redirect / open redirect candidates
REDIRECT_PARAMS = ["redirect", "next", "return", "url", "goto", "target", "dest", "returnUrl", "back"]
REDIRECT_VALUES = [
    "https://evil.com", "//evil.com", "http://localhost/admin",
    "javascript:alert(1)", "https://github.com/juice-shop",
    "http://169.254.169.254/latest/meta-data/",
]
for param in REDIRECT_PARAMS:
    for val in REDIRECT_VALUES:
        interesting_rows.append({
            "URL": url(f"/redirect?{param}={val}"),
            "Method": "GET",
            "POST Params": "{}",
        })
        interesting_rows.append({
            "URL": url(f"/api/redirect?{param}={val}"),
            "Method": "GET",
            "POST Params": "{}",
        })

# 6. File operations / upload / export
FILE_OPS = [
    ("/upload",                 "POST", post_params(("Content-Type", "multipart/form-data"))),
    ("/api/files/upload",       "POST", "{}"),
    ("/api/export",             "GET",  "{}"),
    ("/api/export?format=csv",  "GET",  "{}"),
    ("/api/export?type=users",  "GET",  "{}"),
    ("/download",               "GET",  "{}"),
    ("/download?file=report.pdf","GET", "{}"),
    ("/attachment?filename=test.pdf","GET","{}"),
    ("/api/fileupload",         "POST", "{}"),
    ("/api/download?path=../../etc/passwd","GET","{}"),
]
for path, method, params in FILE_OPS:
    for _ in range(5):
        interesting_rows.append({"URL": url(path), "Method": method, "POST Params": params})

# 7. Sensitive GET params
for param in SENSITIVE_PARAMS:
    for val in ["test", "1", "admin", "null"]:
        interesting_rows.append({
            "URL": url(f"/api/data?{param}={val}"),
            "Method": "GET",
            "POST Params": "{}",
        })
        interesting_rows.append({
            "URL": url(f"/api/user/profile?{param}={val}"),
            "Method": "GET",
            "POST Params": "{}",
        })

# 8. REST API endpoints from SecLists
api_seclists = os.path.join(SECLISTS, "api", "api-endpoints.txt")
if os.path.exists(api_seclists):
    with open(api_seclists) as f:
        for line in f:
            path = line.strip()
            if path and not path.startswith("#"):
                if not path.startswith("/"):
                    path = "/" + path
                interesting_rows.append({"URL": url(path),         "Method": "GET",  "POST Params": "{}"})
                interesting_rows.append({"URL": url(path + "?id=1"), "Method": "GET",  "POST Params": "{}"})
                interesting_rows.append({"URL": url(path),         "Method": "POST", "POST Params": post_params(("data", "value"))})

# 9. More POST endpoints with bodies
POST_PATHS = [
    ("/api/complaints", post_params(("message", "test complaint"), ("UserId", "1"))),
    ("/api/feedbacks",  post_params(("comment", "test"), ("rating", "5"), ("UserId", "1"))),
    ("/api/BasketItems", post_params(("ProductId", "1"), ("BasketId", "1"), ("quantity", "1"))),
    ("/api/Addresses",  post_params(("country", "US"), ("fullName", "Test"), ("zipCode", "12345"), ("streetAddress", "123 Main St"), ("city", "TestCity"), ("state", "NY"))),
    ("/api/Deliveries", post_params(("addressId", "1"), ("deliveryMethodId", "1"))),
    ("/api/PrivacyRequests", post_params(("UserId", "1"))),
    ("/api/Quantitys",  post_params(("ProductId", "1"), ("quantity", "3"))),
    ("/api/Recycles",   post_params(("AddressId", "1"), ("quantity", "2"), ("isPickup", "true"))),
    ("/rest/products/reviews", post_params(("message", "test review"), ("author", "user@test.com"))),
    ("/rest/user/reset-password", post_params(("email", "user@test.com"), ("answer", "test"), ("new", "newpass"), ("repeat", "newpass"))),
]
for path, params in POST_PATHS:
    for _ in range(8):
        interesting_rows.append({"URL": url(path), "Method": "POST", "POST Params": params})

# 10. SSRF candidates (url-like params)
SSRF_PARAMS = ["url", "uri", "src", "path", "file", "fetch", "proxy", "host", "endpoint", "remote"]
SSRF_VALUES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "http://localhost:8080/admin",
    "file:///etc/passwd",
    "http://internal.service.local/api",
]
for param in SSRF_PARAMS:
    for val in SSRF_VALUES:
        interesting_rows.append({
            "URL": url(f"/api/data?{param}={val}"),
            "Method": "GET",
            "POST Params": "{}",
        })

print(f"[+] Interesting examples generated: {len(interesting_rows)}")


# ─── BORING examples (label=1) ────────────────────────────────────────────────

boring_rows = []

# 1. Static files with extensions
STATIC_DIRS = [
    "/static", "/assets", "/dist", "/public", "/build",
    "/vendor", "/lib", "/fonts", "/images", "/img", "/media",
    "/css", "/js", "/styles", "/scripts",
    "/node_modules/lodash", "/node_modules/react",
]
FILE_NAMES = [
    "app", "vendor", "main", "bundle", "index", "runtime",
    "polyfills", "styles", "theme", "icons", "logo", "background",
    "jquery.min", "bootstrap.min", "react.production.min",
    "angular.min", "vue.min", "chunk-vendors", "2.chunk",
]
for d in STATIC_DIRS:
    for name in FILE_NAMES:
        for ext in STATIC_EXTENSIONS:
            boring_rows.append({
                "URL": url(f"{d}/{name}{ext}"),
                "Method": "GET",
                "POST Params": "{}",
            })

# 2. Well-known boring paths
BORING_WELLKNOWN = [
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/favicon.png",
    "/humans.txt", "/manifest.json", "/browserconfig.xml",
    "/crossdomain.xml", "/apple-touch-icon.png",
    "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/android-chrome-192x192.png", "/android-chrome-512x512.png",
    "/apple-touch-icon-precomposed.png",
    "/service-worker.js", "/sw.js", "/workbox-*.js",
    "/.htaccess", "/.htpasswd",
]
for path in BORING_WELLKNOWN:
    for _ in range(12):
        boring_rows.append({"URL": url(path), "Method": "GET", "POST Params": "{}"})

# 3. Paths from SecLists big.txt (static-looking)
big_txt = os.path.join(SECLISTS, "big.txt")
if os.path.exists(big_txt):
    with open(big_txt) as f:
        for line in f:
            path = line.strip()
            if not path or path.startswith("#"):
                continue
            if not path.startswith("/"):
                path = "/" + path
            ext = os.path.splitext(path)[1].lower()
            if ext in STATIC_EXTENSIONS or ext in BORING_EXTENSIONS:
                boring_rows.append({"URL": url(path), "Method": "GET", "POST Params": "{}"})

# 4. Versioned asset paths (cache-busted)
HASH_SUFFIXES = ["abc123", "d4e5f6", "1234567", "abcdef0"]
for name in ["app", "vendor", "main", "styles"]:
    for suffix in HASH_SUFFIXES:
        for ext in [".js", ".css", ".js.map", ".css.map"]:
            boring_rows.append({
                "URL": url(f"/static/{name}.{suffix}{ext}"),
                "Method": "GET",
                "POST Params": "{}",
            })

# 5. Source maps and lock files
SOURCE_MAPS = [
    "/app.js.map", "/vendor.js.map", "/styles.css.map",
    "/package-lock.json", "/yarn.lock",
    "/webpack.config.js", "/tsconfig.json",
    "/.eslintrc.json", "/.babelrc",
    "/Dockerfile", "/docker-compose.yml",
]
for path in SOURCE_MAPS:
    for _ in range(5):
        boring_rows.append({"URL": url(path), "Method": "GET", "POST Params": "{}"})

print(f"[+] Boring examples generated: {len(boring_rows)}")

# ─── Balance and save ─────────────────────────────────────────────────────────

n_samples = min(len(interesting_rows), len(boring_rows), 6000)
print(f"[+] Sampling {n_samples} from each class (total: {n_samples*2})")

random.shuffle(interesting_rows)
random.shuffle(boring_rows)

rows = []
for r in interesting_rows[:n_samples]:
    r["classification"] = 0
    rows.append(r)
for r in boring_rows[:n_samples]:
    r["classification"] = 1
    rows.append(r)

df = pd.DataFrame(rows, columns=["URL", "Method", "POST Params", "classification"])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "Data_Files", "Training_data_v2.csv")
df.to_csv(out_path, index=False)

print(f"\n[+] Saved {len(df)} rows to {out_path}")
print(f"    Class distribution:\n{df['classification'].value_counts().to_string()}")
print(f"    Method distribution:\n{df['Method'].value_counts().to_string()}")
