"""
NTUSF — Valutazione approfondita del modello ML (XGBoost)
Risponde a 5 domande chiave:
  1. Performance sul training set (metriche interne)
  2. Distribuzione delle probabilità su Juice Shop
  3. Sensitivity analysis: quanti endpoint passano al variare della soglia
  4. Recall sugli endpoint noti come vulnerabili (non filtra i veri positivi?)
  5. Feature importance: cosa guida le decisioni del modello
  6. Analisi del domain shift: quanto è diverso il training set da Juice Shop
"""

import sys, os, warnings, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
warnings.filterwarnings("ignore")

from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, precision_score, recall_score,
    roc_curve, auc
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
from urllib.parse import urlparse, unquote, parse_qs, urlsplit, parse_qsl
import xgboost as xgb

BASE_URL = "localhost:3000"
DF_DIR   = f"results/{BASE_URL}/DF/"
IMG_DIR  = f"results/{BASE_URL}/IMG/"
os.makedirs(IMG_DIR, exist_ok=True)

print("\n" + "═"*65)
print("  NTUSF — Valutazione modello ML")
print("═"*65)

# ─── Carica il modello (riciclo URLClassifier) ────────────────────────────────
from ML.ml import URLClassifier
clf = URLClassifier(base_url=BASE_URL, threshold=0.3, n_estimators=500)
clf.load_data()
clf.preprocess_data()

# ════════════════════════════════════════════════════════════════════════════════
# 1. PERFORMANCE SUL TRAINING SET (80/20 split interno)
# ════════════════════════════════════════════════════════════════════════════════
print("\n[1] Performance sul training set (hold-out 20%)")
print("─"*65)

clf.model.fit(clf.X_train, clf.y_train)
y_pred      = clf.model.predict(clf.X_test)
y_prob      = clf.model.predict_proba(clf.X_test)[:, 1]
train_acc   = clf.model.score(clf.X_train, clf.y_train)
test_acc    = accuracy_score(clf.y_test, y_pred)
f1          = f1_score(clf.y_test, y_pred, average="weighted")
precision   = precision_score(clf.y_test, y_pred, average="weighted")
recall      = recall_score(clf.y_test, y_pred, average="weighted")

print(f"  Training accuracy  : {train_acc*100:.2f}%")
print(f"  Test accuracy      : {test_acc*100:.2f}%")
print(f"  F1 (weighted)      : {f1:.4f}")
print(f"  Precision          : {precision:.4f}")
print(f"  Recall             : {recall:.4f}")

gap = train_acc - test_acc
print(f"  Train/Test gap     : {gap*100:.2f}pp  ", end="")
print("(overfitting)" if gap > 0.05 else "(stabile)")

# Confusion matrix
cm = confusion_matrix(clf.y_test, y_pred)
print(f"\n  Confusion matrix (class 0=benign, 1=malicious):")
print(f"                 Pred 0   Pred 1")
print(f"    Actual  0    {cm[0,0]:6d}   {cm[0,1]:6d}")
print(f"    Actual  1    {cm[1,0]:6d}   {cm[1,1]:6d}")
tn, fp, fn, tp = cm.ravel()
print(f"\n  FPR (false positive rate) : {fp/(fp+tn)*100:.2f}%")
print(f"  FNR (false negative rate) : {fn/(fn+tp)*100:.2f}%")

# ROC curve
fpr_arr, tpr_arr, _ = roc_curve(clf.y_test, y_prob)
roc_auc = auc(fpr_arr, tpr_arr)
print(f"  ROC-AUC                   : {roc_auc:.4f}")

# Plot ROC
fig, ax = plt.subplots(figsize=(7, 5))
ax.plot(fpr_arr, tpr_arr, color="steelblue", lw=2,
        label=f"ROC (AUC = {roc_auc:.3f})")
ax.plot([0,1],[0,1],"k--", lw=1)
ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curve — XGBoost su CSIC 2010")
ax.legend(); plt.tight_layout()
plt.savefig(IMG_DIR + "ml_roc_curve.png", dpi=120)
plt.close()

# 5-fold cross-validation (veloce, sul training set)
print("\n  Cross-validation 5-fold (su training data, 500 estimatori)...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(
    xgb.XGBClassifier(objective="binary:logistic",
                      eval_metric="logloss", n_estimators=500),
    clf.X_train, clf.y_train, cv=cv, scoring="f1_weighted", n_jobs=-1
)
print(f"  CV F1 scores : {[f'{s:.4f}' for s in cv_scores]}")
print(f"  CV mean ± std: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ════════════════════════════════════════════════════════════════════════════════
# 2. DISTRIBUZIONE PROBABILITÀ SU JUICE SHOP
# ════════════════════════════════════════════════════════════════════════════════
print("\n[2] Distribuzione probabilità sui 40 endpoint di Juice Shop")
print("─"*65)

clf.predict()
probs = clf.test_data["Probabilities"].values
print(f"  Min  : {probs.min():.4f}")
print(f"  Max  : {probs.max():.4f}")
print(f"  Mean : {probs.mean():.4f}")
print(f"  Std  : {probs.std():.4f}")

bins = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
hist, edges = np.histogram(probs, bins=bins)
print(f"\n  Distribuzione per bucket di probabilità:")
for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
    bar = "█" * int(hist[i] * 30 / max(hist))
    print(f"    [{lo:.2f}, {hi:.2f})  {hist[i]:3d}  {bar}")

# Print per-URL detail
print(f"\n  Probabilità per endpoint (ordinato decrescente):")
url_probs = clf.test_data[["URL","Probabilities"]].copy()
url_probs = url_probs.sort_values("Probabilities", ascending=False)
for _, row in url_probs.iterrows():
    url_short = row["URL"].replace("http://localhost:3000","")[:55]
    marker = "  ← kept" if row["Probabilities"] < 0.3 else "  [FILTERED OUT]"
    print(f"    {row['Probabilities']:.4f}  {url_short}{marker}")

# Plot distribuzione
fig, ax = plt.subplots(figsize=(9, 4))
ax.hist(probs, bins=20, color="steelblue", edgecolor="white", alpha=0.85)
ax.axvline(0.3, color="red", linestyle="--", lw=2, label="Soglia lax (0.30)")
ax.axvline(0.15, color="orange", linestyle="--", lw=2, label="Soglia strict (0.15)")
ax.set_xlabel("Probabilità predetta (classe malevola)")
ax.set_ylabel("N° endpoint")
ax.set_title("Distribuzione probabilità ML — Juice Shop endpoints")
ax.legend()
plt.tight_layout()
plt.savefig(IMG_DIR + "ml_juiceshop_probs.png", dpi=120)
plt.close()

# ════════════════════════════════════════════════════════════════════════════════
# 3. SENSITIVITY ANALYSIS — quanti endpoint passano al variare della soglia
# ════════════════════════════════════════════════════════════════════════════════
print("\n[3] Sensitivity analysis — endpoint passati al variare della soglia")
print("─"*65)
print(f"  {'Soglia':>8}  {'Endpoint passati':>16}  {'% totale':>10}")
print(f"  {'─'*8}  {'─'*16}  {'─'*10}")
total = len(probs)
for thr in [0.00, 0.05, 0.10, 0.15, 0.20, 0.30, 0.50, 0.70, 1.00]:
    kept = (probs < thr).sum()
    flag = "  ← lax" if thr == 0.30 else ("  ← strict" if thr == 0.15 else
           ("  ← brutal" if thr == 0.00 else ""))
    print(f"  {thr:>8.2f}  {kept:>16d}  {kept/total*100:>9.1f}%{flag}")

# ════════════════════════════════════════════════════════════════════════════════
# 4. RECALL SUI ENDPOINT VULNERABILI NOTI
# ════════════════════════════════════════════════════════════════════════════════
print("\n[4] Recall sugli endpoint vulnerabili noti (dal test run)")
print("─"*65)

# Ground truth from our scan
KNOWN_VULNERABLE = {
    "http://localhost:3000/redirect?to=https%3A%2F%2Fgithub.com%2Fjuice-shop": ["XSS"],
    "http://localhost:3000/rest/products/search?q=apple":                       ["SQLi"],
    "http://localhost:3000/rest/user/whoami":                                   ["CSRF"],
    "http://localhost:3000/api/Users/1":                                        ["CSRF"],
    "http://localhost:3000/rest/user/change-password?current=x&new=y&repeat=y":["CSRF"],
    "http://localhost:3000/api/Users/login":                                    ["CSRF"],
}

url_prob_map = dict(zip(clf.test_data["URL"], clf.test_data["Probabilities"]))

print(f"  {'URL':<55}  {'Prob':>6}  {'Passato (lax 0.3)':>18}  Vuln")
print(f"  {'─'*55}  {'─'*6}  {'─'*18}  ─────")
vuln_kept = 0
for url, vulns in KNOWN_VULNERABLE.items():
    prob = url_prob_map.get(url, -1)
    passed = prob < 0.3
    if passed: vuln_kept += 1
    short = url.replace("http://localhost:3000","")[:55]
    status = "✓  kept" if passed else "✗  FILTERED"
    print(f"  {short:<55}  {prob:>6.4f}  {status:>18}  {', '.join(vulns)}")

print(f"\n  Recall @ soglia 0.3 : {vuln_kept}/{len(KNOWN_VULNERABLE)} = {vuln_kept/len(KNOWN_VULNERABLE)*100:.0f}%")

# ════════════════════════════════════════════════════════════════════════════════
# 5. FEATURE IMPORTANCE
# ════════════════════════════════════════════════════════════════════════════════
print("\n[5] Top-20 feature importance")
print("─"*65)

tfidf_names = clf.tfidf_vectorizer.get_feature_names_out().tolist()
domain_names = ["entropy","query_length","query_params_count","query_punctuations"]
for tok in clf.suspicious_tokens:
    domain_names.append(f"token_{tok}_count")
# Extended features added by v2 dataset
if clf._use_v2:
    domain_names += [
        "has_static_ext", "has_numeric_id", "is_api_path",
        "method_is_post", "has_post_params", "num_post_params",
        "has_sensitive_param", "path_depth", "has_redirect_param",
        "has_auth_keyword", "has_admin_keyword", "has_boring_path",
    ]
feature_names = tfidf_names + domain_names

importances = clf.model.feature_importances_
fi_df = pd.DataFrame({"feature": feature_names, "importance": importances})
fi_df = fi_df.sort_values("importance", ascending=False).head(20)

for _, row in fi_df.iterrows():
    bar = "█" * int(row["importance"] * 500)
    print(f"  {row['importance']:.5f}  {row['feature']:<35}  {bar}")

# Plot feature importance
fig, ax = plt.subplots(figsize=(9, 7))
sns.barplot(data=fi_df, x="importance", y="feature",
            palette="Blues_r", ax=ax)
ax.set_title("Top-20 Feature Importance — XGBoost")
ax.set_xlabel("Importance")
plt.tight_layout()
plt.savefig(IMG_DIR + "ml_feature_importance.png", dpi=120)
plt.close()

# ════════════════════════════════════════════════════════════════════════════════
# 6. DOMAIN SHIFT ANALYSIS
# ════════════════════════════════════════════════════════════════════════════════
print("\n[6] Analisi domain shift: training set vs Juice Shop")
print("─"*65)

from ML.ml import URLClassifier as _C
_inst = _C.__new__(_C)
_inst.suspicious_tokens = clf.suspicious_tokens

def avg_tokens(urls):
    count = 0
    for url in urls:
        url_low = unquote(str(url)).lower()
        for tok in clf.suspicious_tokens:
            count += url_low.count(tok)
    return count / len(urls)

def url_entropy(url):
    url = str(url)
    prob = [float(url.count(c))/len(url) for c in dict.fromkeys(list(url))]
    return -sum(p * np.log2(p) for p in prob)

train_urls  = clf.training_data["URL"].tolist()
juice_urls  = clf.test_data["URL"].tolist()

print(f"  {'Metric':<35} {'Training':>12} {'Juice Shop':>12}")
print(f"  {'─'*35} {'─'*12} {'─'*12}")

train_lens   = [len(str(u)) for u in train_urls]
juice_lens   = [len(str(u)) for u in juice_urls]
print(f"  {'Avg URL length':<35} {np.mean(train_lens):>12.1f} {np.mean(juice_lens):>12.1f}")

train_ent  = [url_entropy(u) for u in train_urls[:5000]]  # sample
juice_ent  = [url_entropy(u) for u in juice_urls]
print(f"  {'Avg URL entropy':<35} {np.mean(train_ent):>12.3f} {np.mean(juice_ent):>12.3f}")

train_tok = avg_tokens(train_urls[:5000])
juice_tok = avg_tokens(juice_urls)
print(f"  {'Avg suspicious token matches':<35} {train_tok:>12.3f} {juice_tok:>12.3f}")

# Vocabulary overlap
train_sample = clf.training_data["URL"].head(10000).apply(clf.clean_url)
juice_clean  = clf.test_data["URL"].apply(clf.clean_url)
train_vocab  = set(" ".join(train_sample).split())
juice_vocab  = set(" ".join(juice_clean).split())
overlap      = train_vocab & juice_vocab
print(f"  {'TF-IDF vocabulary size (train)':<35} {len(train_vocab):>12,}")
print(f"  {'Unique tokens in Juice Shop URLs':<35} {len(juice_vocab):>12,}")
print(f"  {'Vocabulary overlap':<35} {len(overlap):>12,}  ({len(overlap)/len(juice_vocab)*100:.0f}% of JS tokens in training)")

# ════════════════════════════════════════════════════════════════════════════════
# SOMMARIO FINALE
# ════════════════════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print("  SOMMARIO VALUTAZIONE ML")
print("═"*65)
print(f"""
  Dataset training  : CSIC 2010 HTTP Dataset
                      {len(clf.training_data):,} richieste HTTP → app JSP spagnola 2010
                      Classe 0 (benign): {(clf.training_data['classification']==0).sum():,}
                      Classe 1 (malicious): {(clf.training_data['classification']==1).sum():,}

  Performance interna (hold-out 20%):
    Accuracy  : {test_acc*100:.2f}%  (training: {train_acc*100:.2f}%)
    F1        : {f1:.4f}
    ROC-AUC   : {roc_auc:.4f}
    CV F1     : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}

  Comportamento su Juice Shop:
    Endpoint totali   : {total}
    Filtrati (lax)    : {(probs >= 0.3).sum()} / {total}
    Passati (lax)     : {(probs < 0.3).sum()} / {total}
    Range probabilità : [{probs.min():.4f}, {probs.max():.4f}]

  Recall su endpoint vulnerabili noti:
    {vuln_kept}/{len(KNOWN_VULNERABLE)} passano il filtro (soglia 0.3)

  Immagini salvate in: {IMG_DIR}
    - ml_roc_curve.png
    - ml_juiceshop_probs.png
    - ml_feature_importance.png
""")
