
import os, re, time, threading, queue, json, logging, math, traceback
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Config
APP_TITLE = "Cloud Credential Leakage Detection & Auto-Revocation "
APP_SUBTITLE = "Regex + AI detection (TF-IDF fallback) "

    # thresholds
HIGH_CONF_THRESHOLD = float(os.getenv("HIGH_CONF_THRESHOLD", "0.80"))
MEDIUM_CONF_THRESHOLD = float(os.getenv("MEDIUM_CONF_THRESHOLD", "0.60"))

    # In-memory stores
FINDINGS = []
APPROVALS = []
AUDIT = []
_next_finding_id = 1
_next_approval_id = 1
lock = threading.Lock()
REVOKE_QUEUE = queue.Queue()

    # Patterns (same as your original)
PATTERNS = {
        "AWS_ACCESS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
        "GITHUB_PAT": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "GITHUB_TOKEN": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "SLACK_TOKEN": re.compile(r"xox[baprs]-[A-Za-z0-9]{10,48}"),
        "GCP_PRIVATE_KEY": re.compile(r'\"private_key\":\\s*\"-----BEGIN PRIVATE KEY-----'),
    }

    # Minimal TF-IDF fallback AI (toy)
try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        TF_READY = True
except Exception:
        TF_READY = False

class SimpleAI:
        def __init__(self):
            self.use_transformer = False
            if TF_READY:
                self.vec = TfidfVectorizer(analyzer='char', ngram_range=(3,6))
                X = ["AKIA1111111111111111", "ghp_abcdefghijklmnopqrstuvwxyz012345", "xoxp-ABCDEFGHIJKLMNOP", "random_text", "placeholder"]
                y = [1,1,1,0,0]
                try:
                    self.vec.fit(X)
                    self.clf = LogisticRegression().fit(self.vec.transform(X), y)
                except Exception as e:
                    logging.warning("TF fallback init issue: %s", e)
                    self.clf = None
            else:
                self.vec = None
                self.clf = None
        def score(self, token, context=""):
            if self.clf is None:
                return 0.0
            txt = token if not context else token + " " + context[:200]
            try:
                return float(self.clf.predict_proba(self.vec.transform([txt]))[0][1])
            except Exception as e:
                logging.error("AI.score error: %s", e)
                return 0.0

AI = SimpleAI()

    # heuristics
def token_entropy(s: str) -> float:
        if not s: return 0.0
        counts = Counter(s)
        length = len(s)
        ent = -sum((cnt/length) * math.log2(cnt/length) for cnt in counts.values())
        max_ent = math.log2(62) if length > 0 else 1.0
        return min(1.0, ent/max_ent)

def fuse_scores(regex_score, ai_score, entropy_score):
        w_regex = 0.30; w_ai = 0.55; w_entropy = 0.15
        fused = (w_regex*regex_score) + (w_ai*ai_score) + (w_entropy*entropy_score)
        return max(0.0, min(1.0, fused))

def risk_level_from_score(score: float) -> str:
        if score >= HIGH_CONF_THRESHOLD: return "HIGH"
        if score >= MEDIUM_CONF_THRESHOLD: return "MEDIUM"
        return "LOW"

def mask_token(token: str) -> str:
        if not token: return ""
        if len(token) <= 8: return token[:2] + "***"
        return token[:4] + "*"*(len(token)-8) + token[-4:]

def add_audit(event, details):
    with lock:
        AUDIT.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details
        })
        created_at = datetime.now(timezone.utc).isoformat()
        datetime.utcnow().isoformat()
    # persistence (optional)
PERSISTENCE_FILE = os.getenv("PERSISTENCE_FILE", "leakrd_state.json")
ENABLE_PERSISTENCE = os.getenv("ENABLE_PERSISTENCE", "true").lower() == "true"
def save_state(path=PERSISTENCE_FILE):
        if not ENABLE_PERSISTENCE: return
        try:
            with open(path, "w") as fh:
                json.dump({"findings": FINDINGS, "approvals": APPROVALS, "audit": AUDIT}, fh, default=str, indent=2)
        except Exception as e:
            logging.error("save_state error: %s", e)
def load_state(path=PERSISTENCE_FILE):
        global _next_finding_id, _next_approval_id
        if not ENABLE_PERSISTENCE or not os.path.exists(path): return
        try:
            with open(path, "r") as fh:
                state = json.load(fh)
            FINDINGS.clear(); APPROVALS.clear(); AUDIT.clear()
            FINDINGS.extend(state.get("findings", []))
            APPROVALS.extend(state.get("approvals", []))
            AUDIT.extend(state.get("audit", []))
            max_fid = max([f.get("id",0) for f in FINDINGS] or [0])
            max_aid = max([a.get("id",0) for a in APPROVALS] or [0])
            _next_finding_id = max_fid + 1; _next_approval_id = max_aid + 1
        except Exception as e:
            logging.error("load_state error: %s", e)
load_state()

    # insert & process
def insert_finding(rec):
        global _next_finding_id
        with lock:
            rec["id"] = _next_finding_id; _next_finding_id += 1
            FINDINGS.insert(0, rec)
        add_audit("finding_inserted", f"id={rec['id']} pattern={rec['pattern']} score={rec['fused_score']:.3f}")
        if ENABLE_PERSISTENCE: save_state()
        return rec

def process_candidate(source, location, pattern_name, candidate, context):
        regex_score = 1.0
        ai_sc = AI.score(candidate, context)
        ent_sc = token_entropy(candidate)
        fused = fuse_scores(regex_score, ai_sc, ent_sc)
        level = risk_level_from_score(fused)
        rec = {"source": source, "location": location, "pattern": pattern_name,
               "sample_masked": mask_token(candidate), "sample_raw": None,
               "context": context, "regex_score": regex_score, "ai_score": ai_sc,
               "entropy_score": ent_sc, "fused_score": fused, "risk_level": level,
               "validated": False, "valid": False, "revoked": False, "created_at": datetime.utcnow().isoformat()}
        return insert_finding(rec)

def scan_text(text, source="upload", location="upload"):
        out = []
        for pname, regex in PATTERNS.items():
            for m in regex.finditer(text):
                cand = m.group(0)
                ctx = text[max(0,m.start()-200):m.end()+200]
                out.append(process_candidate(source, location, pname, cand, ctx))
        return out

def scan_local_folder(folder="demo"):
        res = []
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        for root, _, files in os.walk(folder):
            for fname in files:
                if not fname.lower().endswith(('.py','.txt','.env','.json','.yaml','.yml','.md')):
                    continue
                p = os.path.join(root, fname)
                try:
                    with open(p, 'r', errors='ignore') as fh:
                        txt = fh.read()
                    res.extend(scan_text(txt, source="local", location=p))
                except Exception as e:
                    logging.warning("read file error: %s", e)
        return res

    # approvals & revoke (simulated)
def request_revoke_in_memory(finding_id, requester="user"):
        global _next_approval_id
        with lock:
            ap = {"id": _next_approval_id, "finding_id": finding_id, "action": "revoke", "requester": requester,
                  "approved": False, "approver": None, "details": None, "created_at": datetime.utcnow().isoformat()}
            _next_approval_id += 1
            APPROVALS.insert(0, ap)
        add_audit("revoke_requested", f"approval_id={ap['id']} finding_id={finding_id} requester={requester}")
        if ENABLE_PERSISTENCE: save_state()
        return ap

def perform_revoke_simulated(finding_id):
        with lock:
            for f in FINDINGS:
                if f["id"] == finding_id:
                    f["revoked"] = True; f["updated_at"] = datetime.utcnow().isoformat()
                    add_audit("revoke_simulated", f"finding_id={finding_id}")
                    if ENABLE_PERSISTENCE: save_state()
                    return True, "simulated_revoked"
        return False, "finding_not_found"

    # revoke worker
def revoke_worker_loop():
        logging.info("Revoke worker started.")
        while True:
            try:
                job = REVOKE_QUEUE.get(timeout=2)
            except Exception:
                time.sleep(1); continue
            try:
                approval_id = job.get("approval_id"); finding_id = job.get("finding_id")
                ok, resp = perform_revoke_simulated(finding_id)
                with lock:
                    for a in APPROVALS:
                        if a["id"] == approval_id:
                            a["approved"] = True; a["approver"] = "simulated"; a["details"] = resp; a["approved_at"] = datetime.utcnow().isoformat()
                            break
                add_audit("revoke_processed", f"approval_id={approval_id} finding_id={finding_id} ok={ok} resp={resp}")
            except Exception as e:
                logging.error("revoke_worker_loop error: %s", e)
                traceback.print_exc()

    # start worker safely (avoid multiple starts in streamlit reruns)
if "revoke_worker_started" not in st.session_state:
        _worker_thread = threading.Thread(target=revoke_worker_loop, daemon=True)
        _worker_thread.start()
        st.session_state.revoke_worker_started = True

    # Streamlit UI
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE); st.caption(APP_SUBTITLE)
st.markdown("**Safety:** Simulated by default. Enable real revocation only in test accounts.")

    # sidebar
st.sidebar.header("Controls"); scan_source = st.sidebar.selectbox("Scan source", ["Upload file","Local demo folder","Simulated GitHub"])
st.sidebar.markdown("---"); st.sidebar.markdown("Model options"); st.sidebar.write("TF-IDF fallback used")

tabs = st.tabs(["🔍 Scan","📊 Findings","📈 Analytics","⚙️ Admin","🧠 Model"])

with tabs[0]:
        st.header("Scan")
        if scan_source == "Upload file":
            uploaded = st.file_uploader("Upload file", type=["py","txt","env","json","yaml","yml","md"])
            if uploaded:
                raw = uploaded.read().decode("utf-8", errors="ignore")
                st.code(raw[:2000] + ("\n\n... (truncated)" if len(raw)>2000 else ""))
                if st.button("Scan uploaded file"):
                    items = scan_text(raw, source="upload", location=f"upload:{uploaded.name}")
                    st.success(f"Scan complete: {len(items)} findings.")
        elif scan_source == "Local demo folder":
            st.write("demo folder: demo/")
            if st.button("Scan demo folder"):
                items = scan_local_folder("demo")
                st.success(f"Scanned demo folder: {len(items)} findings.")
        else:
            st.write("Simulated GitHub scan")
            if st.button("Run simulated GitHub scan"):
                frags = ["AKIA1111111111111111","ghp_abcdEFGHijklMNOPqrstUVWXyz0123456789","xoxp-AAAAAAAAAAAA"]
                out = []
                for i,f in enumerate(frags):
                    content = f"# simulated file {i}\nsecret='{f}'\n"
                    out.extend(scan_text(content, source="github-sim", location=f"https://github.com/demo/repo/file{i}.py"))
                st.success(f"Simulated created {len(out)} findings.")

with tabs[1]:
        st.header("Findings (in-memory)")
        if not FINDINGS: st.info("No findings yet. Run a scan.")
        else:
            df = pd.DataFrame(FINDINGS); df['created_at'] = pd.to_datetime(df['created_at'])
            st.dataframe(df[['id','source','location','pattern','sample_masked','fused_score','risk_level','validated','revoked','created_at']])
            sel = st.number_input("Enter Finding ID", min_value=0, step=1, value=0)
            if sel:
                f = next((x for x in FINDINGS if x['id']==int(sel)), None)
                if not f: st.error("Not found")
                else:
                    st.write(f)
                    if st.button("Request Revoke"):
                        ap = request_revoke_in_memory(int(sel), requester="streamlit_user"); st.success(f"Approval requested id={ap['id']}")
                    if st.button("Force Revoke (simulated)"):
                        ok, msg = perform_revoke_simulated(int(sel)); st.info(f"ok={ok} msg={msg}")

with tabs[2]:
        st.header("Analytics")
        if not FINDINGS: st.info("No data")
        else:
            df = pd.DataFrame(FINDINGS); df['created_at']=pd.to_datetime(df['created_at']); df['date']=df['created_at'].dt.date
            counts = df.groupby('date').size().reset_index(name='count'); avg = df.groupby('date')['fused_score'].mean().reset_index(name='avg_score')
            merged = counts.merge(avg, on='date'); st.plotly_chart(px.line(merged, x='date', y='count', title='Daily Leak Count'), use_container_width=True)
            st.plotly_chart(px.histogram(df, x='fused_score', nbins=40, title='Risk Score Distribution'), use_container_width=True)

with tabs[3]:
        st.header("Admin / Approvals")
        if not APPROVALS: st.info("No approvals yet.") 
        else: st.dataframe(pd.DataFrame(APPROVALS))
        ap_id = st.number_input("Approval ID", min_value=0, step=1, value=0, key='ap_id')
        if st.button("Approve & Enqueue"):
            if ap_id<=0: st.error("Enter id")
            else:
                ap = next((a for a in APPROVALS if a['id']==int(ap_id)), None)
                if not ap: st.error("Approval not found")
                else:
                    REVOKE_QUEUE.put({'approval_id':ap['id'],'finding_id':ap['finding_id']}); st.success("Enqueued revoke job")
        if st.button("Create Approval (demo)"):
            fid_manual = st.number_input("Finding ID for approval", min_value=0, step=1, value=0, key='fid_manual')
            if fid_manual>0: ap = request_revoke_in_memory(int(fid_manual), requester='demo_user'); st.success(f"Approval created id={ap['id']}")

with tabs[4]:
        st.header("Model")
        st.info("TF-IDF fallback used for scoring in this demo. You can retrain with positive/negative samples (toy)")
        pos = st.text_area("Positive samples", value="AKIA1111111111111111\nghp_abcdefghijklmnopqrstuvwxyz0123456789")
        neg = st.text_area("Negative samples", value="placeholder_token\nexample_text")
        if st.button("Retrain TF-IDF (demo)"):
            pos_list = [x.strip() for x in pos.splitlines() if x.strip()]; neg_list=[x.strip() for x in neg.splitlines() if x.strip()]
            if pos_list and neg_list and TF_READY:
                X = pos_list + neg_list; y=[1]*len(pos_list)+[0]*len(neg_list)
                try:
                    AI.vec.fit(X); AI.clf.fit(AI.vec.transform(X), y); st.success("Retrained TF-IDF fallback")
                except Exception as e:
                    st.error(f"Retrain failed: {e}")
            else:
                st.error("Provide samples and ensure scikit-learn is installed")
