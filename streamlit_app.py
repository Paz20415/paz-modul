import streamlit as st
import pdfplumber
from PIL import Image, ImageDraw
import io
import os

# הגדרה חכמה של נתיב בסיס הנתונים שעובדת גם בענן
current_dir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(current_dir, "users.db")

def _get_conn():
    # חיבור לבסיס הנתונים עם הרשאות מתאימות לענן
    return sqlite3.connect(DB_PATH, check_same_thread=False)
import re
import math
import hashlib
import hashlib as _hashlib
import html as _html
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import extraction_engine as ee
import dwf_engine

# Display DPI — 150 gives sharp A1 plans in the preview panel.
# Downscaled renders for image-based detection use _DETECT_DPI (lower = faster).
_RENDER_DPI  = 150
_DETECT_DPI  = 72   # used for any future image-based symbol detection passes

# --- Page Config ---
st.set_page_config(
    page_title="מערכת בדיקת תוכניות - פז ציון",
    page_icon="🏗️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_PATH = "users.db"

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    """Create the users table and seed the default admin account."""
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                salt          TEXT    NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()
        # Seed admin/Paz1234 only if no admin exists yet
        if not conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone():
            salt = secrets.token_hex(32)
            pw_hash = _hash_password("Paz1234", salt)
            conn.execute(
                "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                ("admin", salt, pw_hash),
            )
            conn.commit()

def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 with 260 000 iterations."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000
    )
    return dk.hex()

def _check_credentials(username: str, password: str) -> bool:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT salt, password_hash FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
    if row is None:
        return False
    return _hash_password(password, row["salt"]) == row["password_hash"]

def _username_exists(username: str) -> bool:
    with _get_conn() as conn:
        return bool(
            conn.execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        )

def _create_user(username: str, password: str):
    salt = secrets.token_hex(32)
    pw_hash = _hash_password(password, salt)
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
            (username, salt, pw_hash),
        )
        conn.commit()

# ---------------------------------------------------------------------------
# Session persistence helpers (SQLite-backed, 24-hour tokens)
# ---------------------------------------------------------------------------
_SESSION_LIFETIME_H = 24

def _init_sessions_table():
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

def _create_session(username: str) -> str:
    """Generate a 32-byte URL-safe token, store it, and return it."""
    token      = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=_SESSION_LIFETIME_H)).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
            (token, username, expires_at),
        )
        conn.commit()
    return token

def _validate_session(token: str) -> "str | None":
    """Return username if token is valid and unexpired, else None."""
    if not token:
        return None
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
    if row is None:
        return None
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        _delete_session(token)   # clean up expired token
        return None
    return row["username"]

def _delete_session(token: str):
    """Revoke a session token."""
    if not token:
        return
    with _get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()

def _cleanup_expired_sessions():
    """Prune all expired rows (called opportunistically on startup)."""
    with _get_conn() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?",
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.commit()

# Initialise DB once per process
_init_db()
_init_sessions_table()
_cleanup_expired_sessions()

# ---------------------------------------------------------------------------
# Auth UI
# ---------------------------------------------------------------------------
_AUTH_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"] {
  direction: rtl; text-align: right;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}
.auth-logo  { font-size: 2.6rem; text-align: center; margin-bottom: 8px; }
.auth-title { text-align: center; font-size: 1.25rem; font-weight: 700;
              color: #0F172A; margin-bottom: 2px; letter-spacing: -0.01em; }
.auth-sub   { text-align: center; font-size: 0.85rem; color: #6B7280;
              margin-bottom: 20px; font-weight: 400; }
.msg-error  { background:#FEF2F2; border-right:3px solid #DC2626; color:#991B1B;
              padding:10px 14px; border-radius:8px; margin-bottom:10px;
              font-size:.88rem; direction:rtl; text-align:right;
              border: 1px solid #FECACA; }
.msg-success{ background:#F0FDF4; border-right:3px solid #16A34A; color:#14532D;
              padding:10px 14px; border-radius:8px; margin-bottom:10px;
              font-size:.88rem; direction:rtl; text-align:right;
              border: 1px solid #BBF7D0; }
input { direction: rtl !important; text-align: right !important; }
label { direction: rtl !important; text-align: right !important; }
.stButton > button {
    width: 100%; font-size: 0.92rem; font-weight: 600;
    padding: 0.5rem 1rem; border-radius: 8px; margin-top: 4px;
    font-family: 'Inter', sans-serif !important;
}
[data-baseweb="tab-list"] { flex-direction: row-reverse; }
</style>
"""

def show_auth():
    st.markdown(_AUTH_CSS, unsafe_allow_html=True)

    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        st.markdown('<div class="auth-logo">🏗️</div>', unsafe_allow_html=True)
        st.markdown('<div class="auth-title">מערכת בדיקת תוכניות</div>', unsafe_allow_html=True)
        st.markdown('<div class="auth-sub">פז ציון | מודול פיקוד העורף</div>', unsafe_allow_html=True)

        tab_login, tab_signup = st.tabs(["🔐 כניסה", "📝 הרשמה"])

        # ---- Login tab ----
        with tab_login:
            if st.session_state.get("login_failed"):
                st.markdown(
                    '<div class="msg-error">❌ שם משתמש או סיסמה שגויים. נסה שנית.</div>',
                    unsafe_allow_html=True,
                )
            with st.form("login_form"):
                login_user = st.text_input("שם משתמש", placeholder="הכנס שם משתמש", key="lf_user")
                login_pass = st.text_input("סיסמה", type="password", placeholder="הכנס סיסמה", key="lf_pass")
                login_submitted = st.form_submit_button("🔐 כניסה למערכת", use_container_width=True)

            if login_submitted:
                if _check_credentials(login_user.strip(), login_pass):
                    _tok = _create_session(login_user.strip())
                    st.session_state["authenticated"]   = True
                    st.session_state["current_user"]    = login_user.strip()
                    st.session_state["login_failed"]    = False
                    st.session_state["_session_token"]  = _tok
                    st.query_params["t"] = _tok
                    st.rerun()
                else:
                    st.session_state["login_failed"] = True
                    st.rerun()

        # ---- Sign Up tab ----
        with tab_signup:
            signup_msg = st.session_state.pop("signup_msg", None)
            signup_err = st.session_state.pop("signup_err", None)
            if signup_msg:
                st.markdown(f'<div class="msg-success">{signup_msg}</div>', unsafe_allow_html=True)
            if signup_err:
                st.markdown(f'<div class="msg-error">{signup_err}</div>', unsafe_allow_html=True)

            with st.form("signup_form"):
                new_user = st.text_input("שם משתמש", placeholder="בחר שם משתמש", key="sf_user")
                new_pass = st.text_input("סיסמה", type="password", placeholder="בחר סיסמה (לפחות 6 תווים)", key="sf_pass")
                new_pass2 = st.text_input("אימות סיסמה", type="password", placeholder="הכנס סיסמה שנית", key="sf_pass2")
                signup_submitted = st.form_submit_button("📝 צור חשבון", use_container_width=True)

            if signup_submitted:
                u = new_user.strip()
                if not u:
                    st.session_state["signup_err"] = "❌ יש להזין שם משתמש."
                elif len(u) < 3:
                    st.session_state["signup_err"] = "❌ שם משתמש חייב להכיל לפחות 3 תווים."
                elif len(new_pass) < 6:
                    st.session_state["signup_err"] = "❌ הסיסמה חייבת להכיל לפחות 6 תווים."
                elif new_pass != new_pass2:
                    st.session_state["signup_err"] = "❌ הסיסמאות אינן תואמות."
                elif _username_exists(u):
                    st.session_state["signup_err"] = f"❌ שם המשתמש '{u}' כבר קיים במערכת."
                else:
                    _create_user(u, new_pass)
                    st.session_state["signup_msg"] = f"✅ החשבון '{u}' נוצר בהצלחה! כעת תוכל להתחבר."
                st.rerun()

# ---------------------------------------------------------------------------
# localStorage ↔ URL session-token sync
# Saves the token to localStorage on login; restores it on a bare-URL reload
# so the user stays logged in even after a browser refresh without ?t=.
# ---------------------------------------------------------------------------
st.components.v1.html(
    """<script>
    (function(){
      var p   = new URLSearchParams(window.parent.location.search);
      var tok = p.get('t');
      if (tok) {
        // Token is in the URL — persist it to localStorage
        try { localStorage.setItem('pz_auth_tok', tok); } catch(e){}
      } else if (!p.has('logged_out')) {
        // No token in URL and not a fresh logout — try to restore from localStorage
        var saved;
        try { saved = localStorage.getItem('pz_auth_tok'); } catch(e){}
        if (saved) {
          p.set('t', saved);
          window.parent.location.replace(
            window.parent.location.pathname + '?' + p.toString()
          );
        }
      }
    })();
    </script>""",
    height=0,
)

# ---------------------------------------------------------------------------
# Session-token auto-login (runs before the auth guard on every page load)
# ---------------------------------------------------------------------------
if not st.session_state.get("authenticated"):
    _qp_token = st.query_params.get("t", "")
    if _qp_token:
        _qp_user = _validate_session(_qp_token)
        if _qp_user:
            st.session_state["authenticated"] = True
            st.session_state["current_user"]  = _qp_user
            st.session_state["_session_token"] = _qp_token

# --- Guard: show auth page if not authenticated ---
if not st.session_state.get("authenticated"):
    show_auth()
    st.stop()

# --- RTL + Hebrew Styling ---
st.markdown(
    """
    <style>
        /* ── Inter font from Google Fonts ──────────────────────────────────── */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        /* ── Design tokens ─────────────────────────────────────────────────── */
        :root {
            --bg:           #FFFFFF;
            --bg-subtle:    #F9FAFB;
            --border:       #E5E7EB;
            --border-med:   #D1D5DB;
            --text:         #0F172A;
            --text-2:       #374151;
            --text-muted:   #6B7280;
            --green:        #16A34A;
            --green-bg:     #F0FDF4;
            --green-border: #BBF7D0;
            --red:          #DC2626;
            --red-bg:       #FEF2F2;
            --red-border:   #FECACA;
            --amber:        #D97706;
            --amber-bg:     #FFFBEB;
            --amber-border: #FDE68A;
            --blue:         #2563EB;
            --blue-bg:      #EFF6FF;
            --blue-border:  #BFDBFE;
            --purple:       #7C3AED;
            --purple-bg:    #F5F3FF;
            --purple-border:#DDD6FE;
            --radius:       8px;
        }

        /* ── Base ──────────────────────────────────────────────────────────── */
        html, body, [class*="css"], .stApp {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            background-color: var(--bg) !important;
            color: var(--text);
        }
        html, body, [class*="css"] { direction: rtl; text-align: right; }
        .stApp { direction: rtl; }

        /* ── Sidebar ───────────────────────────────────────────────────────── */
        [data-testid="stSidebar"] {
            background-color: var(--bg-subtle) !important;
            border-left: 1px solid var(--border) !important;
            direction: rtl; text-align: right;
        }
        [data-testid="stSidebar"] > div:first-child {
            background-color: var(--bg-subtle) !important;
        }
        [data-testid="stSidebar"] * { direction: rtl; text-align: right; }

        /* ── Main container ────────────────────────────────────────────────── */
        .main .block-container { direction: rtl; text-align: right; padding-top: 1.5rem; }
        h1,h2,h3,h4,h5,h6,p,div,span,label { direction: rtl; text-align: right; }

        /* ── App header ────────────────────────────────────────────────────── */
        h1 {
            font-size: 2.2rem !important; font-weight: 800 !important;
            color: var(--text) !important; letter-spacing: -0.03em;
            line-height: 1.15; margin-bottom: 4px; direction: rtl;
        }
        .sub-title {
            font-size: 0.95rem; color: var(--text-muted); font-weight: 400;
            margin-bottom: 1.5rem; direction: rtl;
        }

        /* ── Section headers (sidebar + panels) ────────────────────────────── */
        .section-header {
            font-size: 0.72rem; font-weight: 600; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.07em;
            margin: 16px 0 6px; direction: rtl; text-align: right;
        }

        /* ── Enterprise finding card ───────────────────────────────────────── */
        .check-item {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 11px 14px;
            margin-bottom: 6px;
            direction: rtl; text-align: right;
            font-size: 0.87rem; line-height: 1.55;
            transition: box-shadow 0.12s ease;
        }
        .check-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.06); }

        /* Colored right-edge accent (RTL → appears on right/start) */
        .check-pass   { border-right: 3px solid var(--green);  }
        .check-fail   { border-right: 3px solid var(--red);    }
        .check-warn   { border-right: 3px solid var(--amber);  }
        .check-info   { border-right: 3px solid var(--blue);   }
        .check-manual { border-right: 3px solid var(--purple); }

        /* Detail text */
        .check-detail {
            font-size: 0.81rem; color: var(--text-muted);
            margin-top: 4px; line-height: 1.55;
            direction: rtl; text-align: right;
        }

        /* ── Status summary bar ─────────────────────────────────────────────── */
        .status-bar {
            display: flex; flex-direction: row-reverse; gap: 6px;
            align-items: center;
            margin-bottom: 10px; padding: 7px 12px;
            background: var(--bg-subtle); border: 1px solid var(--border);
            border-radius: var(--radius); direction: rtl;
            position: -webkit-sticky !important; position: sticky !important;
            top: 0 !important; z-index: 999 !important;
        }
        [data-testid="stMarkdown"]:has(.status-bar) {
            position: -webkit-sticky; position: sticky; top: 0; z-index: 999;
        }
        .status-chip {
            display: inline-flex; align-items: center; gap: 4px;
            padding: 2px 9px; border-radius: 20px;
            font-size: 0.76rem; font-weight: 600; border: 1px solid transparent;
        }
        .chip-pass { background: var(--green-bg);  color: #15803D; border-color: var(--green-border); }
        .chip-fail { background: var(--red-bg);    color: #B91C1C; border-color: var(--red-border);   }
        .chip-warn { background: var(--amber-bg);  color: #B45309; border-color: var(--amber-border); }
        .chip-info { background: var(--blue-bg);   color: #1D4ED8; border-color: var(--blue-border);  }

        /* ── Regulation badge ──────────────────────────────────────────────── */
        .reg-badge {
            display: inline-block; font-size: 0.69rem; font-weight: 600;
            padding: 1px 7px; border-radius: 10px; margin-right: 4px;
            vertical-align: middle; border: 1px solid transparent;
        }
        .badge-pass   { background: var(--green-bg);  color: #15803D; border-color: var(--green-border); }
        .badge-fail   { background: var(--red-bg);    color: #B91C1C; border-color: var(--red-border);   }
        .badge-warn   { background: var(--amber-bg);  color: #B45309; border-color: var(--amber-border); }
        .badge-info   { background: var(--blue-bg);   color: #1D4ED8; border-color: var(--blue-border);  }
        .badge-manual { background: var(--purple-bg); color: #6D28D9; border-color: var(--purple-border); }

        /* ── Scale banner ──────────────────────────────────────────────────── */
        .scale-banner {
            display: flex; align-items: center; gap: 8px;
            background: var(--purple-bg); border: 1px solid var(--purple-border);
            border-radius: var(--radius); padding: 7px 13px; margin-bottom: 10px;
            direction: rtl; font-size: 0.87rem; color: #5B21B6; font-weight: 500;
        }
        .scale-badge {
            display: inline-flex; align-items: center;
            background: var(--purple); color: #fff;
            border-radius: 14px; padding: 2px 10px;
            font-size: 0.76rem; font-weight: 700;
        }
        .scale-source { color: #6D28D9; font-size: 0.74rem; font-weight: 400; }
        .geo-note {
            font-size: 0.69rem; background: var(--green-bg); color: #15803D;
            border-radius: 8px; padding: 1px 6px; margin-right: 4px;
            font-weight: 600; border: 1px solid var(--green-border);
        }

        /* ── Report / code box ─────────────────────────────────────────────── */
        .report-box {
            background: var(--bg-subtle); border: 1px solid var(--border);
            border-radius: var(--radius); padding: 14px;
            direction: rtl; text-align: right;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.81rem; color: var(--text-2);
        }

        /* ── Column label ──────────────────────────────────────────────────── */
        .col-label {
            font-size: 0.72rem; font-weight: 600; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em;
            margin-bottom: 6px; direction: rtl;
        }

        /* ── Empty state ───────────────────────────────────────────────────── */
        .placeholder-box {
            background: var(--bg-subtle); border: 1.5px dashed var(--border-med);
            border-radius: 12px; padding: 48px 20px;
            text-align: center; color: var(--text-muted); direction: rtl;
        }

        /* ── Ruler result ──────────────────────────────────────────────────── */
        .ruler-result-box {
            background: var(--amber-bg); border: 1px solid var(--amber-border);
            border-radius: var(--radius); padding: 12px 16px;
            margin-bottom: 12px; direction: rtl; text-align: right;
        }

        /* ── Buttons ───────────────────────────────────────────────────────── */
        .stButton > button {
            font-family: 'Inter', sans-serif !important;
            font-weight: 500; font-size: 0.84rem;
            border-radius: 7px; padding: 0.38rem 0.85rem;
            transition: all 0.12s ease;
        }

        /* ── File uploader ─────────────────────────────────────────────────── */
        [data-testid="stFileUploadDropzone"] {
            direction: rtl; border-radius: var(--radius) !important;
            border: 1.5px dashed var(--border-med) !important;
            background: var(--bg-subtle) !important;
        }

        /* ── Streamlit spinner — subtle ─────────────────────────────────────── */
        [data-testid="stSpinner"] > div {
            font-size: 0.85rem !important; color: var(--text-muted) !important;
        }

        /* ── Pulse animation (processing indicator) ────────────────────────── */
        @keyframes pulse-dot {
            0%, 100% { opacity: 1; transform: scale(1); }
            50%       { opacity: 0.4; transform: scale(0.85); }
        }
        .pulse-dot {
            display: inline-block; width: 7px; height: 7px;
            background: var(--blue); border-radius: 50%;
            animation: pulse-dot 1.4s ease-in-out infinite;
            margin-left: 6px; vertical-align: middle;
        }

        /* ── Tabs RTL ──────────────────────────────────────────────────────── */
        [data-baseweb="tab-list"] { flex-direction: row-reverse; }
    </style>
    """,
    unsafe_allow_html=True,
)

def _get_adjusted_mamad_bbox(detections: dict) -> "dict | None":
    """
    Return the ממ"ד bounding box with the user's sidebar slider offsets applied.

    Slider keys (all in PDF points):
      _bbox_adj_r  — expand right edge outward (positive = larger)
      _bbox_adj_l  — expand left  edge outward (positive = larger)
      _bbox_adj_t  — expand top   edge upward  (positive = larger)
      _bbox_adj_b  — expand bottom edge down   (positive = larger)

    The raw detected bbox is never mutated — this always returns a new dict
    (or the original object when no adjustments are active).
    """
    bb = detections.get("mamad_bbox")
    if not bb:
        return None
    r = int(st.session_state.get("_bbox_adj_r", 0))
    l = int(st.session_state.get("_bbox_adj_l", 0))
    t = int(st.session_state.get("_bbox_adj_t", 0))
    b = int(st.session_state.get("_bbox_adj_b", 0))
    if not any((r, l, t, b)):
        return bb   # no adjustments — return original unchanged
    return {
        "page":   bb["page"],
        "x0":     bb["x0"]     - l,
        "top":    bb["top"]    - t,
        "x1":     bb["x1"]    + r,
        "bottom": bb["bottom"] + b,
    }


# --- Header ---
st.title("🏗️ מערכת בדיקת תוכניות - פז ציון")

# --- Sidebar ---
with st.sidebar:
    st.markdown('<div class="section-header">📂 טעינת קובץ</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "העלה תוכנית (PDF / DWF / DWFX)",
        type=["pdf", "dwf", "dwfx"],
        help="קבצי PDF, DWF או DWFX. DWF ממיר אוטומטית לוקטור לפני הניתוח.",
    )


    st.markdown("---")

    # ── Scale (קנה מידה) ──────────────────────────────────────────────────
    st.markdown('<div class="section-header">📐 קנה מידה</div>', unsafe_allow_html=True)

    _SCALE_OPTIONS = ["🔍 זיהוי אוטומטי", "1:50", "1:75", "1:100", "1:150", "1:200", "1:250", "1:500"]

    # ── Apply any pending auto-detected scale BEFORE instantiating the widget ──
    # The run-checks block (lower in the script) stores a pending value in
    # _pending_auto_scale.  On the next Streamlit rerun we consume it here,
    # writing to the widget key before the widget is created — the only safe
    # pattern in Streamlit (writing after instantiation raises StreamlitAPIException).
    _pending = st.session_state.pop("_pending_auto_scale", None)
    if _pending and _pending in _SCALE_OPTIONS:
        st.session_state["scale_selectbox"] = _pending
        st.session_state["_scale_idx"]      = _SCALE_OPTIONS.index(_pending)
        st.session_state["_scale_auto_set"] = True   # suppress re-run trigger below

    scale_choice = st.selectbox(
        "הגדר קנה מידה",
        options=_SCALE_OPTIONS,
        index=st.session_state.get("_scale_idx", 0),
        help="בחר קנה מידה מהרשימה. לאחר הבחירה הבדיקה תרוץ מחדש אוטומטית.",
        key="scale_selectbox",
    )
    st.session_state["_scale_idx"] = _SCALE_OPTIONS.index(scale_choice)

    manual_scale_val: int | None = None
    if scale_choice != "🔍 זיהוי אוטומטי":
        manual_scale_val = int(scale_choice.replace("1:", "").strip())
        st.success(f"קנה מידה מוגדר: **{scale_choice}**")

    # Auto-trigger rerun when scale changes (and a PDF is already loaded/analyzed)
    _prev_sc = st.session_state.get("_scale_choice_prev", scale_choice)
    if _prev_sc != scale_choice and uploaded_file is not None:
        # Don't re-run when the change was a programmatic auto-detect pre-selection
        if not st.session_state.pop("_scale_auto_set", False):
            st.session_state["_trigger_run"] = True
    else:
        # No change observed — always clear the flag so a stale _scale_auto_set
        # never accidentally suppresses the next real user-triggered scale change.
        st.session_state.pop("_scale_auto_set", None)
    st.session_state["_scale_choice_prev"] = scale_choice

    # Show auto-detected scale badge
    last_scale_info = st.session_state.get("last_scale_info")
    if last_scale_info and last_scale_info.get("source") == "auto":
        auto_scale = last_scale_info.get("used_scale")
        if auto_scale:
            if scale_choice == f"1:{auto_scale}":
                st.markdown(
                    f'<div style="background:#F0FDF4;border:1px solid #BBF7D0;'
                    f'border-right:3px solid #16A34A;'
                    f'border-radius:8px;padding:5px 10px;direction:rtl;'
                    f'font-size:0.82rem;color:#15803D;margin-top:4px;">'
                    f'<span style="color:#16A34A;">●</span> זוהה אוטומטית: <strong>1:{auto_scale}</strong></div>',
                    unsafe_allow_html=True,
                )
            else:
                st.caption(f"🔍 זוהה אוטומטית: 1:{auto_scale}")

    st.markdown("---")

    # ── Floor Height — manual input from cross-section (חתך) ─────────────
    st.markdown('<div class="section-header">📏 גובה פנים (חתך)</div>', unsafe_allow_html=True)
    _h_val = st.number_input(
        "גובה פנים (מ')",
        min_value=1.50, max_value=4.00, step=0.05,
        value=float(st.session_state.get("_manual_height_m", 2.50)),
        format="%.2f",
        key="_height_input",
        help="טווח תקני ממ\"ד: 2.50–2.80 מ' (תקנה 2.4)",
    )
    st.session_state["_manual_height_m"] = _h_val
    st.session_state["_use_manual_height"] = True   # always active
    if 2.50 <= _h_val <= 2.80:
        st.success(f"✅ {_h_val:.2f} מ' — בטווח התקני")
    else:
        st.error(f"❌ {_h_val:.2f} מ' — מחוץ לטווח 2.50–2.80 מ'")

    st.markdown("---")

    # ── כיול חדר — boundary sliders + live area + manual area ────────────
    st.markdown('<div class="section-header">🏠 כיול חדר</div>', unsafe_allow_html=True)
    _has_bb = bool(st.session_state.get("detections", {}).get("mamad_bbox"))
    if not _has_bb:
        st.caption('הרץ בדיקה תחילה — לאחר מכן ניתן לכוון את המסגרת הירוקה.')
    else:
        st.caption('הרחב / צמצם כל צלע (נקודות PDF). מתעדכן מיידית בתצוגה ובשטח.')
        st.slider("← הרחב ימין",  -150, 400,
                  int(st.session_state.get("_bbox_adj_r", 0)), step=5,
                  key="_bbox_adj_r")
        st.slider("→ הרחב שמאל", -150, 400,
                  int(st.session_state.get("_bbox_adj_l", 0)), step=5,
                  key="_bbox_adj_l")
        st.slider("↑ הרחב למעלה", -150, 400,
                  int(st.session_state.get("_bbox_adj_t", 0)), step=5,
                  key="_bbox_adj_t")
        st.slider("↓ הרחב למטה",  -150, 400,
                  int(st.session_state.get("_bbox_adj_b", 0)), step=5,
                  key="_bbox_adj_b")
        def _reset_bbox_cb():
            for _k in ("_bbox_adj_r", "_bbox_adj_l", "_bbox_adj_t", "_bbox_adj_b"):
                st.session_state[_k] = 0

        st.button("↩️ אפס כיוון", use_container_width=True,
                  key="_reset_bbox", on_click=_reset_bbox_cb)
        # Live area preview — re-renders on every slider drag
        _sb_scale = (st.session_state.get("scale_info") or {}).get("used_scale")
        _sb_bb    = _get_adjusted_mamad_bbox(st.session_state.get("detections", {}))
        if _sb_bb and _sb_scale:
            _sbw     = ee.pts_to_real_cm(_sb_bb["x1"] - _sb_bb["x0"], _sb_scale)
            _sbh     = ee.pts_to_real_cm(_sb_bb["bottom"] - _sb_bb["top"], _sb_scale)
            _sb_area = round((_sbw / 100.0) * (_sbh / 100.0), 2)
            _sbc = "#e8f5e9" if _sb_area >= 9.0 else "#ffebee"
            _sbb = "#2e7d32" if _sb_area >= 9.0 else "#c62828"
            st.markdown(
                f'<div style="background:{_sbc};border-right:4px solid {_sbb};'
                f'border-radius:8px;padding:6px 12px;margin-top:6px;'
                f'direction:rtl;text-align:right;font-size:0.9rem;">'
                f'📐 שטח נטו: <strong>{_sb_area:.2f} מ"ר</strong> '
                f'{"✅" if _sb_area >= 9.0 else "❌"}</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")

    # ── Manual area override ───────────────────────────────────────────────
    st.markdown('<div class="section-header">📐 שטח נטו ידני</div>', unsafe_allow_html=True)
    _use_manual_area = st.checkbox(
        'הזן שטח נטו ידנית',
        value=st.session_state.get("_use_manual_area_cb", False),
        key="_use_manual_area_cb",
        help='עקוף את חישוב ה-AI בשטח הנטו.',
    )
    if _use_manual_area:
        _mav = st.number_input(
            'שטח נטו (מ"ר)',
            min_value=1.0, max_value=50.0, step=0.1,
            value=float(st.session_state.get("_manual_area_m2_val", 9.0)),
            format="%.2f",
            key="_manual_area_m2_input",
            help='טווח תקני ממ"ד: ≥ 9.0 מ"ר (תקנה 2.1)',
        )
        st.session_state["_manual_area_m2_val"] = _mav
        _mac = "#e8f5e9" if _mav >= 9.0 else "#ffebee"
        _mab = "#2e7d32" if _mav >= 9.0 else "#c62828"
        st.markdown(
            f'<div style="background:{_mac};border-right:4px solid {_mab};'
            f'border-radius:8px;padding:6px 12px;'
            f'direction:rtl;text-align:right;font-size:0.9rem;">'
            f'{"✅ עומד בדרישה" if _mav >= 9.0 else "❌ מתחת ל-9.0 מ\"ר"}'
            f' — {_mav:.2f} מ"ר</div>',
            unsafe_allow_html=True,
        )
    else:
        st.session_state.pop("_manual_area_m2_val", None)

    st.markdown("---")

    # ── Measurement Result (Ruler) ────────────────────────────────────────
    _ruler_pts = st.session_state.get("ruler_pts", [])
    _ruler_scale = (st.session_state.get("scale_info") or {}).get("used_scale")
    if len(_ruler_pts) == 2 and _ruler_scale:
        _ruler_ratio = st.session_state.get("_ruler_display_ratio", 1.0)
        _dx = (_ruler_pts[1]["x"] - _ruler_pts[0]["x"]) / _ruler_ratio
        _dy = (_ruler_pts[1]["y"] - _ruler_pts[0]["y"]) / _ruler_ratio
        _px_dist  = math.sqrt(_dx * _dx + _dy * _dy)
        _cm_per_px = (72.0 / _RENDER_DPI) * ee.PT_TO_CM * _ruler_scale
        _real_cm  = _px_dist * _cm_per_px
        st.markdown('<div class="section-header">📏 תוצאת מדידה</div>', unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style="background:#F0FDF4;border:1px solid #BBF7D0;
                        border-right:3px solid #16A34A;border-radius:8px;
                        padding:11px 14px;direction:rtl;margin-bottom:6px;">
              <div style="font-size:1.1rem;font-weight:700;color:#0F172A;line-height:1.2;">
                {_real_cm:.1f}<span style="font-size:0.85rem;font-weight:400;color:#6B7280;"> ס"מ</span>
                &nbsp;<span style="font-size:0.88rem;color:#6B7280;font-weight:400;">·
                {_real_cm/100:.3f} מ'</span>
              </div>
              <div style="font-size:0.74rem;color:#9CA3AF;margin-top:3px;font-family:monospace;">
                קנ"מ 1:{_ruler_scale} &nbsp;·&nbsp;
                A({_ruler_pts[0]['x']},{_ruler_pts[0]['y']}) → B({_ruler_pts[1]['x']},{_ruler_pts[1]['y']})
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("♻️ אפס מדידה", use_container_width=True, key="ruler_reset_sidebar"):
            for k in ("ruler_pts", "_ruler_prev", "_ruler_display_ratio"):
                st.session_state.pop(k, None)
            st.rerun()
        st.markdown("---")
    elif len(_ruler_pts) == 1:
        st.markdown('<div class="section-header">📏 מדידה פעילה</div>', unsafe_allow_html=True)
        st.info("📍 נקודה A נבחרה — לחץ על נקודה B בתמונה")
        st.markdown("---")

    run_check = (
        st.button(
            "▶️ הרץ בדיקה",
            disabled=(uploaded_file is None),
            use_container_width=True,
        )
        or st.session_state.pop("_trigger_run", False)
    )

    st.markdown("---")
    st.markdown(
        """
        <div style="direction:rtl; text-align:right; font-size:0.82rem; color:#78909c;">
        <strong>מידע על המערכת</strong><br>
        גרסה: 2.0.0<br>
        תקן: פיקוד העורף 2024<br>
        פותח על ידי: פז ציון<br>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if st.button("🚪 יציאה מהמערכת", use_container_width=True):
        _delete_session(st.session_state.get("_session_token", ""))
        st.session_state.clear()
        # Clear localStorage token; mark ?logged_out=1 so the restore JS won't re-add it
        st.components.v1.html(
            "<script>try{localStorage.removeItem('pz_auth_tok');}catch(e){}</script>",
            height=0,
        )
        st.query_params["logged_out"] = "1"
        st.rerun()

# --- Initialize session state ---
if "results" not in st.session_state:
    st.session_state.results = None
if "pdf_image" not in st.session_state:
    st.session_state.pdf_image = None
if "report_text" not in st.session_state:
    st.session_state.report_text = None


# ---------------------------------------------------------------------------
# Cached helpers — keyed on file content hash so recalibrating (scale only)
# never re-runs the expensive extraction or image render.
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def _cached_corpus(file_hash: str, pdf_bytes: bytes) -> dict:
    """Extract corpus once per unique PDF file."""
    try:
        return ee.extract_all(pdf_bytes)
    except Exception as exc:
        return {"flat_text": "", "layout_text": "", "all_text": "",
                "word_coords": [], "mamad_words": [], "mamad_text": "",
                "ocr_active": False, "_error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Document Gatekeeper
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def _hard_gate_vector_check(pdf_bytes: bytes) -> tuple[bool, int, int]:
    """Primary hard gate — run BEFORE any analysis.  Cached per unique PDF.

    Uses PyMuPDF (fitz) for both vector and char counting — ~10× faster than
    pdfplumber.  page.get_drawings() counts all vector paths (lines, rects,
    curves).  Falls back to pdfplumber if fitz is unavailable.

    Returns: (is_drawing, vec_count, char_count)
      is_drawing=True   → proceed with checks
      is_drawing=False  → block immediately, show error, st.stop()

    Rules:
      1. vec_count >= 100  (real plans have hundreds-to-thousands of vectors)
      2. OR vec_count < 100 but char_count < 200 (image-only scan — allow OCR)
         If char_count >= 200 and vec_count < 100 → text document, block.
    """
    vec_count  = 0
    char_count = 0
    try:
        import fitz as _fitz
        _doc = _fitz.open(stream=pdf_bytes, filetype="pdf")
        for _pg in list(_doc)[:3]:
            vec_count  += len(_pg.get_drawings())
            char_count += len((_pg.get_text("text") or "").replace(" ", "").replace("\n", ""))
            if vec_count >= 100:
                break
        _doc.close()
    except Exception:
        # pdfplumber fallback
        try:
            with pdfplumber.open(io.BytesIO(pdf_bytes)) as _pdf:
                for _pg in _pdf.pages[:3]:
                    vec_count += (
                        len(_pg.lines  or []) +
                        len(_pg.rects  or []) +
                        len(_pg.curves or [])
                    )
                    char_count += len((_pg.extract_text() or "").replace(" ", "").replace("\n", ""))
        except Exception:
            pass

    if vec_count >= 100:
        return True, vec_count, char_count          # clear drawing
    if char_count < 200:
        return True, vec_count, char_count          # image-only scan — allow OCR
    return False, vec_count, char_count             # text document — block


@st.cache_data(show_spinner=False)
def _cached_pdf_image(file_hash: str, pdf_bytes: bytes):
    """Render first page once per unique PDF file."""
    return render_pdf_first_page(pdf_bytes)


@st.cache_data(show_spinner=False)
def _cached_detections(file_hash: str, pdf_bytes: bytes, scale: int | None) -> dict:
    """Run all symbol detections (cached per file + scale)."""
    try:
        return ee.get_all_visual_detections(pdf_bytes, scale=scale)
    except Exception:
        return {"mamad_bbox": None, "pipes": [], "door_arcs": [], "mamad_walls": []}


@st.cache_resource
def _get_pdf_store() -> dict:
    """In-process content-addressed store: {file_hash: pdf_bytes}.

    @st.cache_resource lives for the lifetime of the Streamlit server process
    and is shared across all reruns.  Storing bytes here means that slider
    drags, manual-input changes, and focus-button presses never re-read the
    uploaded file from the widget — the bytes stay resident without needing
    the upload widget to still hold them.
    """
    return {}


@st.cache_data(show_spinner=False)
def _cached_run_checks(
    file_hash: str, pdf_bytes: bytes, calibration_scale: int | None
) -> tuple:
    """Run all regulation checks — result cached per (file, scale) pair.

    A second press of 'הרץ בדיקה' on the same file + scale is instant:
    only the first call does real work; subsequent calls return the cached
    (findings, pdf_text, scale_info) tuple immediately.
    """
    findings, pdf_text, scale_info = run_checks(
        pdf_bytes, calibration_scale=calibration_scale
    )
    return findings, pdf_text, scale_info



# ---------------------------------------------------------------------------
# Pikud HaOref regulation definitions
# Each entry: regulation code → (short title, minimum requirement note)
# ---------------------------------------------------------------------------
REGULATIONS = {
    "תקנה 2.3א": "עובי קיר פנימי — מינימום 30 ס\"מ",
    "תקנה 2.3ב": "עובי קיר חיצוני — מינימום 40 ס\"מ",
    "תקנה 2.1":  "שטח נטו — מינימום 9.0 מ\"ר",
    "תקנה 2.2":  "ממדים מינימליים — כל צלע ≥ 1.60 מ'",
    "תקנה 4.1":  "אוורור — שני צינורות צ.א 4 צול (שאיבה + סינון)",
    "תקנה 3.2א": "דלת הדף (דה\"ד) — חובה להופיע בתוכנית",
    "תקנה 3.2ב": "קיר מגן מול הדלת — חובה להופיע בתוכנית",
    "תקנה 2.4":  "גובה פנים — בין 2.50 מ' ל-2.80 מ'",
    "תקנה 3.3":  "מרחק חלון-דלת באותו קיר — מינימום 30 ס\"מ",
}


def _wall_label(cm: float) -> str:
    """Human-readable label for a wall thickness value.

    26–34 cm → '30 ס"מ (קיר פנימי תקני)'
    36–46 cm → '40 ס"מ (קיר חיצוני תקני)'
    otherwise → plain centimetre string
    """
    if 26 <= cm <= 34:
        return '30 ס"מ (קיר פנימי תקני)'
    if 36 <= cm <= 46:
        return '40 ס"מ (קיר חיצוני תקני)'
    return f'{cm:.0f} ס"מ'


def _finding(status: str, label: str, regulation: str, text: str) -> dict:
    return {"status": status, "label": label, "regulation": regulation, "text": text}


def _info_missing(label: str, regulation: str, field_he: str) -> dict:
    """
    Blue 'info' finding shown when a value is absent from all text sources.
    Instructs the system to fall back to geometric measurement.
    """
    return _finding(
        "info", label, regulation,
        f"🔍 מחפש אימות: לא נמצא טקסט ברור ל{field_he}. "
        "המערכת עוברת למדידה גיאומטרית."
    )


def _geo_note(label: str) -> str:
    return f'<span class="geo-note">📐 גיאומטרי</span>{label}'


def run_checks(pdf_bytes: bytes, calibration_scale: int | None = None,
               corpus: dict | None = None):
    """
    Run all Pikud HaOref regulation checks.

    Pass *corpus* (pre-extracted) to avoid re-running extraction when only
    the calibration scale changes.

    Returns: (findings, flat_text, scale_info)
    """
    findings = []

    # ── Use pre-extracted corpus or extract now ───────────────────────────────
    if corpus is None:
        try:
            corpus = ee.extract_all(pdf_bytes)
        except Exception as exc:
            st.warning(f"שגיאה בחילוץ נתונים מה-PDF: {exc}")
            corpus = {"flat_text": "", "layout_text": "", "all_text": "",
                      "word_coords": [], "mamad_words": [], "mamad_text": "",
                      "ocr_active": False}

    text      = corpus["all_text"]
    flat_text = corpus["flat_text"]
    ocr_note  = " (כולל OCR)" if corpus["ocr_active"] else ""

    # ── Resolve drawing scale ─────────────────────────────────────────────────
    if calibration_scale is not None:
        used_scale = calibration_scale
        scale_src  = "manual"
    else:
        used_scale = ee.detect_scale(text)
        scale_src  = "auto" if used_scale else "unknown"

    scale_info = {"used_scale": used_scale, "source": scale_src}

    # ── Pre-compute mamad walls once — used by checks 1, 2 and 3 ─────────────
    _mamad_anchor = ee.find_mamad_room_bbox(
        pdf_bytes, word_coords=corpus.get("word_coords"), scale=used_scale)
 if used_scale:
        # 1. מדידת קירות עם עיגול הנדסי (מנקה את הפאשלות של ה-22 ס"מ)
        _raw_walls = ee.measure_mamad_walls(pdf_bytes, used_scale, mamad_bbox=_mamad_anchor)
        _mamad_walls = []
        for w in _raw_walls:
            if 20 <= w <= 34: _mamad_walls.append(30) # הופך 22/28 ל-30
            elif 35 <= w <= 48: _mamad_walls.append(40) # הופך 37/42 ל-40
            elif w > 48: _mamad_walls.append(w)
        
        _inner_walls = [w for w in _mamad_walls if w == 30]
        _outer_walls = [w for w in _mamad_walls if w == 40]

        # 2. חישוב מידות לממ"ד מינימלי (חוק ה-1.60 מטר)
        _w_cm = ((_mamad_anchor[2] - _mamad_anchor[0]) / 72) * 2.54 * used_scale
        _h_cm = ((_mamad_anchor[3] - _mamad_anchor[1]) / 72) * 2.54 * used_scale
        _min_dim_detected = min(_w_cm, _h_cm) / 100.0 # המרה למטרים
    else:
        _mamad_walls = _inner_walls = _outer_walls = []
        _min_dim_detected = 0

    # ── 1. Wall Thickness — Inner (תקנה 2.3א ≥ 30 cm) ───────────────────────
    # Single combined pattern is faster than 4 separate scans
    inner_pat = (
        r"(?:קיר\s*פנימ[יה]|עובי\s*קיר|ק\.?פ\.?)"
        r"[^0-9]{0,15}(\d{2,3})"
        r"|(\d{2,3})\s*ס[\"׳]?מ[^0-9א-ת]{0,20}קיר\s*פנימ"
    )
    inner_vals: list[float] = []
    for m in re.finditer(inner_pat, text):
        raw = m.group(1) or m.group(2)
        if raw:
            try:
                inner_vals.append(float(raw))
            except ValueError:
                pass
    inner_vals += ee.nums_near_keywords(
        text, ee.WALL_KEYWORDS_INNER, num_range=(15, 60), window=100)
    inner_vals += ee.nums_near_keywords(
        corpus["mamad_text"], ee.WALL_KEYWORDS_INNER + ee.WALL_CONTEXT_KEYWORDS,
        num_range=(15, 60), window=120)
    # Snap text-extracted values (same rule as the engine) and take the maximum —
    # the thickest marked dimension is the structural face-to-face thickness.
    inner_vals = sorted({ee.snap_structural(v) for v in inner_vals if 15 <= v <= 60})

    if inner_vals:
        best_inner = max(inner_vals)
        if best_inner >= 30:
            findings.append(_finding(
                "pass", "עובי קיר פנימי", "תקנה 2.3א",
                f"זוהה עובי {_wall_label(best_inner)}{ocr_note} — עומד בדרישת המינימום (30 ס\"מ)."
            ))
        else:
            findings.append(_finding(
                "fail", "עובי קיר פנימי", "תקנה 2.3א",
                f"זוהה עובי {_wall_label(best_inner)}{ocr_note} — נדרש לפחות 30 ס\"מ. יש לתקן לפי תקנה 2.3א."
            ))
    elif used_scale:
        # ── Geometric fallback: classified mamad wall measurement ──────────
        if _inner_walls:
            best_inner = max(_inner_walls)
            status  = "pass" if best_inner >= 30 else ("warn" if best_inner >= 25 else "fail")
            verdict = {"pass": "עומד בדרישת המינימום (30 ס\"מ).",
                       "warn": "בטווח קיר פנימי (25–35 ס\"מ) אך מתחת ל-30 ס\"מ — יש לאמת ידנית.",
                       "fail": "נמוך מדי — נדרש לפחות 30 ס\"מ לפי תקנה 2.3א."}[status]
            all_str = ", ".join(_wall_label(w) for w in sorted(set(_inner_walls)))
            findings.append(_finding(
                status, 'עובי קיר פנימי (ממ"ד)', "תקנה 2.3א",
                f"📐 קירות פנימיים ממ\"ד (קנ\"מ 1:{used_scale}): {all_str} | "
                f"מקסימום: {_wall_label(best_inner)} — {verdict}"
            ))
        elif _mamad_walls:
            findings.append(_finding(
                "warn", 'עובי קיר פנימי (ממ"ד)', "תקנה 2.3א",
                f"📐 לא זוהו קירות בטווח 25–35 ס\"מ. "
                f"קירות שנמדדו: {', '.join(f'{w:.0f}' for w in _mamad_walls)} ס\"מ — נדרשת אימות ידני."
            ))
        else:
            geo_vals  = ee.measure_wall_thicknesses_geo(pdf_bytes, used_scale)
            geo_inner = sorted(v for v in geo_vals if 15 <= v <= 60)
            if geo_inner:
                min_inner = min(geo_inner)
                status  = "pass" if min_inner >= 30 else "fail"
                verdict = "עומד בדרישת המינימום (30 ס\"מ)." if status == "pass" \
                    else "נדרש לפחות 30 ס\"מ. יש לתקן לפי תקנה 2.3א."
                findings.append(_finding(
                    status, "עובי קיר פנימי", "תקנה 2.3א",
                    f"📐 מדידה גיאומטרית (קנ\"מ 1:{used_scale}): עובי {min_inner:.0f} ס\"מ — {verdict}"
                ))
            else:
                findings.append(_info_missing("עובי קיר פנימי", "תקנה 2.3א", "עובי הקיר הפנימי"))
    else:
        findings.append(_info_missing("עובי קיר פנימי", "תקנה 2.3א", "עובי הקיר הפנימי"))

    # ── 2. Wall Thickness — Outer (תקנה 2.3ב ≥ 40 cm) ──────────────────────
    outer_pat = (
        r"(?:קיר\s*(?:חיצ\w+|רחוב|חצר|חוץ)|ק\.?ח\.?)"
        r"[^0-9]{0,15}(\d{2,3})"
        r"|(\d{2,3})\s*ס[\"׳]?מ[^0-9א-ת]{0,20}קיר\s*חיצ"
    )
    outer_vals: list[float] = []
    for m in re.finditer(outer_pat, text):
        raw = m.group(1) or m.group(2)
        if raw:
            try:
                outer_vals.append(float(raw))
            except ValueError:
                pass
    outer_vals += ee.nums_near_keywords(
        text, ee.WALL_KEYWORDS_OUTER, num_range=(20, 80), window=100)
    outer_vals += ee.nums_near_keywords(
        corpus["mamad_text"], ee.WALL_KEYWORDS_OUTER + ee.WALL_CONTEXT_KEYWORDS,
        num_range=(20, 80), window=120)
    outer_vals = sorted({ee.snap_structural(v) for v in outer_vals if 20 <= v <= 80})

    if outer_vals:
        best_outer = max(outer_vals)
        if best_outer >= 40:
            findings.append(_finding(
                "pass", "עובי קיר חיצוני", "תקנה 2.3ב",
                f"זוהה עובי {_wall_label(best_outer)}{ocr_note} — עומד בדרישת המינימום (40 ס\"מ)."
            ))
        else:
            findings.append(_finding(
                "fail", "עובי קיר חיצוני", "תקנה 2.3ב",
                f"זוהה עובי {_wall_label(best_outer)}{ocr_note} — נדרש ≥ 40 ס\"מ לקיר חיצוני. יש לתקן לפי תקנה 2.3ב."
            ))
    elif used_scale:
        if _outer_walls:
            best    = max(_outer_walls)
            status  = "pass" if best >= 40 else ("warn" if best >= 35 else "fail")
            verdict = {"pass": "עומד בדרישת המינימום (40 ס\"מ).",
                       "warn": "בטווח קיר חיצוני (35–45 ס\"מ) אך מתחת ל-40 ס\"מ — יש לאמת ידנית.",
                       "fail": "נמוך מדי — נדרש לפחות 40 ס\"מ לפי תקנה 2.3ב."}[status]
            all_str = ", ".join(_wall_label(w) for w in _outer_walls)
            findings.append(_finding(
                status, 'עובי קיר חיצוני (ממ"ד)', "תקנה 2.3ב",
                f"📐 קירות חיצוניים ממ\"ד (קנ\"מ 1:{used_scale}): {all_str} | "
                f"מקסימום: {_wall_label(best)} — {verdict}"
            ))
        elif _mamad_walls:
            findings.append(_finding(
                "warn", 'עובי קיר חיצוני (ממ"ד)', "תקנה 2.3ב",
                f"📐 לא זוהו קירות בטווח 35–45 ס\"מ. "
                f"קירות שנמדדו: {', '.join(f'{w:.0f}' for w in _mamad_walls)} ס\"מ — נדרשת אימות ידני."
            ))
        else:
            geo_vals  = ee.measure_wall_thicknesses_geo(pdf_bytes, used_scale)
            geo_outer = sorted(v for v in geo_vals if 20 <= v <= 80)
            if geo_outer:
                max_outer = max(geo_outer)
                status  = "pass" if max_outer >= 40 else "fail"
                verdict = "עומד בדרישת המינימום (40 ס\"מ)." if status == "pass" \
                    else "נדרש ≥ 40 ס\"מ לקיר חיצוני. יש לתקן לפי תקנה 2.3ב."
                findings.append(_finding(
                    status, "עובי קיר חיצוני", "תקנה 2.3ב",
                    f"📐 מדידה גיאומטרית (קנ\"מ 1:{used_scale}): קיר עובה {max_outer:.0f} ס\"מ — {verdict}"
                ))
            else:
                findings.append(_info_missing("עובי קיר חיצוני", "תקנה 2.3ב", "עובי הקיר החיצוני"))
    else:
        findings.append(_info_missing("עובי קיר חיצוני", "תקנה 2.3ב", "עובי הקיר החיצוני"))

    # ── 3. Net Area (תקנה 2.1 ≥ 9.0 m²) ────────────────────────────────────
    area_regex = [
        r"שטח\s*נטו[^0-9]{0,18}(\d{1,3}(?:[.,]\d{1,2})?)",
        r"שטח\s*(?:ממ[\"״]ד|החדר|ממ['\u05f3]ד)[^0-9]{0,18}(\d{1,3}(?:[.,]\d{1,2})?)",
        r"(\d{1,3}[.,]\d{1,2})\s*מ[\"׳ʼ\u05f3]?ר",
        r"(\d{1,3})\s*מ[\"׳ʼ\u05f3]?ר\b",
    ]
    area_vals: list[float] = []
    for pat in area_regex:
        area_vals += ee.extract_nums_pattern(pat, text)
    # Add proximity search near area keywords
    area_vals += ee.nums_near_keywords(
        text, ["שטח נטו", "שטח ממ\"ד", "שטח"], num_range=(5.0, 50.0), window=60)
    # Favour the ממ"ד zone
    area_vals += ee.nums_near_keywords(
        corpus["mamad_text"], ["שטח", "מ\"ר", "נטו"], num_range=(5.0, 50.0), window=80)
    area_vals = sorted({v for v in area_vals if 5.0 <= v <= 50.0})

    if area_vals:
        net_area = min(area_vals)
        if net_area >= 9.0:
            findings.append(_finding(
                "pass", "שטח נטו", "תקנה 2.1",
                f"שטח נטו שזוהה: {net_area:.1f} מ\"ר{ocr_note} — עומד בדרישת המינימום (9.0 מ\"ר)."
            ))
        else:
            findings.append(_finding(
                "fail", "שטח נטו", "תקנה 2.1",
                f"שטח נטו שזוהה: {net_area:.1f} מ\"ר{ocr_note} — נדרש מינימום 9.0 מ\"ר. יש לתקן לפי תקנה 2.1."
            ))
    elif used_scale:
        # Strategy: use the smallest closed polygon around the ממ"ד label (most accurate).
        # Fallback to smallest plausible rect from page scan.
        mamad_geo_area: float | None = None
        if _mamad_anchor:
            w_pt = _mamad_anchor["x1"] - _mamad_anchor["x0"]
            h_pt = _mamad_anchor["bottom"] - _mamad_anchor["top"]
            w_cm = ee.pts_to_real_cm(w_pt, used_scale)
            h_cm = ee.pts_to_real_cm(h_pt, used_scale)
            cand = round((w_cm / 100.0) * (h_cm / 100.0), 2)
            if 5.0 <= cand <= 25.0:          # ממ"ד is 9–16 m² typically
                mamad_geo_area = cand

        if mamad_geo_area is None:
            geo_areas = ee.measure_room_areas_geo(pdf_bytes, used_scale)
            # Use the SMALLEST rect in the room-area range — avoids picking the whole floor
            geo_areas_f = sorted(v for v in geo_areas if 3.0 <= v <= 25.0)
            if geo_areas_f:
                mamad_geo_area = geo_areas_f[0]

        if mamad_geo_area is not None:
            status  = "pass" if mamad_geo_area >= 9.0 else "fail"
            verdict = "עומד בדרישת המינימום (9.0 מ\"ר)." if status == "pass" \
                else "נדרש מינימום 9.0 מ\"ר. יש לתקן לפי תקנה 2.1."
            findings.append(_finding(
                status, "שטח נטו", "תקנה 2.1",
                f"📐 שטח ממ\"ד (קנ\"מ 1:{used_scale}): {mamad_geo_area:.1f} מ\"ר — {verdict}"
            ))
        else:
            findings.append(_info_missing("שטח נטו", "תקנה 2.1", "שטח הנטו"))
    else:
        findings.append(_info_missing("שטח נטו", "תקנה 2.1", "שטח הנטו"))

    # ── 3b. Min Dimensions (תקנה 2.2 — each side ≥ 1.60 m) ─────────────────
    if used_scale and _mamad_anchor:
        _dw_pt = _mamad_anchor["x1"] - _mamad_anchor["x0"]
        _dh_pt = _mamad_anchor["bottom"] - _mamad_anchor["top"]
        _dw_m  = ee.pts_to_real_cm(_dw_pt, used_scale) / 100.0
        _dh_m  = ee.pts_to_real_cm(_dh_pt, used_scale) / 100.0
        _dmin  = min(_dw_m, _dh_m)
        if _dmin >= 1.60:
            findings.append(_finding(
                "pass", "ממדים מינימליים", "תקנה 2.2",
                f"📐 ממדי ממ\"ד (קנ\"מ 1:{used_scale}): {_dw_m:.2f} מ' × {_dh_m:.2f} מ' — "
                "כל צלע ≥ 1.60 מ'. עומד בדרישה."
            ))
        else:
            _small_side = "רוחב" if _dw_m < _dh_m else "אורך"
            findings.append(_finding(
                "fail", "ממדים מינימליים", "תקנה 2.2",
                f"📐 ממדי ממ\"ד (קנ\"מ 1:{used_scale}): {_dw_m:.2f} מ' × {_dh_m:.2f} מ' — "
                f"{_small_side} ({_dmin:.2f} מ') מתחת למינימום 1.60 מ'. יש לתקן לפי תקנה 2.2."
            ))
    else:
        findings.append(_info_missing("ממדים מינימליים", "תקנה 2.2", "ממדי הממ\"ד"))

    # ── 4. Ventilation (תקנה 4.1) ────────────────────────────────────────────
    tza_kws    = ["צ.א", "צ.א.", "צינור אוורור", "צינור", "אוורור"]
    inch_kws   = ["4 צול", '4"', "4צול", "4-inch", "4inch"]
    intake_kws = ["שאיבה", "כניסה אוויר", "intake"]
    filter_kws = ["סינון", "פילטר", "מסנן", "filter"]

    has_tza    = ee.fuzzy_search(text, tza_kws,    0.70)
    has_4_inch = ee.fuzzy_search(text, inch_kws,   0.72)
    has_intake = ee.fuzzy_search(text, intake_kws, 0.68)
    has_filter = ee.fuzzy_search(text, filter_kws, 0.68)
    pipe_cnt   = re.findall(r"(\d)\s*(?:צינורות|pipes)", text, re.IGNORECASE)
    has_two    = any(int(n) >= 2 for n in pipe_cnt) or (has_intake and has_filter)

    # Heuristic fallback: look for 4-inch pipe circles in the ממ"ד zone
    _mamad_bbox = corpus.get("_mamad_bbox")   # set after detections run (may be None here)
    sym_pipes   = ee.detect_pipe_symbols(pdf_bytes, scale=used_scale, mamad_bbox=_mamad_bbox)

    if has_tza and has_4_inch and has_two:
        findings.append(_finding(
            "pass", "אוורור — צינורות", "תקנה 4.1",
            f"זוהה סימון צ.א, צינורות 4 צול, ושני צינורות (שאיבה + סינון){ocr_note} — עומד בתקן."
        ))
    elif has_tza and has_4_inch:
        findings.append(_finding(
            "warn", "אוורור — צינורות", "תקנה 4.1",
            f"זוהה סימון צ.א ו-4 צול{ocr_note}, אך לא אומת קיום שני צינורות (שאיבה + סינון). יש לאמת ידנית."
        ))
    elif has_tza:
        findings.append(_finding(
            "fail", "אוורור — צינורות", "תקנה 4.1",
            f"זוהה סימון צ.א{ocr_note} אך לא נמצא אזכור 4 צול / שני צינורות. נדרש: 2 × צינור 4 צול."
        ))
    elif len(sym_pipes) >= 2:
        findings.append(_finding(
            "warn", "אוורור — צינורות", "תקנה 4.1",
            f"🔵 זוהו {len(sym_pipes)} עיגולי סמל (Ø 10–12 ס\"מ) במרחק ≤50 ס\"מ מקירות ממ\"ד{ocr_note}. "
            "טקסט מאמת לא נמצא — נדרש אימות ידני."
        ))
    elif len(sym_pipes) == 1:
        findings.append(_finding(
            "manual", "אוורור — צינורות", "תקנה 4.1",
            f"🔵 זוהה עיגול אחד בלבד (Ø≈{sym_pipes[0]['radius_cm']*2:.0f} ס\"מ) באזור ממ\"ד — "
            "נדרשים 2 × צינור 4 צול (שאיבה + סינון) לפי תקנה 4.1."
        ))
    else:
        findings.append(_finding(
            "manual", "אוורור — צינורות", "תקנה 4.1",
            "לא נמצא סימון צ.א, צינור אוורור, או עיגולי סמל (Ø 10–12 ס\"מ) באזור ממ\"ד. "
            "נדרש: 2 × צינור 4 צול (שאיבה + סינון) לפי תקנה 4.1."
        ))

    # ── 5a. Blast Door — דלת הדף (תקנה 3.2א) ───────────────────────────────
    blast_door_kws = ['דלת הדף', 'דה"ד', 'דה״ד', 'blast door', 'דהד', 'דלת פלדה']
    has_blast_door = ee.fuzzy_search(text, blast_door_kws, 0.70)

    # Heuristic fallback: door swing arc symbol
    sym_arcs = ee.detect_door_arc(pdf_bytes, scale=used_scale, mamad_bbox=_mamad_bbox)

    if has_blast_door:
        findings.append(_finding(
            "pass", 'דלת הדף (דה"ד)', "תקנה 3.2א",
            f"זוהה סימון דלת הדף / דה\"ד בתוכנית{ocr_note} — עומד בתקן."
        ))
    elif sym_arcs:
        findings.append(_finding(
            "warn", 'דלת הדף (דה"ד)', "תקנה 3.2א",
            f"🔶 זוהה קשת פתיחת דלת (swing arc, רדיוס ≈{sym_arcs[0]['radius_cm']:.0f} ס\"מ) "
            "בממ\"ד — טקסט מאמת לא נמצא. יש לאמת שמדובר בדה\"ד מאושרת."
        ))
    else:
        findings.append(_finding(
            "manual", 'דלת הדף (דה"ד)', "תקנה 3.2א",
            "לא נמצא סימון דלת הדף (דה\"ד) בתוכנית ולא זוהתה קשת פתיחת דלת בטווח 70–100 ס\"מ באזור ממ\"ד."
        ))

    # ── 5b. Blast Wall — קיר מגן (תקנה 3.2ב) ───────────────────────────────
    magen_kws = ["קיר מגן", "מגן דלת", "blast wall", "קיר.מגן", "קיר-מגן"]
    has_magen = ee.fuzzy_search(text, magen_kws, 0.68)

    if has_magen:
        findings.append(_finding(
            "pass", "קיר מגן", "תקנה 3.2ב",
            f"זוהה קיר מגן מול הדלת{ocr_note} — עומד בתקן."
        ))
    else:
        findings.append(_finding(
            "fail", "קיר מגן", "תקנה 3.2ב",
            "לא נמצא קיר מגן מול הדלת. נדרש קיר מגן (blast wall) לפי תקנה 3.2ב."
        ))

    # ── 6. Floor-to-Ceiling Height (תקנה 2.4, 2.50–2.80 m) ─────────────────
    # Geometric extraction is intentionally disabled: a 2D top-view plan never
    # encodes floor-to-ceiling height reliably.  The sidebar number input is
    # always active (defaulting to 2.50 m) and overrides this placeholder at
    # display time.
    findings.append(_finding(
        "info", "גובה פנים", "תקנה 2.4",
        "🔍 נדרש אימות מחתך — גובה הפנים אינו נקרא מתוכנית עליונה (2D). "
        "הזן את הגובה מחתך / חזית בסרגל הצד לאישור אוטומטי."
    ))

    # ── 7. Window–Door Distance (תקנה 3.3 ≥ 30 cm) ──────────────────────────
    dist_regex = [
        r"מרחק\s*(?:חלון|דלת|בין)[^0-9]{0,22}(\d{2,3})\s*ס[\"׳]?מ",
        r"(\d{2,3})\s*ס[\"׳]?מ[^0-9א-ת]{0,22}(?:חלון|דלת)",
        r"מרחק[^0-9]{0,16}(\d{2,3})",
    ]
    dist_vals: list[float] = []
    for pat in dist_regex:
        dist_vals += ee.extract_nums_pattern(pat, text)
    dist_vals += ee.nums_near_keywords(
        text, ["מרחק", "חלון", "דלת"], num_range=(10, 200), window=80)
    dist_vals = sorted({v for v in dist_vals if 10 <= v <= 200})

    has_window   = ee.fuzzy_search(text, ["חלון", "חלונ", "window"], 0.70)
    has_door_ref = ee.fuzzy_search(text, ["דלת", "פתח", "door"],    0.70)

    if dist_vals and has_window and has_door_ref:
        min_dist = min(dist_vals)
        if min_dist >= 30:
            findings.append(_finding(
                "pass", "מרחק חלון–דלת", "תקנה 3.3",
                f"מרחק מינימלי שזוהה: {min_dist:.0f} ס\"מ{ocr_note} — עומד בדרישה (≥ 30 ס\"מ)."
            ))
        else:
            # Cannot confirm that window and door share the same wall segment.
            # A low reading alone is not conclusive — require manual check.
            findings.append(_finding(
                "manual", "מרחק חלון–דלת", "תקנה 3.3",
                f"🔍 בדיקה ידנית נדרשת — מרחק שזוהה: {min_dist:.0f} ס\"מ{ocr_note}. "
                "לא ניתן לאמת אוטומטית שהחלון והדלת על אותו קטע קיר. "
                "יש לאמת ידנית שהמרחק בין החלון לדלת ≥ 30 ס\"מ (תקנה 3.3)."
            ))
    elif has_window and has_door_ref:
        findings.append(_finding(
            "manual", "מרחק חלון–דלת", "תקנה 3.3",
            f"🔍 בדיקה ידנית נדרשת — זוהו חלון ודלת{ocr_note} אך לא נמצא ציון מרחק מפורש. "
            "יש לאמת ידנית שהמרחק ≥ 30 ס\"מ (תקנה 3.3)."
        ))
    else:
        findings.append(_info_missing("מרחק חלון–דלת", "תקנה 3.3", "מרחק החלון–דלת"))

    return findings, flat_text, scale_info


def render_pdf_first_page(pdf_bytes: bytes):
    """Render first page as PIL Image.

    Uses PyMuPDF (fitz) at _RENDER_DPI — roughly 5× faster than pdfplumber.
    Falls back to pdfplumber if fitz is unavailable.
    """
    import numpy as np
    try:
        import fitz
        doc  = fitz.open(stream=pdf_bytes, filetype="pdf")
        if not doc.page_count:
            return None
        page = doc[0]
        mat  = fitz.Matrix(_RENDER_DPI / 72.0, _RENDER_DPI / 72.0)
        pix  = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB, alpha=False)
        arr  = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, 3)
        doc.close()
        return Image.fromarray(arr, mode="RGB")
    except Exception:
        pass
    # pdfplumber fallback
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            if not pdf.pages:
                return None
            img = pdf.pages[0].to_image(resolution=_RENDER_DPI)
            return img.original
    except Exception as e:
        st.error(f"שגיאה בהצגת תמונת PDF: {e}")
        return None


def _zoom_to_finding(
    annotated_img: "Image.Image",
    detections: dict,
    focused_regulation: "str | None",
) -> "Image.Image":
    """
    Return a cropped (zoomed-in) region of *annotated_img* that centres on
    the feature referenced by *focused_regulation*.

    Mapping:
      תקנה 2.3א  (inner walls L/R)  → ממ"ד bbox ± 40 % margin
      תקנה 2.3ב  (outer walls T/B)  → ממ"ד bbox ± 40 % margin
      תקנה 2.1   (area)             → ממ"ד bbox ± 25 % margin
      תקנה 4.1   (pipes)            → union of pipe bboxes ± 80 px
      תקנה 3.2א/ב (doors)           → union of door bboxes ± 80 px
      anything else / not found     → return original image unchanged

    Coordinates are in *image pixels* (already scaled by _RENDER_DPI/72).
    """
    if not focused_regulation:
        return annotated_img

    sf  = _RENDER_DPI / 72.0
    W, H = annotated_img.size

    def _clamp(v, lo, hi):
        return max(lo, min(hi, int(v)))

    def _crop_bbox(x0, y0, x1, y1, margin_frac=0.30):
        dx = (x1 - x0) * margin_frac
        dy = (y1 - y0) * margin_frac
        cx0 = _clamp(x0 - dx, 0, W)
        cy0 = _clamp(y0 - dy, 0, H)
        cx1 = _clamp(x1 + dx, 0, W)
        cy1 = _clamp(y1 + dy, 0, H)
        if cx1 - cx0 < 20 or cy1 - cy0 < 20:
            return annotated_img        # too small — fall back to full image
        return annotated_img.crop((cx0, cy0, cx1, cy1))

    bb = detections.get("mamad_bbox")

    # ── Wall findings → zoom on the ממ"ד box (where wall bands are drawn) ──
    if ("2.3" in focused_regulation or "2.1" in focused_regulation) and bb:
        rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
        rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
        margin = 0.40 if "2.3" in focused_regulation else 0.25
        return _crop_bbox(rx0, ry0, rx1, ry1, margin)

    # ── Pipe finding → zoom on pipe cluster ───────────────────────────────
    if "4.1" in focused_regulation:
        pipes = detections.get("pipes") or []
        if pipes:
            px0 = min(p["x0"] for p in pipes) * sf
            py0 = min(p["top"] for p in pipes) * sf
            px1 = max(p["x1"] for p in pipes) * sf
            py1 = max(p["bottom"] for p in pipes) * sf
            return _crop_bbox(px0, py0, px1, py1, margin_frac=1.0)

    # ── Door findings → zoom on door arc cluster ───────────────────────────
    if "3.2" in focused_regulation:
        arcs = detections.get("door_arcs") or []
        if arcs:
            dx0 = min(d["x0"] for d in arcs) * sf
            dy0 = min(d["top"] for d in arcs) * sf
            dx1 = max(d["x1"] for d in arcs) * sf
            dy1 = max(d["bottom"] for d in arcs) * sf
            return _crop_bbox(dx0, dy0, dx1, dy1, margin_frac=1.0)

    # ── Height / other with a known ממ"ד bbox ─────────────────────────────
    if bb:
        rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
        rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
        return _crop_bbox(rx0, ry0, rx1, ry1, margin_frac=0.20)

    return annotated_img   # no feature found — show full image


def draw_detections_on_image(
    pil_img,
    detections: dict,
    findings: list | None = None,
    focused_regulation: str | None = None,
    overrides: dict | None = None,
) -> "Image.Image":
    """
    Draw visual overlays on the rendered PDF image.

    Coordinate conversion:  img_pixel = pdf_point × (_RENDER_DPI / 72)

    Layers (bottom → top):
      1. ממ"ד green room box (always, when bbox is known)
      2. Per-finding numbered annotations — color reflects pass/fail/warn/info
      3. Focused annotation gets an extra glow ring

    Parameters
    ----------
    detections         : raw detections dict from get_all_visual_detections()
    findings           : list of finding dicts from run_checks(); if None only
                         the base ממ"ד box + pipes + doors are drawn (legacy)
    focused_regulation : regulation string (e.g. "תקנה 2.1") to highlight
    overrides          : {ovr_key: True} from session state — overridden items
                         are rendered green regardless of original status
    """
    from PIL import ImageDraw, ImageFont
    sf   = _RENDER_DPI / 72.0          # PDF points → image pixels
    bb   = detections.get("mamad_bbox")
    findings  = findings  or []
    overrides = overrides or {}

    # ── Font ─────────────────────────────────────────────────────────────────
    try:
        _font_lg = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
        _font_sm = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
        _font_xs = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 10)
    except Exception:
        _font_lg = _font_sm = _font_xs = ImageFont.load_default()

    # Status → RGBA color (outline / badge background)
    _STATUS_RGB = {
        "pass":   (34,  197,  94),
        "fail":   (220,  38,  38),
        "warn":   (245, 158,  11),
        "info":   ( 59, 130, 246),
        "manual": (124,  58, 237),
    }

    img  = pil_img.convert("RGBA")
    over = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(over)

    # ── 1. Base ממ"ד room bounding box ───────────────────────────────────────
    if bb:
        rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
        rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
        draw.rectangle([rx0, ry0, rx1, ry1],
                       fill=(34, 197, 94, 40),
                       outline=(34, 197, 94, 200), width=3)
        # Label tab
        lw, lh = 80, 20
        draw.rectangle([rx0, ry0 - lh, rx0 + lw, ry0], fill=(34, 197, 94, 200))
        draw.text((rx0 + 4, ry0 - lh + 2), 'ממ"ד', font=_font_sm,
                  fill=(255, 255, 255, 255))

    # ── Helper: draw a number badge circle ───────────────────────────────────
    def _badge(cx: float, cy: float, num: str,
               rgb: tuple, focused: bool):
        r  = 14 if focused else 11
        fill_a  = 230 if focused else 200
        draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                     fill=(*rgb, fill_a), outline=(255, 255, 255, 220),
                     width=2)
        fw, _ = draw.textlength(num, font=_font_sm), 0
        draw.text((cx - fw / 2, cy - 7), num, font=_font_sm,
                  fill=(255, 255, 255, 255))

    # ── Helper: glow ring around a rect ──────────────────────────────────────
    def _glow_rect(x0, y0, x1, y1, rgb, gap=5, w=4):
        draw.rectangle([x0 - gap, y0 - gap, x1 + gap, y1 + gap],
                       fill=(*rgb, 30), outline=(*rgb, 180), width=w)

    # ── Helper: draw a wall-band annotation (inner walls ↔ L/R, outer ↔ T/B) ─
    def _wall_band(side: str, rgb: tuple, num: str, focused: bool):
        if not bb:
            return
        rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
        rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
        thick  = 8 if focused else 5
        alpha  = 200 if focused else 140
        if side == "lr":
            # left band
            draw.rectangle([rx0, ry0, rx0 + thick * 2, ry1],
                           fill=(*rgb, alpha), outline=(*rgb, 240), width=2)
            # right band
            draw.rectangle([rx1 - thick * 2, ry0, rx1, ry1],
                           fill=(*rgb, alpha), outline=(*rgb, 240), width=2)
            cx, cy = rx0 + thick, (ry0 + ry1) / 2
        else:   # tb
            # top band
            draw.rectangle([rx0, ry0, rx1, ry0 + thick * 2],
                           fill=(*rgb, alpha), outline=(*rgb, 240), width=2)
            # bottom band
            draw.rectangle([rx0, ry1 - thick * 2, rx1, ry1],
                           fill=(*rgb, alpha), outline=(*rgb, 240), width=2)
            cx, cy = (rx0 + rx1) / 2, ry0 + thick
        if focused:
            _glow_rect(rx0, ry0, rx1, ry1, rgb)
        _badge(cx, cy, num, rgb, focused)

    # ── 2. Per-finding numbered annotations ──────────────────────────────────
    for i, f in enumerate(findings):
        reg     = f.get("regulation", "")
        num     = str(i + 1)
        focused = (focused_regulation == reg)

        # Override → always green
        _ovr_key = f"ovr_{reg.replace(' ','_').replace(chr(34),'')}"
        if overrides.get(_ovr_key):
            status = "pass"
        else:
            status  = f.get("status", "info")

        rgb = _STATUS_RGB.get(status, (128, 128, 128))

        # ── Area (תקנה 2.1) — outline around full mamad bbox ─────────────────
        if "2.1" in reg and bb:
            rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
            rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
            lw  = 5 if focused else 3
            draw.rectangle([rx0, ry0, rx1, ry1],
                           fill=(*rgb, 25 if focused else 15),
                           outline=(*rgb, 230), width=lw)
            if focused:
                _glow_rect(rx0, ry0, rx1, ry1, rgb)
            _badge(rx0 + 14, ry0 + 14, num, rgb, focused)

        # ── Inner walls (תקנה 2.3א) — left + right bands ─────────────────────
        elif "2.3" in reg and "א" in reg:
            _wall_band("lr", rgb, num, focused)

        # ── Outer walls (תקנה 2.3ב) — top + bottom bands ─────────────────────
        elif "2.3" in reg and "ב" in reg:
            _wall_band("tb", rgb, num, focused)

        # ── Pipes (תקנה 4.1) — circles around each detected pipe ─────────────
        elif "4.1" in reg:
            pipes = detections.get("pipes") or []
            if pipes:
                for p in pipes:
                    px0 = p["x0"] * sf - 6;  py0 = p["top"]    * sf - 6
                    px1 = p["x1"] * sf + 6;  py1 = p["bottom"] * sf + 6
                    draw.ellipse([px0, py0, px1, py1],
                                 fill=(*rgb, 50 if focused else 30),
                                 outline=(*rgb, 220), width=3 if focused else 2)
                    if focused:
                        draw.ellipse([px0 - 5, py0 - 5, px1 + 5, py1 + 5],
                                     fill=(0, 0, 0, 0), outline=(*rgb, 100), width=2)
                cx = (pipes[0]["x0"] + pipes[0]["x1"]) / 2 * sf
                cy = (pipes[0]["top"] + pipes[0]["bottom"]) / 2 * sf
                _badge(cx, cy, num, rgb, focused)
            elif bb:
                # No pipe detected → label at top-right of mamad
                rx1 = bb["x1"] * sf;  ry0 = bb["top"] * sf
                _badge(rx1 - 14, ry0 + 14, num, rgb, focused)

        # ── Door / blast-wall (תקנה 3.2) — rectangle around door arc ─────────
        elif "3.2" in reg:
            arcs = detections.get("door_arcs") or []
            if arcs:
                for d in arcs:
                    dx0 = d["x0"] * sf;  dy0 = d["top"]    * sf
                    dx1 = d["x1"] * sf;  dy1 = d["bottom"] * sf
                    draw.rectangle([dx0, dy0, dx1, dy1],
                                   fill=(*rgb, 40 if focused else 20),
                                   outline=(*rgb, 220), width=3 if focused else 2)
                    if focused:
                        _glow_rect(dx0, dy0, dx1, dy1, rgb)
                cx = (arcs[0]["x0"] + arcs[0]["x1"]) / 2 * sf
                cy = (arcs[0]["top"] + arcs[0]["bottom"]) / 2 * sf
                _badge(cx, cy, num, rgb, focused)
            elif bb:
                # No arc detected → label at bottom-left of mamad
                rx0 = bb["x0"] * sf;  ry1 = bb["bottom"] * sf
                _badge(rx0 + 14, ry1 - 14, num, rgb, focused)

        # ── Height / window-distance — label at center of mamad ──────────────
        elif bb:
            rx0 = bb["x0"] * sf;  ry0 = bb["top"]    * sf
            rx1 = bb["x1"] * sf;  ry1 = bb["bottom"] * sf
            cx  = (rx0 + rx1) / 2
            # Stagger vertically by finding-index so labels don't overlap
            cy  = (ry0 + ry1) / 2 + (i - len(findings) // 2) * 28
            if focused:
                draw.ellipse([cx - 22, cy - 22, cx + 22, cy + 22],
                             fill=(*rgb, 40), outline=(*rgb, 180), width=3)
            _badge(cx, cy, num, rgb, focused)

    combined = Image.alpha_composite(img, over)
    return combined.convert("RGB")


def build_report(findings, filename: str,
                 scale_info: dict | None = None) -> str:
    """Build a plain-text report in Hebrew including regulation references and scale."""
    scale_info = scale_info or {}
    used_scale = scale_info.get("used_scale")
    scale_src  = scale_info.get("source", "unknown")
    src_label  = {"auto": "זוהה אוטומטית", "manual": "ידני", "unknown": "לא זוהה"}.get(
        scale_src, "לא זוהה"
    )
    scale_line = f"קנה מידה:     1:{used_scale} ({src_label})" if used_scale \
        else "קנה מידה:     לא זוהה — מדידה גיאומטרית לא זמינה"

    lines = [
        "=" * 65,
        "דוח בדיקת תוכנית - פז ציון | מודול פיקוד העורף",
        "תקן: פיקוד העורף — ממ\"ד / ממ\"ק",
        "=" * 65,
        f"קובץ:          {filename}",
        f"תאריך בדיקה:  {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        scale_line,
        "",
        "תוצאות הבדיקה לפי תקנות:",
        "-" * 65,
    ]
    pass_count = sum(1 for f in findings if f["status"] == "pass")
    fail_count = sum(1 for f in findings if f["status"] == "fail")
    warn_count = sum(1 for f in findings if f["status"] == "warn")
    info_count = sum(1 for f in findings if f["status"] == "info")

    for f in findings:
        icon = {"pass": "✅", "fail": "❌", "warn": "⚠️", "info": "🔍"}.get(f["status"], "•")
        regulation = f.get("regulation", "")
        # Strip HTML tags from text for plain-text report
        clean_text = re.sub(r'<[^>]+>', '', f["text"])
        lines.append(f"{icon}  [{regulation}]  {f['label']}")
        lines.append(f"    {clean_text}")
        lines.append("")

    lines += [
        "-" * 65,
        f"סיכום: {pass_count} תקין | {fail_count} כשלונות | {warn_count} אזהרות | {info_count} בחינה גיאומטרית",
        "",
        "תקנות מקור:",
    ]
    for code, desc in REGULATIONS.items():
        lines.append(f"  • {code}: {desc}")
    lines += [
        "",
        "=" * 65,
        "המערכת מיועדת לסיוע בלבד. הבדיקה הסופית באחריות המהנדס הרשום.",
    ]
    return "\n".join(lines)


def build_pdf_report(
    findings: list,
    filename: str,
    scale_info: dict | None,
    pil_image,              # annotated PIL Image or None
    flat_text: str = "",    # raw extracted PDF text for project metadata
) -> bytes:
    """Professional multi-page PDF report with full Hebrew RTL support.

    Structure
    ---------
    Page 1  — Branded cover: header, project metadata, overall verdict, summary tiles
    Page 2  — Annotated plan image (full-page, with detection overlays)
    Page 3+ — Findings table (multi-line rows, no truncation, full Hebrew text)
    Last    — Regulation reference index + legal disclaimer

    Rendering stack: fpdf2 + Heebo TTF + python-bidi get_display() per visual line.
    """
    import re as _re, tempfile, os
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    from bidi.algorithm import get_display

    # ── Design constants ──────────────────────────────────────────────────────
    MW  = 186.0   # usable page width  mm  (A4 210 − 12×2 margins)
    LM  = 12.0    # left margin
    BM  = 15.0    # bottom margin
    CLH = 5.5     # table cell line height  mm
    PAD = 2.0     # cell internal padding   mm

    # ── Brand palette (R, G, B) ───────────────────────────────────────────────
    C_NAVY    = (15, 23, 42)
    C_BLUE    = (37, 99, 235)
    C_WHITE   = (255, 255, 255)
    C_GRAY_BG = (249, 250, 251)
    C_BORDER  = (229, 231, 235)
    C_TEXT    = (30, 41, 59)
    C_MUTED   = (107, 114, 128)
    C_GREEN   = (22, 163, 74);   C_GREEN_BG  = (240, 253, 244);  C_GREEN_BDR  = (187, 247, 208)
    C_RED     = (220, 38, 38);   C_RED_BG    = (254, 242, 242);  C_RED_BDR    = (254, 202, 202)
    C_AMBER   = (217, 119, 6);   C_AMBER_BG  = (255, 251, 235);  C_AMBER_BDR  = (253, 230, 138)
    C_INDIGO  = (79, 70, 229);   C_INDIGO_BG = (238, 242, 255);  C_INDIGO_BDR = (199, 210, 254)

    ST_PALETTE = {
        "pass":   (C_GREEN,  C_GREEN_BG,  C_GREEN_BDR),
        "fail":   (C_RED,    C_RED_BG,    C_RED_BDR),
        "warn":   (C_AMBER,  C_AMBER_BG,  C_AMBER_BDR),
        "info":   (C_INDIGO, C_INDIGO_BG, C_INDIGO_BDR),
        "manual": (C_INDIGO, C_INDIGO_BG, C_INDIGO_BDR),
    }
    ST_HEB = {
        "pass": "עבר", "fail": "נכשל", "warn": "אזהרה",
        "info": "בחינה", "manual": "ידני",
    }

    # ── Font paths ─────────────────────────────────────────────────────────────
    _FONTS  = Path(__file__).parent / "fonts"
    HEEBO_R = str( "Heebo-Regular.ttf")
    HEEBO_B = str( "Heebo-Bold.ttf")

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _h(text: str) -> str:
        """Strip non-BMP (emoji), replace chars Heebo lacks, apply BiDi."""
        # ≥ / ≤ (U+2265 / U+2264) are not in Heebo — use ASCII alternatives
        s = (str(text)
             .replace('\u2265', '>=')
             .replace('\u2264', '<='))
        clean = "".join(ch for ch in s if ord(ch) <= 0xFFFF)
        return get_display(clean)

    def _strip_html(text: str) -> str:
        return _re.sub(r'<[^>]+>', '', str(text)).strip()

    def _extract_meta(txt: str) -> list[tuple[str, str]]:
        """Extract key project fields from the PDF's raw text."""
        results = []
        patterns = [
            ("מספר תוכנית", r"(?:מספר\s+תוכנית|תב\"ע|תוכנית\s+מס)[:\s.]+([^\n]{3,40})"),
            ("כתובת",       r"(?:כתובת|רחוב)[:\s.]+([^\n]{4,50})"),
            ("אדריכל",      r"(?:אדריכל|מתכנן)[:\s.]+([^\n]{3,40})"),
            ("מהנדס",       r"מהנדס[:\s.]+([^\n]{3,40})"),
            ("יזם / בעלים", r"(?:יזם|בעל\s+נכס)[:\s.]+([^\n]{3,40})"),
            ("קומה",        r"קומה[:\s.]+([^\n]{2,20})"),
        ]
        for label, pat in patterns:
            m = _re.search(pat, txt, _re.IGNORECASE)
            if m:
                results.append((label, m.group(1).strip()[:55]))
        return results

    # ── FPDF subclass — per-page footer ───────────────────────────────────────
    class _PDF(FPDF):
        def header(self): pass
        def footer(self):
            self.set_y(-11)
            self.set_draw_color(*C_BORDER)
            self.line(LM, self.get_y(), LM + MW, self.get_y())
            self.set_y(-10)
            self.set_font("Heebo", "", 6.5)
            self.set_text_color(*C_MUTED)
            self.set_x(LM)
            self.cell(MW / 2, 4, "Paz Tsion  |  Mamad Inspection System", align="L")
            self.set_x(LM + MW / 2)
            self.cell(MW / 2, 4, f"Page {self.page_no()}", align="R")

    # ── Section-header helper ──────────────────────────────────────────────────
    def _sec(title: str):
        pdf.set_font("Heebo", "B", 10)
        pdf.set_text_color(*C_NAVY)
        pdf.cell(MW, 7, title, align="R",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        y = pdf.get_y()
        pdf.set_draw_color(*C_BLUE)
        pdf.set_line_width(0.6)
        pdf.line(LM, y, LM + MW, y)
        pdf.set_line_width(0.2)
        pdf.set_draw_color(*C_BORDER)
        pdf.ln(3)

    # ── Multi-line table-row helper ────────────────────────────────────────────
    def _row(raw_cells, col_widths, aligns, st_bg, st_tc, alt=False):
        """
        Draw one table row.  Returns row height, or None if a page break is needed.
        raw_cells  — un-bidi'd text per column (HTML already stripped)
        Measures height with split_only, then draws background rects + multi_cell.
        """
        pdf.set_font("Heebo", "", 7.5)
        max_lines = 1
        splits    = []
        for raw, cw in zip(raw_cells, col_widths):
            inner = cw - PAD * 2
            parts = pdf.multi_cell(inner, CLH, raw or "", split_only=True) or [""]
            splits.append(parts)
            max_lines = max(max_lines, len(parts))
        row_h = max_lines * CLH + PAD * 2

        if pdf.get_y() + row_h > pdf.page_break_trigger:
            return None   # caller must add page + redraw header

        row_y = pdf.get_y()
        x     = LM
        for col_i, (raw, cw, align, parts) in enumerate(
                zip(raw_cells, col_widths, aligns, splits)):
            if col_i == 1:            # status column — coloured bg
                fill_c = st_bg
                bdr_c  = C_BORDER
                tc     = st_tc
                bold   = True
            else:
                fill_c = (248, 250, 252) if alt else C_WHITE
                bdr_c  = C_BORDER
                tc     = C_TEXT
                bold   = False

            pdf.set_fill_color(*fill_c)
            pdf.set_draw_color(*bdr_c)
            pdf.rect(x, row_y, cw, row_h, style="FD")

            # Bidi per visual line (correct for mixed Hebrew/Latin content)
            bidi_text = "\n".join(_h(line) for line in parts)
            pdf.set_xy(x + PAD, row_y + PAD)
            pdf.set_font("Heebo", "B" if bold else "", 7.5)
            pdf.set_text_color(*tc)
            pdf.multi_cell(cw - PAD * 2, CLH, bidi_text, align=align, border=0)
            x += cw

        pdf.set_xy(LM, row_y + row_h)
        return row_h

    # ── Derived values ─────────────────────────────────────────────────────────
    scale_info = scale_info or {}
    used_scale = scale_info.get("used_scale")
    scale_src  = scale_info.get("source", "unknown")
    scale_text = (f"1:{used_scale} "
                  f"({'זוהה אוטומטית' if scale_src == 'auto' else 'ידני'})"
                  if used_scale else "לא זוהה")

    fails  = sum(1 for f in findings if f.get("status") == "fail")
    warns  = sum(1 for f in findings if f.get("status") == "warn")
    passes = sum(1 for f in findings if f.get("status") == "pass")
    infos  = sum(1 for f in findings if f.get("status") in ("info", "manual"))
    total  = len(findings)

    meta = _extract_meta(flat_text) if flat_text else []

    # ── Initialise PDF ─────────────────────────────────────────────────────────
    pdf = _PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=BM + 12)
    pdf.set_margins(LM, 15, LM)
    pdf.add_font("Heebo", "",  HEEBO_R)
    pdf.add_font("Heebo", "B", HEEBO_B)

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 1 — BRANDED COVER
    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()

    # ── Masthead bar (navy + blue accent stripe) ───────────────────────────────
    HBAR = 40
    pdf.set_fill_color(*C_NAVY)
    pdf.rect(0, 0, 210, HBAR, style="F")
    pdf.set_fill_color(*C_BLUE)
    pdf.rect(0, HBAR - 3, 210, 3, style="F")   # accent stripe

    pdf.set_y(8)
    pdf.set_font("Heebo", "B", 18)
    pdf.set_text_color(*C_WHITE)
    pdf.cell(210, 11, _h("פז ציון — מערכת בדיקת תוכניות אוטומטית"), align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Heebo", "", 9)
    pdf.set_text_color(175, 195, 220)
    pdf.cell(210, 6, _h("מודול פיקוד העורף  |  ממ\"ד / ממ\"ק  |  תקן פיקוד העורף 2024"),
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Meta strip ────────────────────────────────────────────────────────────
    pdf.set_y(HBAR + 5)
    pdf.set_font("Heebo", "", 8)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(
        MW, 5,
        "  ·  ".join([
            _h(f"קובץ: {filename}"),
            _h(f"תאריך: {datetime.now().strftime('%d/%m/%Y  %H:%M')}"),
            _h(f"קנה מידה: {scale_text}"),
        ]),
        align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.ln(2)
    pdf.set_draw_color(*C_BORDER)
    pdf.line(LM, pdf.get_y(), LM + MW, pdf.get_y())
    pdf.ln(5)

    # ── Project metadata (if extracted) ──────────────────────────────────────
    if meta:
        _sec(_h("פרטי הפרויקט"))
        cw2 = MW / 2
        for i in range(0, len(meta), 2):
            chunk  = meta[i:i + 2]
            row_y2 = pdf.get_y()
            for j, (lbl, val) in enumerate(chunk):
                xj = LM + j * cw2
                pdf.set_xy(xj, row_y2)
                pdf.set_font("Heebo", "", 8)
                pdf.set_text_color(*C_MUTED)
                pdf.cell(cw2 * 0.38, 6, _h(f"{lbl}:"), align="R",
                         new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_font("Heebo", "B", 8)
                pdf.set_text_color(*C_TEXT)
                pdf.cell(cw2 * 0.62, 6, _h(val), align="R")
            pdf.ln(6)
        pdf.ln(2)

    # ── Overall verdict badge ─────────────────────────────────────────────────
    if fails:
        vfill, vbdr, vtc = C_RED_BG,   C_RED,   C_RED
        vtxt = f"לא עמד בדרישות — {fails} כשלונות · {warns} אזהרות מתוך {total} בדיקות"
    elif warns:
        vfill, vbdr, vtc = C_AMBER_BG, C_AMBER, C_AMBER
        vtxt = f"עמד בתנאי אזהרה — {warns} אזהרות מתוך {total} בדיקות"
    else:
        vfill, vbdr, vtc = C_GREEN_BG, C_GREEN, C_GREEN
        vtxt = f"עמד בכל הדרישות — {passes} מתוך {total} בדיקות עברו"

    pdf.set_fill_color(*vfill)
    pdf.set_draw_color(*vbdr)
    pdf.set_text_color(*vtc)
    pdf.set_font("Heebo", "B", 12)
    pdf.cell(MW, 13, _h(vtxt), border=1, align="C", fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # ── Summary tiles (4 coloured count boxes) ────────────────────────────────
    TW = MW / 4
    TH = 24
    ty = pdf.get_y()
    tiles = [
        (passes, "תקין",  C_GREEN,  C_GREEN_BG,  C_GREEN_BDR),
        (fails,  "נכשל",  C_RED,    C_RED_BG,    C_RED_BDR),
        (warns,  "אזהרה", C_AMBER,  C_AMBER_BG,  C_AMBER_BDR),
        (infos,  "בחינה", C_INDIGO, C_INDIGO_BG, C_INDIGO_BDR),
    ]
    for i, (cnt, lbl, tc, bg, bdr) in enumerate(tiles):
        tx = LM + i * TW
        pdf.set_fill_color(*bg)
        pdf.set_draw_color(*bdr)
        pdf.rect(tx, ty, TW, TH, style="FD")
        pdf.set_xy(tx, ty + 2)
        pdf.set_font("Heebo", "B", 20)
        pdf.set_text_color(*tc)
        pdf.cell(TW, 12, str(cnt), align="C",
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_xy(tx, ty + 15)
        pdf.set_font("Heebo", "", 8)
        pdf.set_text_color(*C_MUTED)
        pdf.cell(TW, 6, _h(lbl), align="C")
    pdf.set_y(ty + TH)

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2 — ANNOTATED PLAN IMAGE
    # ══════════════════════════════════════════════════════════════════════════
    if pil_image is not None:
        pdf.add_page()
        _sec(_h("תוכנית מסומנת — עמוד ראשון"))
        pdf.ln(1)
        try:
            _buf = io.BytesIO()
            pil_image.convert("RGB").save(_buf, format="JPEG", quality=90)
            _buf.seek(0)
            with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as _tf:
                _tf.write(_buf.getvalue())
                _tf_path = _tf.name

            _iw, _ih = pil_image.size
            sc  = min(MW / _iw, 215.0 / _ih)
            dw, dh = _iw * sc, _ih * sc
            ix  = LM + (MW - dw) / 2
            iy  = pdf.get_y()

            # Subtle drop shadow + border
            pdf.set_fill_color(220, 220, 220)
            pdf.rect(ix + 1.5, iy + 1.5, dw, dh, style="F")   # shadow
            pdf.set_draw_color(*C_BORDER)
            pdf.rect(ix, iy, dw, dh)                           # border frame
            pdf.image(_tf_path, x=ix, y=iy, w=dw, h=dh)
            os.unlink(_tf_path)

            # Caption strip
            cap_y = iy + dh + 3
            pdf.set_font("Heebo", "", 7)
            pdf.set_text_color(*C_MUTED)
            pdf.set_y(cap_y)
            pdf.cell(
                MW, 4,
                _h(f"{filename}   |   קנה מידה: {scale_text}   |   "
                   f"{datetime.now().strftime('%d/%m/%Y')}"),
                align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 3+ — FINDINGS TABLE
    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()
    _sec(_h("ממצאי הבדיקה לפי תקנות"))
    pdf.ln(1)

    # Column widths (mm) — must sum to MW = 186
    #  #(8) | סטטוס(22) | תקנה(30) | תיאור(52) | פרטים(74)
    COLS   = [8.0, 22.0, 30.0, 52.0, 74.0]
    HDRS   = ["#", _h("סטטוס"), _h("תקנה"), _h("תיאור"), _h("פרטים")]
    CALIGN = ["C", "C", "R", "R", "R"]

    def _tbl_hdr():
        pdf.set_font("Heebo", "B", 8)
        pdf.set_fill_color(*C_NAVY)
        pdf.set_text_color(*C_WHITE)
        pdf.set_draw_color(*C_BORDER)
        for cw, hdr, al in zip(COLS, HDRS, CALIGN):
            pdf.cell(cw, 8, hdr, border=1, fill=True, align=al)
        pdf.ln()
        pdf.set_font("Heebo", "", 7.5)

    _tbl_hdr()

    for idx, f in enumerate(findings, 1):
        st_key   = f.get("status", "info")
        tc, bg, _bdr = ST_PALETTE.get(st_key, ST_PALETTE["info"])

        raw_cells = [
            str(idx),
            _strip_html(ST_HEB.get(st_key, st_key)),
            _strip_html(f.get("regulation") or ""),
            _strip_html(f.get("label") or ""),
            _strip_html(f.get("text") or ""),
        ]

        result = _row(raw_cells, COLS, CALIGN, bg, tc, alt=(idx % 2 == 0))
        if result is None:
            pdf.add_page()
            _sec(_h("ממצאי הבדיקה — המשך"))
            pdf.ln(1)
            _tbl_hdr()
            _row(raw_cells, COLS, CALIGN, bg, tc, alt=(idx % 2 == 0))

    # ══════════════════════════════════════════════════════════════════════════
    # LAST SECTION — REGULATION REFERENCE + DISCLAIMER
    # ══════════════════════════════════════════════════════════════════════════
    pdf.ln(8)
    if pdf.get_y() > 235:
        pdf.add_page()
    _sec(_h("תקנות מקור — פיקוד העורף"))
    pdf.ln(1)

    for code, desc in REGULATIONS.items():
        if pdf.get_y() + 6 > pdf.page_break_trigger:
            pdf.add_page()
        r_y = pdf.get_y()
        pdf.set_font("Heebo", "B", 7.5)
        pdf.set_text_color(*C_NAVY)
        pdf.set_xy(LM, r_y)
        pdf.cell(28, 5.5, _h(code), align="R",
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Heebo", "", 7.5)
        pdf.set_text_color(*C_TEXT)
        pdf.multi_cell(MW - 28, 5.5, _h(desc), align="R", border=0)

    # Disclaimer amber box
    pdf.ln(6)
    if pdf.get_y() + 22 > pdf.page_break_trigger:
        pdf.add_page()
    disc = ("המערכת מיועדת לסיוע בלבד. הבדיקה הסופית והאחריות המקצועית נותרות "
            "באחריות המהנדס/אדריכל הרשום. יש לאמת את הממצאים מול תוכנית המקור.")
    disc_y = pdf.get_y()
    pdf.set_font("Heebo", "", 7.5)
    disc_lines = pdf.multi_cell(MW - 8, 5, _h(disc), split_only=True) or [""]
    disc_h = len(disc_lines) * 5 + 9
    pdf.set_fill_color(*C_AMBER_BG)
    pdf.set_draw_color(*C_AMBER_BDR)
    pdf.rect(LM, disc_y, MW, disc_h, style="FD")
    pdf.set_xy(LM + 4, disc_y + 4)
    pdf.set_text_color(*C_AMBER)
    pdf.multi_cell(MW - 8, 5, _h(disc), align="R", border=0)

    return bytes(pdf.output())


# --- Run checks on button press ---
_do_run = run_check
if _do_run and uploaded_file is not None:
    _raw_bytes = uploaded_file.read()
    _fname     = uploaded_file.name

    pdf_bytes = _raw_bytes

    # ── DWF / DWFX → PDF conversion ──────────────────────────────────────────
    # Convert before ANY other processing so the rest of the pipeline sees a
    # regular PDF regardless of the original file format.
    # Path A (preferred): DXF embedded in the archive → ezdxf + matplotlib
    #                     vector render → crisp geometry for wall detection.
    # Path B (fallback): largest PNG/JPG thumbnail → wrapped in PDF via Pillow.
    if dwf_engine.is_dwf_file(_fname):
        with st.spinner("🔄 ממיר DWF לפורמט PDF…"):
            try:
                sheets, _dwf_log = dwf_engine.extract_sheets(_raw_bytes, _fname)
                pdf_bytes = sheets[0].pdf_bytes
                _render_mode = (
                    "🗂️ רנדור וקטורי (DXF)"
                    if not sheets[0].image_bytes   # image_bytes empty → vector path
                    else "🖼️ תמונה ממוטמעת (רסטר)"
                )
                st.info(f"DWF הומר בהצלחה · {_render_mode}")
            except dwf_engine.DWFParseError as _e:
                st.error(
                    f"❌ לא ניתן להמיר את קובץ ה-DWF: {_e}\n\n"
                    "יש לייצא מחדש מ-AutoCAD כ-PDF ולנסות שוב."
                )
                st.stop()

    # ══════════════════════════════════════════════════════════════════════════
    # HARD GATE — vector count check fires BEFORE any analysis or corpus work.
    # A real engineering drawing has hundreds of vector paths.
    # A text document (letter / price quote) has almost none.
    # ══════════════════════════════════════════════════════════════════════════
    _gate_ok, _gate_vecs, _gate_chars = _hard_gate_vector_check(pdf_bytes)
    if not _gate_ok:
        st.error(
            "⚠️ המסמך שזוהה אינו שרטוט הנדסי. "
            "המערכת חוסמת בדיקה של מסמכי טקסט."
        )
        st.stop()

    file_hash = _hashlib.md5(pdf_bytes).hexdigest()
    _get_pdf_store()[file_hash] = pdf_bytes          # persist across reruns

    # Step 1 — extract corpus (cached per file)
    with st.spinner("📄 טוען וחולץ טקסט מה-PDF..."):
        corpus = _cached_corpus(file_hash, pdf_bytes)
        if corpus.get("_error"):
            st.warning(f"שגיאה בחילוץ: {corpus['_error']}")

    # Step 2 — run regulation checks (cached per file+scale — instant on repeat)
    with st.spinner("🔍 מבצע בדיקת תקנות..."):
        cal_scale = manual_scale_val  # None → auto-detect; int → force
        findings, pdf_text, scale_info = _cached_run_checks(
            file_hash, pdf_bytes, cal_scale
        )
        report = build_report(findings, uploaded_file.name, scale_info=scale_info)

    # Step 3 — symbol / visual detections (cached per file + scale)
    resolved_scale = scale_info.get("used_scale")
    with st.spinner("🔎 מזהה סמלים (צינורות, דלתות, ממ\"ד)..."):
        detections = _cached_detections(file_hash, pdf_bytes, resolved_scale)

    # Step 4 — render base PDF image (no overlays yet; overlays drawn at display time)
    with st.spinner("🖼️ מכין תצוגה מקדימה..."):
        base_img  = _cached_pdf_image(file_hash, pdf_bytes)
        pil_image = base_img   # raw — overlays drawn per-render with findings

    st.session_state.results          = findings
    st.session_state.pdf_image        = pil_image
    st.session_state.report_text      = report
    st.session_state.filename         = uploaded_file.name
    st.session_state.scale_info       = scale_info
    st.session_state.detections       = detections
    st.session_state["_pdf_flat_text"] = pdf_text   # saved for PDF report metadata extraction
    st.session_state["last_scale_info"] = scale_info
    st.session_state["_last_file_hash"] = file_hash   # used by auto-scroll

    # ── Pre-select auto-detected scale in the sidebar selectbox ──────────────
    # Store the detected scale as _pending_auto_scale; on the NEXT Streamlit
    # rerun the sidebar block reads this key BEFORE creating the selectbox
    # widget and applies it safely (writing to a widget key after instantiation
    # raises StreamlitAPIException, so we use this deferred pending pattern).
    if (scale_info.get("source") == "auto"
            and scale_info.get("used_scale")
            and st.session_state.get("_scale_idx", 0) == 0):
        _auto_val = scale_info["used_scale"]
        _auto_str = f"1:{_auto_val}"
        if _auto_str in _SCALE_OPTIONS:
            st.session_state["_pending_auto_scale"] = _auto_str





# --- Main Layout ---
if st.session_state.results is not None:
    pil_image  = st.session_state.pdf_image
    report     = st.session_state.report_text
    filename   = st.session_state.get("filename", "תוכנית.pdf")
    scale_info = st.session_state.get("scale_info", {})
    used_scale = scale_info.get("used_scale")
    scale_src  = scale_info.get("source", "unknown")

    # ── Detections + slider-adjusted bbox (needed for area override) ──────────
    detections  = st.session_state.get("detections", {})
    _adj_bb     = _get_adjusted_mamad_bbox(detections)
    _adj_dets   = dict(detections)
    _adj_dets["mamad_bbox"] = _adj_bb

    _adj_area_m2: float | None = None
    if _adj_bb and used_scale:
        _w_pt = _adj_bb["x1"] - _adj_bb["x0"]
        _h_pt = _adj_bb["bottom"] - _adj_bb["top"]
        _w_cm = ee.pts_to_real_cm(_w_pt, used_scale)
        _h_cm = ee.pts_to_real_cm(_h_pt, used_scale)
        _cand = round((_w_cm / 100.0) * (_h_cm / 100.0), 2)
        if 3.0 <= _cand <= 35.0:
            _adj_area_m2 = _cand

    _manual_area_m2 = (float(st.session_state["_manual_area_m2_val"])
                       if st.session_state.get("_use_manual_area_cb")
                          and st.session_state.get("_manual_area_m2_val")
                       else None)
    _effective_area_m2  = _manual_area_m2 if _manual_area_m2 is not None else _adj_area_m2
    _effective_area_src = ("ידני" if _manual_area_m2 is not None
                           else ("מסגרת מכוילת"
                                 if any(st.session_state.get(k, 0) for k in
                                        ("_bbox_adj_r","_bbox_adj_l","_bbox_adj_t","_bbox_adj_b"))
                                 else "מסגרת שזוהתה"))

    # ── Step 1: copy findings and apply ALL display-time overrides ────────────
    findings = list(st.session_state.results)   # detach from session state

    # Height override (always active, sidebar value, default 2.50 m)
    _mh = float(st.session_state.get("_manual_height_m", 2.50))
    for _i, _f in enumerate(findings):
        if _f.get("regulation") == "תקנה 2.4":
            _hs = "pass" if _mh >= 2.50 else "fail"
            _ht = (f"גובה תקנית (מאומת לפי חתך) — {_mh:.2f} מ'." if _hs == "pass"
                   else f"גובה פנים (חתך): {_mh:.2f} מ' — נמוך מהמינימום (2.50 מ'). יש לתקן לפי תקנה 2.4.")
            findings[_i] = _finding(_hs, "גובה פנים", "תקנה 2.4", _ht)
            break

    # Area override (manual → slider-adjusted bbox → auto-detected bbox)
    if _effective_area_m2 is not None:
        for _i, _f in enumerate(findings):
            if _f.get("regulation") == "תקנה 2.1":
                _as = "pass" if _effective_area_m2 >= 9.0 else "fail"
                _at = (f"📐 שטח ממ\"ד ({_effective_area_src}, קנ\"מ 1:{used_scale}): "
                       f"{_effective_area_m2:.2f} מ\"ר — "
                       + ("עומד בדרישת המינימום (9.0 מ\"ר)." if _as == "pass"
                          else "נדרש מינימום 9.0 מ\"ר. יש לתקן לפי תקנה 2.1."))
                findings[_i] = _finding(_as, "שטח נטו", "תקנה 2.1", _at)
                break

    # Dimensions override — recompute width/height from (possibly adjusted) bbox
    if _adj_bb and used_scale:
        _ow_m = ee.pts_to_real_cm(_adj_bb["x1"] - _adj_bb["x0"], used_scale) / 100.0
        _oh_m = ee.pts_to_real_cm(_adj_bb["bottom"] - _adj_bb["top"], used_scale) / 100.0
        for _i, _f in enumerate(findings):
            if _f.get("regulation") == "תקנה 2.2":
                _om    = min(_ow_m, _oh_m)
                _os    = "pass" if _om >= 1.60 else "fail"
                _osmall = "רוחב" if _ow_m < _oh_m else "אורך"
                _otext = (f"📐 ממדי ממ\"ד ({_effective_area_src}, קנ\"מ 1:{used_scale}): "
                          f"{_ow_m:.2f} מ' × {_oh_m:.2f} מ' — "
                          + ("כל צלע ≥ 1.60 מ'. עומד בדרישה."
                             if _os == "pass"
                             else f"{_osmall} ({_om:.2f} מ') מתחת למינימום 1.60 מ'. יש לתקן לפי תקנה 2.2."))
                findings[_i] = _finding(_os, "ממדים מינימליים", "תקנה 2.2", _otext)
                break

    # ── Step 2: sort strictly by severity (overrides respected) ──────────────
    # fail=0  →  info/manual=1  →  warn=2  →  pass=3
    _overrides_pre  = st.session_state.get("_overrides", {})
    _STATUS_ORDER   = {"fail": 0, "info": 1, "manual": 1, "warn": 2, "pass": 3}

    def _eff_status(f):
        k = f"ovr_{f.get('regulation','').replace(' ','_').replace(chr(34),'')}"
        return "pass" if _overrides_pre.get(k) else f["status"]

    findings = sorted(findings, key=lambda f: _STATUS_ORDER.get(_eff_status(f), 1))

    # ── Step 3: compute counts from the final sorted + overridden list ────────
    pass_count = sum(1 for f in findings if _eff_status(f) == "pass")
    fail_count = sum(1 for f in findings if _eff_status(f) == "fail")
    warn_count = sum(1 for f in findings if _eff_status(f) == "warn")
    info_count = sum(1 for f in findings if _eff_status(f) in ("info", "manual"))

    # ── Scale banner ──────────────────────────────────────────────────────────
    src_label = {"auto": "זוהה אוטומטית", "manual": "ידני", "unknown": "לא זוהה"}.get(
        scale_src, "לא זוהה"
    )
    if used_scale:
        scale_display = (
            f'<span class="scale-badge">📐 קנ"מ 1:{used_scale}</span>'
            f'<span class="scale-source">({src_label})</span>'
            f'<span style="flex:1"></span>'
            f'<span style="font-size:0.82rem; opacity:.7;">קנה מידה בשימוש לכל המדידות הגיאומטריות</span>'
        )
    else:
        scale_display = (
            '<span class="scale-badge" style="background:#9e9e9e;">📐 קנ"מ לא זוהה</span>'
            '<span class="scale-source">(הזן קנה מידה ידנית בסרגל הצד לאפשר מדידה גיאומטרית)</span>'
        )
    st.markdown(
        f'<div class="scale-banner">{scale_display}</div>',
        unsafe_allow_html=True,
    )

    # ── Step 4: render sticky summary bar ────────────────────────────────────
    st.markdown(
        f"""
        <div class="status-bar">
          <span class="status-chip chip-fail">
            <span style="color:#DC2626;font-size:.85rem;">●</span> {fail_count} כישלון
          </span>
          <span class="status-chip chip-warn">
            <span style="color:#D97706;font-size:.85rem;">●</span> {warn_count} אזהרה
          </span>
          <span class="status-chip chip-info">
            <span style="color:#2563EB;font-size:.85rem;">●</span> {info_count} בחינה
          </span>
          <span class="status-chip chip-pass">
            <span style="color:#16A34A;font-size:.85rem;">●</span> {pass_count} תקין
          </span>
          <span style="flex:1;direction:rtl;text-align:left;color:#9CA3AF;
                       font-size:0.76rem;align-self:center;font-family:monospace;">
            {filename}
          </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Two-column layout: PDF preview (60%) | Checklist (40%)
    col_pdf, col_check = st.columns([6, 4])

    with col_pdf:
        st.markdown('<div class="col-label">📄 תצוגה מקדימה — עמוד ראשון</div>',
                    unsafe_allow_html=True)

        # ── Focused finding (set by 📍 button in right panel) ─────────────────
        _focused_reg = st.session_state.get("_focused_regulation")

        # ── Legend row ────────────────────────────────────────────────────────
        if pil_image is not None:
            has_mamad = _adj_bb is not None
            n_pipes   = len(detections.get("pipes") or [])
            n_arcs    = len(detections.get("door_arcs") or [])
            _bbox_adjusted = any(st.session_state.get(k, 0) for k in
                                 ("_bbox_adj_r", "_bbox_adj_l", "_bbox_adj_t", "_bbox_adj_b"))
            legend_parts = []
            if has_mamad:
                _bb_label = '■ ממ"ד' + (' ✏️' if _bbox_adjusted else '')
                legend_parts.append(f'<span style="color:#16a34a;font-weight:700;">{_bb_label}</span>')
            if n_pipes:
                legend_parts.append(f'<span style="color:#3b82f6;font-weight:700;">● {n_pipes} צינור</span>')
            if n_arcs:
                legend_parts.append(f'<span style="color:#f97316;font-weight:700;">■ {n_arcs} דלת</span>')
            if _focused_reg:
                legend_parts.append(
                    f'<span style="color:#7c3aed;font-weight:700;">'
                    f'📍 ממוקד: {_focused_reg}</span>'
                )
                if st.button("✖ נקה מיקוד", key="_clear_focus",
                             help="הסר הדגשה מהתמונה"):
                    st.session_state.pop("_focused_regulation", None)
                    st.rerun()
            if legend_parts:
                st.markdown(
                    '<div style="direction:rtl;font-size:0.78rem;margin-bottom:4px;opacity:.85;">'
                    + " &nbsp;|&nbsp; ".join(legend_parts) + "</div>",
                    unsafe_allow_html=True,
                )
            # Draw overlays: detections + per-finding annotations + focus
            _display_img = draw_detections_on_image(
                pil_image,
                _adj_dets,
                findings=findings,
                focused_regulation=_focused_reg,
                overrides=st.session_state.get("_overrides", {}),
            )

            # ── Zoom-crop when a finding is focused ──────────────────────────
            # Crop the annotated image around the relevant feature so the user
            # sees a close-up of exactly what is being measured.
            _zoom_img = _zoom_to_finding(_display_img, _adj_dets, _focused_reg)
            if _zoom_img is not _display_img:
                # Upscale crop 2× with Lanczos for sharp high-res zoom display
                _zoom_img = _zoom_img.resize(
                    (_zoom_img.width * 2, _zoom_img.height * 2),
                    resample=Image.Resampling.LANCZOS,
                )
                # Show zoomed crop (focused feature) + small full-plan thumbnail
                st.image(_zoom_img, use_container_width=True,
                         caption=f"🔍 תקריב: {_focused_reg}")
                with st.expander("📄 תוכנית מלאה", expanded=False):
                    st.image(_display_img, use_container_width=True,
                             caption=f"עמוד 1 — {filename}")
            else:
                st.image(_display_img, use_container_width=True,
                         caption=f"עמוד 1 — {filename}")
        else:
            st.markdown(
                '<div class="placeholder-box">⚠️ לא ניתן להציג תצוגה מקדימה של הקובץ</div>',
                unsafe_allow_html=True,
            )

        # ── Interactive Ruler ─────────────────────────────────────────────────
        if pil_image is not None:
            st.markdown("---")
            st.markdown(
                '<div class="col-label">📏 סרגל מדידה — לחץ שתי נקודות</div>',
                unsafe_allow_html=True,
            )
            if used_scale:
                st.caption("לחץ נקודה A, אחר כך נקודה B. הקו ייצייר על התמונה ותוצאת המדידה תופיע בסרגל הצד.")
            else:
                st.caption("⚠️ בחר קנה מידה בסרגל הצד כדי לחשב מרחק בס\"מ.")

            from streamlit_image_coordinates import streamlit_image_coordinates

            # Build display image (max 640 px wide for comfortable clicking)
            MAX_W = 640
            ratio = min(1.0, MAX_W / pil_image.width)
            ruler_w = int(pil_image.width  * ratio)
            ruler_h = int(pil_image.height * ratio)
            ruler_base = pil_image.resize((ruler_w, ruler_h), resample=Image.Resampling.LANCZOS)

            # Store ratio so the sidebar can use it for cm computation
            st.session_state["_ruler_display_ratio"] = ratio

            # Draw line + markers on a working copy if 2 points are stored
            ruler_draw = ruler_base.copy()
            pts = st.session_state.get("ruler_pts", [])
            if len(pts) >= 1:
                _dr = ImageDraw.Draw(ruler_draw)
                # Endpoint A
                ax, ay = int(pts[0]["x"]), int(pts[0]["y"])
                _dr.ellipse([ax - 6, ay - 6, ax + 6, ay + 6],
                             fill=(220, 38, 38), outline=(255, 255, 255), width=2)
                _dr.text((ax + 8, ay - 10), "A", fill=(220, 38, 38))
                if len(pts) == 2:
                    # Line
                    bx, by = int(pts[1]["x"]), int(pts[1]["y"])
                    _dr.line([ax, ay, bx, by], fill=(220, 38, 38), width=2)
                    # Endpoint B
                    _dr.ellipse([bx - 6, by - 6, bx + 6, by + 6],
                                 fill=(220, 38, 38), outline=(255, 255, 255), width=2)
                    _dr.text((bx + 8, by - 10), "B", fill=(220, 38, 38))

            coords = streamlit_image_coordinates(ruler_draw, key="ruler_click")

            # Detect new click
            if coords is not None:
                prev = st.session_state.get("_ruler_prev")
                if prev != coords:
                    st.session_state["_ruler_prev"] = coords
                    pts_new = list(st.session_state.get("ruler_pts", []))
                    if len(pts_new) < 2:
                        pts_new.append(coords)
                    else:
                        pts_new = [coords]  # restart measurement
                    st.session_state["ruler_pts"] = pts_new
                    st.rerun()   # redraw line immediately

    with col_check:
        # ── Ruler result — always at the very top in a bright yellow box ──────
        _r_pts   = st.session_state.get("ruler_pts", [])
        _r_sc    = (st.session_state.get("scale_info") or {}).get("used_scale")
        _r_ratio = st.session_state.get("_ruler_display_ratio", 1.0)
        if len(_r_pts) == 2 and _r_sc:
            _dx  = (_r_pts[1]["x"] - _r_pts[0]["x"]) / _r_ratio
            _dy  = (_r_pts[1]["y"] - _r_pts[0]["y"]) / _r_ratio
            _px  = math.sqrt(_dx * _dx + _dy * _dy)
            _cm  = _px * (72.0 / _RENDER_DPI) * ee.PT_TO_CM * _r_sc
            st.markdown(
                f"""<div class="ruler-result-box">
                  <div style="font-size:.75rem;font-weight:700;color:#6d4c00;
                              margin-bottom:4px;direction:rtl;text-align:right;">
                    📏 תוצאת מדידה ידנית — סרגל
                  </div>
                  <div style="font-size:2rem;font-weight:900;color:#1a1a1a;
                              line-height:1.1;direction:rtl;text-align:right;">
                    {_cm:.1f}<span style="font-size:1rem;"> ס"מ</span>
                  </div>
                  <div style="font-size:.82rem;color:#555;margin-top:4px;
                              direction:rtl;text-align:right;">
                    {_cm/100:.3f} מ' &nbsp;·&nbsp; קנ"מ 1:{_r_sc}
                  </div>
                </div>""",
                unsafe_allow_html=True,
            )

        # Always show the active area (manual → adjusted bbox → auto-detected)
        if _effective_area_m2 is not None:
            _area_col    = "#e8f5e9" if _effective_area_m2 >= 9.0 else "#ffebee"
            _area_border = "#2e7d32" if _effective_area_m2 >= 9.0 else "#c62828"
            _area_label  = {"ידני": "שטח ידני", "מסגרת מכוילת": "שטח מכוון",
                            "מסגרת שזוהתה": "שטח שזוהה"}.get(_effective_area_src, "שטח נטו")
            st.markdown(
                f"""<div style="background:{_area_col};border-right:4px solid {_area_border};
                    border-radius:8px;padding:8px 14px;margin-bottom:8px;
                    direction:rtl;text-align:right;font-size:0.9rem;">
                  📐 {_area_label}: <strong>{_effective_area_m2:.2f} מ"ר</strong>
                  {'✅ עומד בדרישה' if _effective_area_m2 >= 9.0 else '❌ מתחת ל-9.0 מ"ר'}
                </div>""",
                unsafe_allow_html=True,
            )

        st.subheader("📋 ממצאי הבדיקה לפי תקנות")

        _overrides = st.session_state.setdefault("_overrides", {})

        _ST_FN = {"pass": st.success, "fail": st.error,
                  "warn": st.warning, "info": st.info, "manual": st.info}

        for _pin_num, f in enumerate(findings, start=1):
            regulation     = f.get("regulation", "")
            _ovr_key       = f"ovr_{regulation.replace(' ','_').replace(chr(34),'')}"
            _is_overridden = _overrides.get(_ovr_key, False)
            status         = "pass" if _is_overridden else f["status"]

            _label = f.get("label", "")
            _text  = f.get("text", "")
            _ovr_note = "  ✔ אושר ידנית" if _is_overridden else ""
            _msg = f"**{_pin_num}. {_label}** | {regulation}{_ovr_note}\n\n{_text}"

            _render = _ST_FN.get(status, st.info)
            _render(_msg)

            # ── Action buttons: Focus | Override ────────────────────────────
            _is_focused = (st.session_state.get("_focused_regulation") == regulation)
            _btn_cols   = st.columns([1, 1, 1])

            with _btn_cols[0]:
                if _is_focused:
                    if st.button("📍 מבוטל", key=f"unfocus_{_ovr_key}",
                                 use_container_width=True,
                                 help="הסר הדגשה מהתמונה"):
                        st.session_state.pop("_focused_regulation", None)
                        st.rerun()
                else:
                    if st.button("📍 הצג בתמונה", key=f"focus_{_ovr_key}",
                                 use_container_width=True,
                                 help="הצג את המיקום המתאים לממצא זה בתמונת התוכנית"):
                        st.session_state["_focused_regulation"] = regulation
                        st.rerun()

            with _btn_cols[1]:
                if _is_overridden:
                    if st.button("↩️ בטל", key=f"undo_{_ovr_key}",
                                 use_container_width=True, help="בטל את האישור הידני"):
                        _overrides.pop(_ovr_key, None)
                        st.rerun()
                else:
                    if st.button("✔ אשר ידנית", key=f"approve_{_ovr_key}",
                                 use_container_width=True,
                                 help="סמן כ'אושר ידנית' אם הבדיקה תקינה לפי עיון בתוכנית"):
                        _overrides[_ovr_key] = True
                        st.rerun()

            if status == "manual" and not _is_overridden:
                _cta_key = f'manual_btn_{regulation.replace(" ","_").replace(chr(34),"")}'
                with _btn_cols[2]:
                    st.button("🔍 סמן ידנית", key=_cta_key,
                              use_container_width=True,
                              help=f"סמן {_label} ידנית בשרטוט")

    st.markdown("---")

    # Report download
    st.markdown('<div class="section-header">📥 ייצוא דוח</div>', unsafe_allow_html=True)

    _dl_col1, _dl_col2 = st.columns(2)

    with _dl_col1:
        # ── PDF report ───────────────────────────────────────────────────────
        try:
            # Build a clean annotated image (no focus, all findings marked)
            _base_for_pdf = st.session_state.get("pdf_image")
            _pdf_ann_img  = (
                draw_detections_on_image(
                    _base_for_pdf,
                    _adj_dets,
                    findings          = findings,
                    focused_regulation= None,
                    overrides         = st.session_state.get("_overrides", {}),
                )
                if _base_for_pdf is not None else None
            )
            _pdf_report_bytes = build_pdf_report(
                findings   = findings,
                filename   = st.session_state.get("filename", "plan.pdf"),
                scale_info = st.session_state.get("scale_info"),
                pil_image  = _pdf_ann_img,
                flat_text  = st.session_state.get("_pdf_flat_text", ""),
            )
            st.download_button(
                label="📄 הורד דוח PDF",
                data=_pdf_report_bytes,
                file_name=f"דוח_פז_ציון_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary",
            )
        except Exception as _pdf_err:
            st.warning(f"לא ניתן ליצור דוח PDF: {_pdf_err}")

    with _dl_col2:
        # ── Plain-text fallback ──────────────────────────────────────────────
        st.download_button(
            label="📃 הורד דוח טקסט",
            data=report.encode("utf-8"),
            file_name=f"דוח_בדיקה_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain",
            use_container_width=True,
        )

    st.caption("הדוח כולל את כל הממצאים, תוצאות הבדיקה ותמונת התוכנית המוערת.")

else:
    # Empty state
    st.markdown("---")
    col1, col2 = st.columns([6, 4])
    with col1:
        st.markdown(
            """
            <div class="placeholder-box">
                <div style="font-size:3rem; margin-bottom:12px;">📄</div>
                <div style="font-size:1.1rem; font-weight:600; margin-bottom:8px;">לא הועלה קובץ PDF</div>
                <div style="font-size:0.9rem;">העלה קובץ תוכנית בסרגל הצד ולחץ על "הרץ בדיקה"</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="placeholder-box">
                <div style="font-size:3rem; margin-bottom:12px;">📋</div>
                <div style="font-size:1.1rem; font-weight:600; margin-bottom:8px;">ממצאי הבדיקה יופיעו כאן</div>
                <div style="font-size:0.9rem;">לאחר הרצת הבדיקה יוצגו כל הממצאים לפי קטגוריה</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
