import streamlit as st
import pdfplumber
from PIL import Image, ImageDraw
import io
import os
import re
import math
import hashlib
import hashlib as _hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import extraction_engine as ee

# Global render DPI — must be defined before any sidebar or function that uses it
_RENDER_DPI = 150

# --- Page Config ---
st.set_page_config(
    page_title="מערכת בדיקת תוכניות - פז ציון",
    page_icon="🏗️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_PATH = Path("/home/runner/workspace/users.db")

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
html, body, [class*="css"] { direction: rtl; text-align: right; }
.auth-logo  { font-size: 2.8rem; text-align: center; margin-bottom: 6px; }
.auth-title { text-align: center; font-size: 1.35rem; font-weight: 700;
              color: #1a3a5c; margin-bottom: 2px; }
.auth-sub   { text-align: center; font-size: 0.88rem; color: #4a6fa5;
              margin-bottom: 20px; }
.msg-error  { background:#ffebee; border-right:4px solid #c62828; color:#7f0000;
              padding:10px 14px; border-radius:8px; margin-bottom:10px;
              font-size:.92rem; direction:rtl; text-align:right; }
.msg-success{ background:#e8f5e9; border-right:4px solid #2e7d32; color:#1b5e20;
              padding:10px 14px; border-radius:8px; margin-bottom:10px;
              font-size:.92rem; direction:rtl; text-align:right; }
input { direction: rtl !important; text-align: right !important; }
label { direction: rtl !important; text-align: right !important; }
.stButton > button {
    width: 100%; font-size: 1rem; font-weight: 600;
    padding: 0.55rem 1rem; border-radius: 8px; margin-top: 4px;
}
/* Tabs RTL */
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
        /* Force RTL on the entire app */
        html, body, [class*="css"] {
            direction: rtl;
            text-align: right;
        }
        .stApp {
            direction: rtl;
        }
        /* Sidebar RTL */
        [data-testid="stSidebar"] {
            direction: rtl;
            text-align: right;
        }
        [data-testid="stSidebar"] * {
            direction: rtl;
            text-align: right;
        }
        /* Main content RTL */
        .main .block-container {
            direction: rtl;
            text-align: right;
        }
        /* Title styling */
        .main-title {
            direction: rtl;
            text-align: right;
            font-size: 2.2rem;
            font-weight: 700;
            color: #1a3a5c;
            margin-bottom: 0.2rem;
        }
        .sub-title {
            direction: rtl;
            text-align: right;
            font-size: 1.1rem;
            color: #4a6fa5;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }
        /* Checklist items */
        .check-item {
            direction: rtl;
            text-align: right;
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 0.97rem;
            line-height: 1.6;
            font-family: 'Arial', sans-serif;
        }
        .check-pass {
            background-color: #e8f5e9;
            border-right: 4px solid #2e7d32;
            color: #1b5e20;
        }
        .check-fail {
            background-color: #ffebee;
            border-right: 4px solid #c62828;
            color: #7f0000;
        }
        .check-warn {
            background-color: #fff8e1;
            border-right: 4px solid #f57f17;
            color: #7f3f00;
        }
        /* Section headers */
        .section-header {
            direction: rtl;
            text-align: right;
            font-size: 1.15rem;
            font-weight: 700;
            color: #1a3a5c;
            border-bottom: 2px solid #4a6fa5;
            padding-bottom: 6px;
            margin-bottom: 14px;
            margin-top: 10px;
        }
        /* Report box */
        .report-box {
            background-color: #f5f7fa;
            border: 1px solid #d0d7de;
            border-radius: 8px;
            padding: 16px;
            direction: rtl;
            text-align: right;
            font-family: 'Courier New', monospace;
            font-size: 0.88rem;
        }
        /* Override Streamlit's default LTR for column headers */
        h1, h2, h3, h4, h5, h6, p, div, span, label {
            direction: rtl;
            text-align: right;
        }
        /* Button RTL */
        .stButton > button {
            width: 100%;
            font-size: 1rem;
            font-weight: 600;
            padding: 0.5rem 1rem;
            border-radius: 8px;
        }
        /* File uploader RTL */
        [data-testid="stFileUploadDropzone"] {
            direction: rtl;
        }
        /* Status summary bar */
        .status-bar {
            display: flex;
            flex-direction: row-reverse;
            gap: 16px;
            margin-bottom: 16px;
            padding: 10px 16px;
            background: #f0f4f9;
            border-radius: 10px;
            direction: rtl;
        }
        .status-chip {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .chip-pass { background: #c8e6c9; color: #1b5e20; }
        .chip-fail { background: #ffcdd2; color: #b71c1c; }
        .chip-warn { background: #fff9c4; color: #f57f17; }
        /* Sticky summary bar — stays pinned when checklist scrolls */
        .status-bar {
            position: -webkit-sticky !important;
            position: sticky !important;
            top: 0 !important;
            z-index: 999 !important;
            background: #f0f4f9 !important;
        }
        /* Force the stMarkdown wrapper that holds the bar to be sticky too */
        [data-testid="stMarkdown"]:has(.status-bar) {
            position: -webkit-sticky;
            position: sticky;
            top: 0;
            z-index: 999;
        }
        /* PDF column label */
        .col-label {
            direction: rtl;
            text-align: right;
            font-size: 1rem;
            font-weight: 600;
            color: #4a6fa5;
            margin-bottom: 8px;
        }
        /* ── Scale / Calibration banner ─────────────────────────── */
        .scale-banner {
            display: flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(90deg, #e8eaf6 0%, #f3e5f5 100%);
            border: 1px solid #9c27b0;
            border-radius: 10px;
            padding: 9px 16px;
            margin-bottom: 10px;
            direction: rtl;
            font-size: 0.9rem;
            color: #4a148c;
            font-weight: 600;
        }
        .scale-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: #9c27b0;
            color: #fff;
            border-radius: 20px;
            padding: 3px 12px;
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: 0.04em;
        }
        .scale-source {
            color: #6a1b9a;
            font-size: 0.78rem;
            font-weight: 400;
        }
        .geo-note {
            font-size: 0.72rem;
            background: #e8f5e9;
            color: #1b5e20;
            border-radius: 10px;
            padding: 1px 7px;
            margin-right: 4px;
            font-weight: 600;
        }
        /* No file placeholder */
        .placeholder-box {
            background: #f0f4f9;
            border: 2px dashed #b0bec5;
            border-radius: 12px;
            padding: 60px 20px;
            text-align: center;
            color: #78909c;
            direction: rtl;
        }
        /* Regulation badge */
        .reg-badge {
            display: inline-block;
            font-size: 0.72rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 12px;
            margin-right: 6px;
            vertical-align: middle;
            letter-spacing: 0.02em;
        }
        .badge-pass { background: #c8e6c9; color: #1b5e20; }
        .badge-fail { background: #ffcdd2; color: #b71c1c; }
        .badge-warn { background: #fff9c4; color: #f57f17; }
        .badge-info { background: #bbdefb; color: #0d47a1; }
        /* Info (blue) check card */
        .check-info {
            background: #e3f2fd;
            border-right: 5px solid #1976d2;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 10px;
            direction: rtl;
            text-align: right;
            color: #0d47a1;
        }
        .check-detail {
            font-size: 0.88rem;
            opacity: 0.88;
            margin-top: 4px;
            line-height: 1.5;
            direction: rtl;
            text-align: right;
        }
        /* Manual-check (unsure) card — blue CTA */
        .check-manual {
            background: #e3f2fd;
            border-right: 5px solid #1565c0;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 6px;
            direction: rtl;
            text-align: right;
            color: #0d47a1;
            font-family: 'Arial', sans-serif;
            font-size: 0.97rem;
            line-height: 1.6;
        }
        .badge-manual { background: #bbdefb; color: #0d47a1; }
        /* Ruler result yellow box */
        .ruler-result-box {
            background: #fff176;
            border: 3px solid #f9a825;
            border-radius: 12px;
            padding: 14px 18px;
            margin-bottom: 16px;
            direction: rtl;
            text-align: right;
            box-shadow: 0 2px 8px rgba(249,168,37,.3);
        }
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
st.markdown('<div class="main-title">🏗️ מערכת בדיקת תוכניות - פז ציון</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">מודול פיקוד העורף | בדיקת תוכניות אוטומטית לפי תקן ממ"ד</div>', unsafe_allow_html=True)

# --- Sidebar ---
with st.sidebar:
    st.markdown('<div class="section-header">📂 טעינת קובץ</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "העלה תוכנית PDF",
        type=["pdf"],
        help="העלה קובץ PDF של תוכנית הבניה לבדיקה",
    )

    st.markdown("---")

    # ── Scale (קנה מידה) ──────────────────────────────────────────────────
    st.markdown('<div class="section-header">📐 קנה מידה</div>', unsafe_allow_html=True)

    _SCALE_OPTIONS = ["🔍 זיהוי אוטומטי", "1:50", "1:75", "1:100", "1:150", "1:200", "1:250", "1:500"]

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
        st.session_state["_trigger_run"] = True
    st.session_state["_scale_choice_prev"] = scale_choice

    # Show last auto-detected scale as reference info
    last_scale_info = st.session_state.get("last_scale_info")
    if last_scale_info and last_scale_info.get("source") == "auto":
        auto_scale = last_scale_info.get("used_scale")
        if auto_scale:
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
        if st.button("↩️ אפס כיוון", use_container_width=True, key="_reset_bbox"):
            for _k in ("_bbox_adj_r", "_bbox_adj_l", "_bbox_adj_t", "_bbox_adj_b"):
                st.session_state[_k] = 0
            st.rerun()
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
            <div style="
                background:#e8f5e9; border:2px solid #43a047; border-radius:10px;
                padding:12px 14px; direction:rtl; font-size:1.05rem; margin-bottom:6px;
            ">
                📏 <strong>{_real_cm:.1f} ס"מ</strong> &nbsp;|&nbsp;
                <span style="color:#555;">{_real_cm/100:.2f} מ'</span><br>
                <span style="font-size:0.78rem; color:#777;">קנ"מ 1:{_ruler_scale} &nbsp;•&nbsp;
                A({_ruler_pts[0]['x']},{_ruler_pts[0]['y']}) → B({_ruler_pts[1]['x']},{_ruler_pts[1]['y']})</span>
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
        st.query_params.clear()
        st.session_state.clear()
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


# ---------------------------------------------------------------------------
# Pikud HaOref regulation definitions
# Each entry: regulation code → (short title, minimum requirement note)
# ---------------------------------------------------------------------------
REGULATIONS = {
    "תקנה 2.3א": "עובי קיר פנימי — מינימום 30 ס\"מ",
    "תקנה 2.3ב": "עובי קיר חיצוני — מינימום 40 ס\"מ",
    "תקנה 2.1":  "שטח נטו — מינימום 9.0 מ\"ר",
    "תקנה 4.1":  "אוורור — שני צינורות צ.א 4 צול (שאיבה + סינון)",
    "תקנה 3.2א": "דלת הדף (דה\"ד) — חובה להופיע בתוכנית",
    "תקנה 3.2ב": "קיר מגן מול הדלת — חובה להופיע בתוכנית",
    "תקנה 2.4":  "גובה פנים — בין 2.50 מ' ל-2.80 מ'",
    "תקנה 3.3":  "מרחק חלון-דלת באותו קיר — מינימום 30 ס\"מ",
}


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
        # measure_mamad_walls already applies max-within-cluster + structural
        # snapping (24–34→30, 36–46→40) before returning.
        _mamad_walls = [w for w in
                        ee.measure_mamad_walls(pdf_bytes, used_scale,
                                               mamad_bbox=_mamad_anchor)
                        if w >= 20]
        _inner_walls = sorted(w for w in _mamad_walls if 25 <= w <= 35)   # target 30 cm
        _outer_walls = sorted(w for w in _mamad_walls if 35 < w <= 45)    # target 40 cm
    else:
        _mamad_walls = _inner_walls = _outer_walls = []

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
                f"זוהה עובי {best_inner:.0f} ס\"מ{ocr_note} — עומד בדרישת המינימום (30 ס\"מ)."
            ))
        else:
            findings.append(_finding(
                "fail", "עובי קיר פנימי", "תקנה 2.3א",
                f"זוהה עובי {best_inner:.0f} ס\"מ{ocr_note} — נדרש לפחות 30 ס\"מ. יש לתקן לפי תקנה 2.3א."
            ))
    elif used_scale:
        # ── Geometric fallback: classified mamad wall measurement ──────────
        if _inner_walls:
            best_inner = max(_inner_walls)
            status  = "pass" if best_inner >= 30 else ("warn" if best_inner >= 25 else "fail")
            verdict = {"pass": "עומד בדרישת המינימום (30 ס\"מ).",
                       "warn": "בטווח קיר פנימי (25–35 ס\"מ) אך מתחת ל-30 ס\"מ — יש לאמת ידנית.",
                       "fail": "נמוך מדי — נדרש לפחות 30 ס\"מ לפי תקנה 2.3א."}[status]
            all_str = ", ".join(f"{w:.0f}" for w in sorted(set(_inner_walls)))
            findings.append(_finding(
                status, 'עובי קיר פנימי (ממ"ד)', "תקנה 2.3א",
                f"📐 קירות פנימיים ממ\"ד (קנ\"מ 1:{used_scale}): {all_str} ס\"מ | "
                f"מקסימום: {best_inner:.0f} ס\"מ — {verdict}"
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
                f"זוהה עובי {best_outer:.0f} ס\"מ{ocr_note} — עומד בדרישת המינימום (40 ס\"מ)."
            ))
        else:
            findings.append(_finding(
                "fail", "עובי קיר חיצוני", "תקנה 2.3ב",
                f"זוהה עובי {best_outer:.0f} ס\"מ{ocr_note} — נדרש ≥ 40 ס\"מ לקיר חיצוני. יש לתקן לפי תקנה 2.3ב."
            ))
    elif used_scale:
        if _outer_walls:
            best    = max(_outer_walls)
            status  = "pass" if best >= 40 else ("warn" if best >= 35 else "fail")
            verdict = {"pass": "עומד בדרישת המינימום (40 ס\"מ).",
                       "warn": "בטווח קיר חיצוני (35–45 ס\"מ) אך מתחת ל-40 ס\"מ — יש לאמת ידנית.",
                       "fail": "נמוך מדי — נדרש לפחות 40 ס\"מ לפי תקנה 2.3ב."}[status]
            all_str = ", ".join(f"{w:.0f}" for w in _outer_walls)
            findings.append(_finding(
                status, 'עובי קיר חיצוני (ממ"ד)', "תקנה 2.3ב",
                f"📐 קירות חיצוניים ממ\"ד (קנ\"מ 1:{used_scale}): {all_str} ס\"מ | "
                f"מקסימום: {best:.0f} ס\"מ — {verdict}"
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
            # Cannot confirm that the detected window and door share the same
            # wall segment — a low dimension reading alone is not conclusive.
            # Require manual verification instead of issuing an automatic fail.
            findings.append(_finding(
                "warn", "מרחק חלון–דלת", "תקנה 3.3",
                f"נדרש אימות ידני — מרחק שזוהה: {min_dist:.0f} ס\"מ{ocr_note}. "
                "לא ניתן לוודא שהחלון והדלת נמצאים על אותו קטע קיר. "
                "יש לאמת ידנית שהמרחק בין החלון לדלת ≥ 30 ס\"מ (תקנה 3.3)."
            ))
    elif has_window and has_door_ref:
        findings.append(_finding(
            "warn", "מרחק חלון–דלת", "תקנה 3.3",
            f"זוהו חלון ודלת בתוכנית{ocr_note} אך לא נמצא ציון מרחק מפורש. יש לאמת ידנית (נדרש ≥ 30 ס\"מ)."
        ))
    else:
        findings.append(_info_missing("מרחק חלון–דלת", "תקנה 3.3", "מרחק החלון–דלת"))

    return findings, flat_text, scale_info


def render_pdf_first_page(pdf_bytes: bytes):
    """Render the first page of a PDF as a PIL Image using pdfplumber + Pillow."""
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


# --- Run checks on button press ---
if run_check and uploaded_file is not None:
    pdf_bytes = uploaded_file.read()
    file_hash = _hashlib.md5(pdf_bytes).hexdigest()

    # Step 1 — extract corpus (cached per file)
    with st.spinner("📄 טוען וחולץ טקסט מה-PDF..."):
        corpus = _cached_corpus(file_hash, pdf_bytes)
        if corpus.get("_error"):
            st.warning(f"שגיאה בחילוץ: {corpus['_error']}")

    # Step 2 — run regulation checks
    with st.spinner("🔍 מבצע בדיקת תקנות..."):
        cal_scale = manual_scale_val  # None → auto-detect; int → force
        findings, pdf_text, scale_info = run_checks(
            pdf_bytes, calibration_scale=cal_scale, corpus=corpus
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

    st.session_state.results     = findings
    st.session_state.pdf_image   = pil_image
    st.session_state.report_text = report
    st.session_state.filename    = uploaded_file.name
    st.session_state.scale_info  = scale_info
    st.session_state.detections  = detections
    st.session_state["last_scale_info"] = scale_info
    st.session_state["_last_file_hash"] = file_hash   # used by auto-scroll

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
            <span class="status-chip chip-fail">❌ כישלון: {fail_count}</span>
            <span class="status-chip" style="background:#bbdefb;color:#0d47a1;">🔍 בחינה: {info_count}</span>
            <span class="status-chip chip-warn">⚠️ אזהרה: {warn_count}</span>
            <span class="status-chip chip-pass">✅ תקין: {pass_count}</span>
            <span style="flex:1; direction:rtl; text-align:right; color:#546e7a; font-size:0.88rem; align-self:center;">
                קובץ: <strong>{filename}</strong>
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

        st.markdown('<div class="section-header">📋 ממצאי הבדיקה לפי תקנות</div>',
                    unsafe_allow_html=True)

        _CARD_CSS  = {"pass": "check-pass", "fail": "check-fail",
                      "warn": "check-warn",  "info": "check-info", "manual": "check-manual"}
        _BADGE_CSS = {"pass": "badge-pass",  "fail": "badge-fail",
                      "warn": "badge-warn",  "info": "badge-info", "manual": "badge-manual"}
        _ICONS     = {"pass": "✅", "fail": "❌", "warn": "⚠️",
                      "info": "🔍", "manual": "🔍"}

        # Overrides: {regulation_key: True} — set when user clicks "אשר ידנית"
        # findings is already sorted + overridden — no sort needed here.
        _overrides = st.session_state.setdefault("_overrides", {})

        # ── Auto-scroll to first failure on initial load (once per file) ─────
        _scroll_hash    = st.session_state.get("_last_file_hash", "")
        _scroll_done_key = f"_scroll_done_{_scroll_hash}"
        if fail_count > 0 and not st.session_state.get(_scroll_done_key):
            st.session_state[_scroll_done_key] = True
            st.components.v1.html(
                """<script>
                (function() {
                  function tryScroll(n) {
                    var el = window.parent.document.querySelector('.check-fail');
                    if (el) { el.scrollIntoView({behavior:'smooth', block:'start'}); }
                    else if (n > 0) { setTimeout(function(){ tryScroll(n-1); }, 350); }
                  }
                  setTimeout(function(){ tryScroll(6); }, 500);
                })();
                </script>""",
                height=0,
            )

        for f in findings:
            regulation = f.get("regulation", "")
            _ovr_key   = f"ovr_{regulation.replace(' ','_').replace(chr(34),'')}"
            _is_overridden = _overrides.get(_ovr_key, False)

            # When overridden, render as pass regardless of original status
            if _is_overridden:
                status    = "pass"
                icon      = "✅"
                card_cls  = "check-pass"
                badge_cls = "badge-pass"
                ovr_badge = (
                    ' <span style="background:#7c3aed;color:#fff;font-size:.72rem;'
                    'border-radius:4px;padding:1px 6px;margin-right:4px;">✔ אושר ידנית</span>'
                )
            else:
                status    = f["status"]
                card_cls  = _CARD_CSS.get(status, "check-warn")
                badge_cls = _BADGE_CSS.get(status, "badge-warn")
                icon      = _ICONS.get(status, "•")
                ovr_badge = ""

            st.markdown(
                f"""<div class="check-item {card_cls}"
                         style="direction:rtl;text-align:right;">
                      <div style="direction:rtl;text-align:right;margin-bottom:4px;">
                        <span class="reg-badge {badge_cls}">{regulation}</span>
                        {ovr_badge}<strong>{icon} {f["label"]}</strong>
                      </div>
                      <div class="check-detail"
                           style="direction:rtl;text-align:right;">{f["text"]}</div>
                    </div>""",
                unsafe_allow_html=True,
            )

            # ── Action buttons: Focus | Override ────────────────────────────
            _is_focused   = (st.session_state.get("_focused_regulation") == regulation)
            _btn_cols = st.columns([1, 1, 1])

            # 📍 Focus button — highlights annotation on the left PDF image
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

            # ✔ Approve / ↩ Undo
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

            # Blue "mark manually" CTA for unsure findings (not overridden)
            if status == "manual" and not _is_overridden:
                _cta_key = f'manual_btn_{regulation.replace(" ","_").replace(chr(34),"")}'
                with _btn_cols[2]:
                    st.button(
                        f'🔍 סמן ידנית',
                        key=_cta_key,
                        use_container_width=True,
                        help=f"סמן {f['label']} ידנית בשרטוט",
                    )

    st.markdown("---")

    # Report download
    st.markdown('<div class="section-header">📥 ייצוא דוח</div>', unsafe_allow_html=True)
    st.download_button(
        label="⬇️ הורד דוח טקסט",
        data=report.encode("utf-8"),
        file_name=f"דוח_בדיקה_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
        mime="text/plain",
        use_container_width=True,
    )
    st.caption("הדוח כולל את כל הממצאים ותוצאות הבדיקה האוטומטית.")

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
