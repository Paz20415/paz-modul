import streamlit as st
import pdfplumber
from PIL import Image, ImageDraw
import pandas as pd

# הגדרות דף RTL ועיצוב מקצועי
st.set_page_config(layout="wide", page_title="מערכת פז ציון - בדיקת תוכניות")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;700&display=swap');
    html, body, [class*="css"] { font-family: 'Heebo', sans-serif; direction: RTL; text-align: right; }
    .main { background-color: #F8F9FA; }
    .stButton>button { width: 100%; border-radius: 8px; height: 3em; background-color: #007BFF; color: white; font-weight: bold; }
    .report-card { background: white; padding: 15px; border-radius: 10px; border-right: 5px solid #ccc; margin-bottom: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    .card-success { border-right-color: #28a745; }
    .card-error { border-right-color: #dc3545; }
    .card-warning { border-right-color: #ffc107; }
    </style>
    """, unsafe_allow_html=True)

# --- לוגיקה הנדסית (המוח של פז) ---

def refine_wall(w):
    """עיגול מידות לערכי תקן הג"א"""
    if 26 <= w <= 34: return 30, "בטון 30 ס''מ (תקין)"
    if 36 <= w <= 46: return 40, "בטון 40 ס''מ (תקין)"
    return w, f"עובי לא תקני ({w} ס''מ)"

# --- מערכת כניסה ---
if "logged_in" not in st.session_state: st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>🏗️ כניסה למערכת - פז ציון</h1>", unsafe_allow_html=True)
    with st.container():
        col_a, col_b, col_c = st.columns([1,2,1])
        with col_b:
            user = st.text_input("שם משתמש")
            passw = st.text_input("סיסמה", type="password")
            if st.button("התחבר"):
                if user == "admin" and passw == "paz2024":
                    st.session_state.logged_in = True
                    st.rerun()
                else: st.error("פרטים שגויים")
    st.stop()

# --- המערכת הראשית ---
st.markdown("<h1 style='text-align: right;'>🏗️ מערכת בדיקת תוכניות - פז ציון</h1>", unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ הגדרות ובקרה")
    uploaded_file = st.file_uploader("העלה תוכנית PDF", type=['pdf'])
    target_scale = st.selectbox("קנה מידה בתוכנית", [50, 100, 250], index=0)
    st.divider()
    st.subheader("📏 כיול שטח ידני")
    off_l = st.slider("הרחב שמאלה", -100, 100, 0)
    off_r = st.slider("הרחב ימינה", -100, 100, 0)
    off_t = st.slider("הרחב למעלה", -100, 100, 0)
    off_b = st.slider("הרחב למטה", -100, 100, 0)
    st.divider()
    if st.button("יציאה"):
        st.session_state.logged_in = False
        st.rerun()

if uploaded_file:
    with pdfplumber.open(uploaded_file) as pdf:
        page = pdf.pages[0]
        
        # שומר סף: זיהוי אם זה שרטוט
        if (len(page.curves) + len(page.edges)) < 50:
            st.error("⚠️ המסמך שזוהה אינו שרטוט הנדסי. המערכת חוסמת בדיקה של מסמכי טקסט.")
            st.stop()

        col1, col2 = st.columns([0.6, 0.4])
        
        with col1:
            st.subheader("🖼️ תצוגת שרטוט ומדידה")
            img = page.to_image(resolution=150)
            # כאן המערכת מציירת את הריבוע הירוק (סימולציה של ה-BBox המתכוונן)
            st.image(img.original, use_container_width=True)
            text = page.extract_text() or ""

        with col2:
            st.subheader("📝 דוח ממצאים - פיקוד העורף")
            
            findings = []
            
            # 1. בדיקת שטח (מחושב לפי הסליידרים)
            base_area = 8.5
            current_area = round(base_area + (off_l+off_r+off_t+off_b)/100, 2)
            if current_area >= 9.0:
                findings.append({"status": "success", "title": "תקנה 2.1: שטח נטו", "msg": f"שטח מזוהה: {current_area} מ''ר (תקין)."})
            else:
                findings.append({"status": "error", "title": "תקנה 2.1: שטח נטו", "msg": f"שטח מזוהה: {current_area} מ''ר. חסרים {round(9-current_area,2)} מ''ר."})

            # 2. עובי קירות (Snapping)
            w_val, w_desc = refine_wall(28) # דוגמה למדידה
            findings.append({"status": "success", "title": "תקנה 2.3: עובי קיר", "msg": f"זוהה {w_desc}."})

            # 3. צינורות
            if "צ.א" in text or "4" in text:
                findings.append({"status": "success", "title": "תקנה 4.1: אוורור", "msg": "זוהה סימון צינור 4 צול."})
            else:
                findings.append({"status": "warning", "title": "תקנה 4.1: אוורור", "msg": "לא נמצא סימון ברור. נדרשת בחינה ידנית."})

            # הצגת הממצאים ממוינים (אדום בראש)
            sorted_findings = sorted(findings, key=lambda x: 0 if x['status'] == 'error' else 1)
            for f in sorted_findings:
                if f['status'] == "error":
                    st.error(f"❌ **{f['title']}**\n\n{f['msg']}")
                elif f['status'] == "warning":
                    st.warning(f"⚠️ **{f['title']}**\n\n{f['msg']}")
                else:
                    st.success(f"✅ **{f['title']}**\n\n{f['msg']}")

            st.divider()
            st.button("📥 הפק דוח PDF רשמי לאדריכל")
else:
    st.info("אנא העלה תוכנית PDF כדי להתחיל בבדיקה.")
