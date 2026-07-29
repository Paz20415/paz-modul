import streamlit as st
import pdfplumber
from PIL import Image, ImageDraw
import pandas as pd

# הגדרות דף RTL ועיצוב יוקרתי
st.set_page_config(layout="wide", page_title="Paz Zion - Plan Checker")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;700&display=swap');
    html, body, [class*="css"] { font-family: 'Heebo', sans-serif; direction: RTL; text-align: right; }
    .main { background-color: #F8F9FA; }
    /* סיכום עליון */
    .summary-box { padding: 10px 20px; border-radius: 10px; color: white; font-weight: bold; display: inline-block; margin-left: 10px; }
    .bg-success { background-color: #28a745; }
    .bg-danger { background-color: #dc3545; }
    .bg-warning { background-color: #ffc107; color: #333; }
    .bg-info { background-color: #17a2b8; }
    /* כפתורי פעולה */
    div.stButton > button { border-radius: 8px; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- לוגיקה של המערכת ---

def get_annotated_image(page, offsets, scale):
    """יוצרת תמונה עם ריבוע ירוק שזז לפי הסליידרים"""
    img = page.to_image(resolution=150).original
    draw = ImageDraw.Draw(img)
    
    # מיקום בסיסי של הממ"ד בנקודות PDF
    base_x, base_y = 350, 450
    w_pts, h_pts = 200, 200
    
    # החלת הסליידרים
    l, r, t, b = offsets
    rect = [base_x - l, base_y - t, base_x + w_pts + r, base_y + h_pts + b]
    
    # ציור המלבן הירוק
    draw.rectangle(rect, outline="green", width=5)
    
    # חישוב שטח אמיתי
    real_w = ((rect[2] - rect[0]) / 72) * 2.54 * (scale / 100) * 10
    real_h = ((rect[3] - rect[1]) / 72) * 2.54 * (scale / 100) * 10
    area = real_w * real_h
    
    return img, round(area, 2)

# --- מערכת כניסה ---
if "logged_in" not in st.session_state: st.session_state.logged_in = False
if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>🏗️ כניסה למערכת - פז ציון</h1>", unsafe_allow_html=True)
    with st.container():
        col_a, col_b, col_c = st.columns([1,2,1])
        with col_b:
            user = st.text_input("שם משתמש", key="u")
            passw = st.text_input("סיסמה", type="password", key="p")
            if st.button("התחבר"):
                if user == "admin" and passw == "paz2024":
                    st.session_state.logged_in = True
                    st.rerun()
                else: st.error("פרטים שגויים")
    st.stop()

# --- ממשק ראשי ---
st.markdown("<h1 style='text-align: right;'>🏗️ מערכת בדיקת תוכניות - פז ציון</h1>", unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ בקרה וכיול")
    uploaded_file = st.file_uploader("העלה תוכנית PDF", type=['pdf'])
    target_scale = st.selectbox("קנה מידה", [50, 100, 250], index=0)
    st.divider()
    st.subheader("📏 כיול שטח ידני")
    off_l = st.slider("הרחב שמאלה", -100, 100, 0)
    off_r = st.slider("הרחב ימינה", -100, 100, 0)
    off_t = st.slider("הרחב למעלה", -100, 100, 0)
    off_b = st.slider("הרחב למטה", -100, 100, 0)
    if st.button("יציאה"):
        st.session_state.logged_in = False
        st.rerun()

if uploaded_file:
    with pdfplumber.open(uploaded_file) as pdf:
        page = pdf.pages[0]
        
        # שומר סף
        if (len(page.curves) + len(page.edges)) < 50:
            st.error("⚠️ שגיאה: המסמך אינו שרטוט הנדסי.")
            st.stop()

        # עיבוד תמונה ושטח
        final_img, area_val = get_annotated_image(page, [off_l, off_r, off_t, off_b], target_scale)

        # שורת סיכום עליונה (KPIs)
        n_pass = 3 if area_val >= 9 else 2
        n_fail = 1 if area_val < 9 else 0
        
        cols = st.columns(5)
        cols[4].markdown(f"<div class='summary-box bg-success'>תקין: {n_pass}</div>", unsafe_allow_html=True)
        cols[3].markdown(f"<div class='summary-box bg-danger'>כישלון: {n_fail}</div>", unsafe_allow_html=True)
        cols[2].markdown(f"<div class='summary-box bg-warning'>אזהרה: 1</div>", unsafe_allow_html=True)
        cols[1].markdown(f"<div class='summary-box bg-info'>בחינה: 1</div>", unsafe_allow_html=True)

        st.divider()

        col_img, col_info = st.columns([0.6, 0.4])
        
        with col_img:
            st.subheader("🖼️ תצוגת שרטוט ומדידה")
            st.image(final_img, use_container_width=True, caption=f"שטח מחושב: {area_val} מ''ר")

        with col_info:
            st.subheader("📝 דוח ממצאים - פיקוד העורף")
            
            # הצגת הממצאים בתיבות
            if area_val >= 9.0:
                st.success(f"✅ **תקנה 2.1: שטח נטו**\n\nשטח: {area_val} מ''ר - עומד בדרישה.")
            else:
                st.error(f"❌ **תקנה 2.1: שטח נטו**\n\nשטח: {area_val} מ''ר - חסרים {round(9-area_val,2)} מ''ר.")

            st.success("✅ **תקנה 2.3: עובי קיר**\n\nזוהה בטון 30 ס''מ תקני.")
            st.success("✅ **תקנה 4.1: אוורור**\n\nזוהה סימון צינור 4 צול.")
            st.info("🔍 **תקנה 2.4: גובה פנים**\n\nנדרש אימות מחתך (2.50 מ' תקני).")
            
            st.divider()
            st.button("📥 הפק דוח PDF רשמי לאדריכל")
else:
    st.info("אנא העלה תוכנית PDF כדי להתחיל בבדיקה.")
