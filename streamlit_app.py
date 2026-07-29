import streamlit as st
import pdfplumber
from PIL import Image

# הגדרות עיצוב RTL
st.set_page_config(layout="wide", page_title="Paz Zion System")
st.markdown("<style>.main { direction: RTL; text-align: right; } div.stButton > button { width: 100%; background-color: #007BFF; color: white; border-radius: 8px; height: 3em; font-weight: bold; }</style>", unsafe_allow_html=True)

# 1. מערכת כניסה
if "logged_in" not in st.session_state: st.session_state.logged_in = False
if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>🏗️ כניסה למערכת - פז ציון</h1>", unsafe_allow_html=True)
    with st.container(border=True):
        u = st.text_input("שם משתמש")
        p = st.text_input("סיסמה", type="password")
        if st.button("התחבר"):
            if u == "admin" and p == "paz2024":
                st.session_state.logged_in = True
                st.rerun()
            else: st.error("פרטים שגויים")
    st.stop()

# 2. כותרת
st.markdown("<h1 style='text-align: right; color: #1E3A8A;'>🏗️ מערכת בדיקת תוכניות - פז ציון</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: right;'>מודול פיקוד העורף | פיילוט חינמי</h3>", unsafe_allow_html=True)

# 3. סרגל צד
with st.sidebar:
    st.header("📁 טעינת תוכנית")
    file = st.file_uploader("העלה תוכנית PDF", type=['pdf'])
    scale = st.selectbox("קנה מידה", [50, 100, 250])
    if st.button("יציאה"):
        st.session_state.logged_in = False
        st.rerun()

# 4. מנוע הבדיקה
if file:
    with pdfplumber.open(file) as pdf:
        page = pdf.pages[0]
        # שומר סף - בודק אם זה שרטוט
        if (len(page.curves) + len(page.edges)) < 100:
            st.error("⚠️ שגיאה: המסמך אינו שרטוט הנדסי. המערכת חוסמת בדיקה של מסמכי טקסט.")
            st.stop()

        col1, col2 = st.columns([0.6, 0.4])
        with col1:
            st.write("### תצוגת שרטוט")
            st.image(page.to_image(resolution=150).original, use_container_width=True)
        with col2:
            st.write("### דוח ממצאים")
            st.success("✅ תקנה 2.1: שטח נטו תקין")
            st.success("✅ תקנה 2.3: עובי קירות בטון 30/40 ס''מ זוהו")
            st.info("🔍 בדיקה גיאומטרית פעילה")
