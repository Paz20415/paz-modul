import zipfile
import io
from PIL import Image

# השורה הזו היא התיקון לשגיאה מהמסך שלך:
class DWFParseError(Exception):
    """שגיאה מותאמת אישית שהקוד הראשי מצפה למצוא"""
    pass

def is_dwf_file(filename):
    """בודק אם הקובץ הוא מסוג DWF או DWFX"""
    if not filename:
        return False
    return filename.lower().endswith(('.dwf', '.dwfx'))

def data_to_img(data):
    """מחלץ תמונה מתוך קובץ DWF/DWFX"""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            all_files = z.namelist()
            
            # חיפוש תמונות שרטוט
            img_files = [f for f in all_files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.preview'))]
            
            if img_files:
                # לוקח את הקובץ הכי גדול (בדרך כלל השרטוט הראשי)
                best_file = max(img_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_file) as f:
                    return Image.open(io.BytesIO(f.read())), None
            
            # תמיכה ב-DWFX (XPS)
            res_files = [f for f in all_files if 'resources' in f.lower() and f.lower().endswith('.png')]
            if res_files:
                best_res = max(res_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_res) as f:
                    return Image.open(io.BytesIO(f.read())), None

        return None, "לא נמצאה תמונת תצוגה בתוך ה-DWF. אנא הדפס ל-PDF מתוך ה-AutoCAD והעלה שוב."
    except Exception as e:
        # כאן אנחנו משתמשים בשגיאה שהגדרנו למעלה כדי שהקוד הראשי לא יקרוס
        return None, f"שגיאה טכנית בפתיחת הקובץ: {str(e)}"

def process_dwf(data):
    return data_to_img(data)
