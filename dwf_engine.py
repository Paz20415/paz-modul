import zipfile
import io
from PIL import Image

class DWFParseError(Exception):
    pass

def is_dwf_file(filename):
    if not filename: return False
    return filename.lower().endswith(('.dwf', '.dwfx'))

def extract_sheets(raw_bytes, filename):
    """
    מחלץ תמונה מתוך DWF והופך אותה ל-PDF כדי ששאר האפליקציה תעבוד חלק
    """
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
            all_files = z.namelist()
            img_files = [f for f in all_files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.preview'))]
            
            if not img_files:
                # בדיקה נוספת ל-DWFx
                img_files = [f for f in all_files if 'resources' in f.lower() and f.lower().endswith('.png')]

            if img_files:
                # לוקח את השרטוט הכי גדול
                best_file = max(img_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_file) as f:
                    img_data = f.read()
                    img = Image.open(io.BytesIO(img_data))
                    
                    # הקסם: הופך את התמונה ל-PDF בזיכרון
                    pdf_buffer = io.BytesIO()
                    img.convert("RGB").save(pdf_buffer, "PDF")
                    pdf_bytes = pdf_buffer.getvalue()
                    
                    # מחזיר רשימה עם ה-PDF והודעת לוג (בדיוק מה שהקוד הראשי מחפש)
                    return [pdf_bytes], "DWF image extracted and converted to PDF successfully"

        return [], "לא נמצאה תמונת תצוגה בתוך ה-DWF"
    except Exception as e:
        return [], f"שגיאה בפענוח: {str(e)}"

# פונקציות נוספות למניעת שגיאות
def get_is_vector_ready():
    return False
