import zipfile
import io
from PIL import Image

class DWFParseError(Exception):
    pass

# הגדרה מדויקת של האובייקט שהקוד הראשי מחפש (כולל image_bytes)
class DWFSheet:
    def __init__(self, pdf_bytes, image_bytes, name="Sheet"):
        self.pdf_bytes = pdf_bytes
        self.image_bytes = image_bytes # זה מה שהיה חסר וגרם לשגיאה
        self.name = name
        self.is_vector = False

def is_dwf_file(filename):
    if not filename: return False
    return filename.lower().endswith(('.dwf', '.dwfx'))

def extract_sheets(raw_bytes, filename):
    """
    מחלץ תמונה מתוך DWF ומכין אותה בדיוק לפי דרישות הקוד הראשי
    """
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
            all_files = z.namelist()
            img_files = [f for f in all_files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.preview'))]
            
            if not img_files:
                img_files = [f for f in all_files if 'resources' in f.lower() and f.lower().endswith('.png')]

            if img_files:
                # לוקח את השרטוט הכי גדול
                best_file = max(img_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_file) as f:
                    img_data = f.read()
                    img = Image.open(io.BytesIO(img_data))
                    
                    # הכנת PDF עבור חלקים אחרים במערכת
                    pdf_buffer = io.BytesIO()
                    img.convert("RGB").save(pdf_buffer, "PDF")
                    pdf_content = pdf_buffer.getvalue()
                    
                    # יצירת האובייקט עם כל הנתונים (גם PDF וגם IMAGE)
                    sheet = DWFSheet(pdf_bytes=pdf_content, image_bytes=img_data, name="DWF View")
                    
                    return [sheet], "DWF processed successfully as Raster image"

        return [], "לא נמצאה תמונת תצוגה בתוך ה-DWF"
    except Exception as e:
        return [], f"שגיאה בפענוח ה-DWF: {str(e)}"

def get_is_vector_ready():
    return False
