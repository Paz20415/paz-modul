import zipfile
import io
from PIL import Image

def data_to_img(data):
    """
    מנוע חילוץ תמונה מ-DWF/DWFX (גרסה יציבה 2.0)
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            all_files = z.namelist()
            
            # חיפוש תמונות שרטוט (PNG/JPG) בתוך הקובץ
            img_files = [f for f in all_files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.preview'))]
            
            if img_files:
                # לוקח את קובץ התמונה הכי גדול (בדרך כלל השרטוט הראשי)
                best_file = max(img_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_file) as f:
                    return Image.open(io.BytesIO(f.read())), None
            
            # בדיקה נוספת עבור קבצי DWFX (מבנה XPS)
            res_files = [f for f in all_files if 'resources' in f.lower() and f.lower().endswith('.png')]
            if res_files:
                best_res = max(res_files, key=lambda f: z.getinfo(f).file_size)
                with z.open(best_res) as f:
                    return Image.open(io.BytesIO(f.read())), None

        return None, "לא נמצאה תמונת תצוגה בתוך ה-DWF. אנא הדפס ל-PDF מתוך ה-AutoCAD והעלה שוב."
    except Exception as e:
        return None, f"שגיאה טכנית בפתיחת הקובץ: {str(e)}"

# פונקציית תאימות לקוד הראשי
def process_dwf(data):
    return data_to_img(data)
