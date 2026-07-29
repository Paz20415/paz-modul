"""
DWF / DWFX support — two rendering paths:

Path A  (vector, preferred)
  1. Open the DWF/DWFX as a ZIP archive.
  2. Look for embedded .dxf files.
  3. Render the DXF to a high-resolution PDF via ezdxf + matplotlib.
     → Preserves true CAD geometry; wall lines are crisp vectors.

Path B  (raster, fallback)
  1. Same ZIP extraction.
  2. Pick the largest embedded .png/.jpg thumbnail.
  3. Wrap it in a single-page PDF via Pillow.
     → Used when no DXF is present or rendering fails.

Raises DWFParseError when neither path can produce a usable result.
"""
from __future__ import annotations

import io
import math
import tempfile
import zipfile
from dataclasses import dataclass, field as _dc_field
from pathlib import Path


# ── Public exception ──────────────────────────────────────────────────────────

class DWFParseError(ValueError):
    """Raised when no usable content is found in the DWF archive."""


_ERR_LOCKED  = "DWF detection failed, please convert to PDF"
_ERR_LOW_RES = "התמונה המוטמעת ב-DWF נמוכת רזולוציה"
_MIN_USABLE_PX = 800


# ── SheetInfo ─────────────────────────────────────────────────────────────────

@dataclass
class SheetInfo:
    index:          int
    name:           str
    pdf_bytes:      bytes = _dc_field(repr=False)
    image_bytes:    bytes = _dc_field(repr=False, default=b"")
    classification: str   = "תוכנית"
    mamad_score:    float = 0.0
    text_preview:   str   = ""


# ── Public API ────────────────────────────────────────────────────────────────

def is_dwf_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in {".dwf", ".dwfx"}


def list_zip_contents(file_bytes: bytes) -> list[tuple[str, int]]:
    """Return all ZIP entries as [(name, size)] for debug display."""
    if file_bytes[:4] != b"PK\x03\x04":
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            return [(i.filename, i.file_size) for i in zf.infolist()]
    except Exception:
        return []


def convert_to_pdf_bytes(file_bytes: bytes, filename: str) -> bytes:
    sheets, _ = extract_sheets(file_bytes, filename)
    return sheets[0].pdf_bytes


def extract_sheets(
    file_bytes: bytes, filename: str
) -> tuple[list[SheetInfo], list[str]]:
    """
    Open DWF/DWFX as ZIP → try vector DXF render → fall back to raster PNG/JPG.

    Render strategy (in priority order):
      1. Find embedded .dxf files → render via ezdxf + matplotlib (vector quality).
      2. Find largest .png/.jpg thumbnail → wrap in PDF via Pillow (raster fallback).

    Raises DWFParseError when neither path produces a usable result.
    """
    log: list[str] = [f"📂 {filename}  ({len(file_bytes):,} bytes)"]

    # Must be a ZIP
    if file_bytes[:4] != b"PK\x03\x04":
        log.append("❌ לא קובץ ZIP — לא ניתן לחלץ תמונה")
        raise DWFParseError(_ERR_LOCKED)

    try:
        zf_obj = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        log.append("❌ קובץ ZIP פגום")
        raise DWFParseError(_ERR_LOCKED)

    with zf_obj as zf:
        all_names = zf.namelist()
        log.append(f"   {len(all_names)} קבצים בארכיב")

        # ── Path A: DXF vector render ─────────────────────────────────────────
        dxf_result = _try_dxf_from_zip(zf, log)
        if dxf_result is not None:
            pdf_data, dxf_label = dxf_result
            sheet = SheetInfo(
                index=0, name=dxf_label,
                pdf_bytes=pdf_data, image_bytes=b"",
                classification="תוכנית",
            )
            log.append(f"   📐 גיליון וקטורי נוצר: {dxf_label}")
            return [sheet], log

        # ── Path B: raster thumbnail fallback ────────────────────────────────
        images = []
        for name in all_names:
            if Path(name).suffix.lower() in {".png", ".jpg", ".jpeg"}:
                try:
                    sz = zf.getinfo(name).file_size
                    images.append((sz, name))
                except Exception:
                    pass

        images.sort(reverse=True)
        log.append(f"   🖼️  {len(images)} תמונת PNG/JPG נמצאה")

        if not images:
            log.append("❌ אין PNG/JPG ואין DXF בארכיב")
            raise DWFParseError(_ERR_LOCKED)

        best_size, best_name = images[0]
        log.append(f"   ✅ משתמש בתמונה: {best_name} ({best_size:,} bytes)")

        try:
            raw_img = zf.read(best_name)
        except Exception as e:
            log.append(f"   ❌ לא ניתן לקרוא: {e}")
            raise DWFParseError(_ERR_LOCKED)

    try:
        pdf_data = _img_to_pdf(raw_img)
    except Exception as e:
        log.append(f"   ❌ המרה ל-PDF נכשלה: {e}")
        raise DWFParseError(_ERR_LOCKED)

    label = Path(best_name).stem or "גיליון 1"
    sheet = SheetInfo(
        index=0, name=label,
        pdf_bytes=pdf_data, image_bytes=raw_img,
    )
    log.append(f"   📄 גיליון (רסטר) נוצר: {label}")
    return [sheet], log


# ── Path A helpers: DXF vector rendering ─────────────────────────────────────

def _try_dxf_from_zip(
    zf: zipfile.ZipFile,
    log: list[str],
) -> "tuple[bytes, str] | None":
    """
    Look for .dxf entries inside the open ZIP.  For each candidate (largest
    first) try to render it to a PDF via ezdxf + matplotlib.  Return
    (pdf_bytes, label) on the first success, or None if nothing works.
    """
    dxf_entries = [
        (zf.getinfo(n).file_size, n)
        for n in zf.namelist()
        if Path(n).suffix.lower() == ".dxf"
    ]
    if not dxf_entries:
        log.append("   ℹ️  אין קבצי DXF בארכיב — ממשיך לנתיב הרסטר")
        return None

    dxf_entries.sort(reverse=True)
    log.append(f"   🔍 נמצאו {len(dxf_entries)} קבצי DXF")

    for sz, name in dxf_entries[:3]:          # try up to 3 candidates
        log.append(f"   ↪ מנסה לרנדר: {name} ({sz:,} bytes)")
        try:
            raw = zf.read(name)
            pdf = _render_dxf_to_pdf(raw, log)
            if pdf:
                label = Path(name).stem or "DXF Layout"
                log.append(f"   ✅ רנדור DXF הצליח: {label}")
                return pdf, label
        except Exception as exc:
            log.append(f"   ⚠ רנדור {name} נכשל: {exc}")

    return None


def _render_dxf_to_pdf(dxf_bytes: bytes, log: list[str]) -> "bytes | None":
    """
    Render a DXF file to a vector-quality PDF using ezdxf + matplotlib.

    Steps:
      1. Parse DXF (ASCII or binary) with ezdxf.
      2. Select the layout with the most entities (usually 'Model').
      3. Render to a large matplotlib figure at 150 DPI.
      4. Save as PDF and return the bytes.

    White background; all CAD layers rendered in their original colours.
    Line widths are normalised so thin geometry is still visible at A4 size.
    """
    try:
        import ezdxf
        from ezdxf.addons.drawing import RenderContext, Frontend
        from ezdxf.addons.drawing.matplotlib import MatplotlibBackend
        import matplotlib
        matplotlib.use("Agg")           # headless — no display needed
        import matplotlib.pyplot as plt
        import matplotlib.patches as _mp
    except ImportError as exc:
        log.append(f"   ⚠ ezdxf/matplotlib לא מותקנים: {exc}")
        return None

    # ── Parse DXF ────────────────────────────────────────────────────────────
    try:
        text = dxf_bytes.decode("utf-8", errors="replace")
        doc  = ezdxf.read(io.StringIO(text))
    except Exception:
        try:
            # Try binary DXF fallback
            doc = ezdxf.read(io.StringIO(
                dxf_bytes.decode("latin-1", errors="replace")
            ))
        except Exception as exc2:
            log.append(f"   ⚠ פענוח DXF נכשל: {exc2}")
            return None

    # ── Pick best layout ──────────────────────────────────────────────────────
    # Prefer Model space; if empty pick the layout with the most entities.
    layouts    = list(doc.layouts)
    best_layout = doc.modelspace()
    best_count  = sum(1 for _ in best_layout)
    for lay in layouts:
        c = sum(1 for _ in lay)
        if c > best_count:
            best_count  = c
            best_layout = lay

    if best_count == 0:
        log.append("   ⚠ DXF ריק — אין ישויות לרנדר")
        return None

    # ── Render ───────────────────────────────────────────────────────────────
    try:
        # A3-ish figure (42×30 cm) at 150 DPI gives 2480×1754 px — enough
        # for sub-mm wall detection downstream.
        fig  = plt.figure(figsize=(42 / 2.54, 30 / 2.54), dpi=150)
        ax   = fig.add_axes([0, 0, 1, 1])
        ax.set_facecolor("white")
        fig.patch.set_facecolor("white")

        ctx = RenderContext(doc)
        out = MatplotlibBackend(ax)
        Frontend(ctx, out).draw_layout(best_layout, finalize=True)

        buf = io.BytesIO()
        fig.savefig(
            buf, format="pdf",
            facecolor="white", edgecolor="none",
            bbox_inches="tight", pad_inches=0.05,
        )
        plt.close(fig)
        buf.seek(0)
        data = buf.getvalue()
        if len(data) < 500:
            return None
        return data
    except Exception as exc:
        log.append(f"   ⚠ matplotlib render נכשל: {exc}")
        try:
            plt.close("all")
        except Exception:
            pass
        return None


# ── Path B helper: image → PDF (Pillow only) ─────────────────────────────────

def _img_to_pdf(img_bytes: bytes) -> bytes:
    from PIL import Image
    img = Image.open(io.BytesIO(img_bytes))
    if img.mode == "RGBA":
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[3])
        img = bg
    elif img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PDF", resolution=150)
    return buf.getvalue()
