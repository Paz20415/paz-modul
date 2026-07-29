"""
extraction_engine.py
════════════════════
Advanced PDF text extraction for construction plan analysis.
Capabilities:
  1. Layout-aware pdfplumber extraction (handles vertical/rotated text natively)
  2. Coordinate-based word extraction (standard + vertical char grouping)
  3. Contextual zone search — collect everything within N px of ממ"ד (bbox fast-path)
  4. Fuzzy / partial keyword matching via difflib
  5. Proximity pattern matching — numbers found near keyword tokens
  6. Scale detection from text (קנה מידה / קנ"מ / 1:50 etc.)
  7. Geometric fallback — wall thickness, room area, height from vector lines
  8. OCR (Tesseract) as last-resort only when PDF has no vector text
"""

import re
import math
import difflib
import io
import hashlib
from typing import Optional

import numpy as np
import pdfplumber

# ─────────────────────────────────────────────────────────────────────────────
# Anchor keywords
# ─────────────────────────────────────────────────────────────────────────────

MAMAD_KEYWORDS  = ['ממ"ד', 'ממד', 'מרחב', "ממ'ד", "ממ״ד"]

WALL_KEYWORDS_INNER = [
    "קיר פנימי", "קיר פנ", "ק.פ", 'ק"פ', "ק.פ.", "פנימי",
    "inner wall", "internal wall",
]
WALL_KEYWORDS_OUTER = [
    "קיר חיצוני", "קיר חוץ", "קיר רחוב", "קיר חצר",
    "ק.ח", 'ק"ח', "ק.ח.", "חיצוני", "חוץ",
    "outer wall", "external wall",
]
WALL_CONTEXT_KEYWORDS = ["קיר", "בטון", "עובי", "ק.ב", 'ק"ב', "בטון מזוין"]


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Fuzzy / partial matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def fuzzy_word_match(word: str, keyword: str, threshold: float = 0.65) -> bool:
    """True if *word* is a close-enough fuzzy match to *keyword*."""
    if not word or not keyword:
        return False
    if keyword in word or word in keyword:
        return True
    return difflib.SequenceMatcher(None, word, keyword).ratio() >= threshold


def fuzzy_any_token(text: str, keywords: list[str], threshold: float = 0.65) -> bool:
    """True if any whitespace-separated token in *text* fuzzy-matches any keyword."""
    tokens = re.findall(r'[\w\u0590-\u05FF."\'״׳]+', text)
    for tok in tokens:
        for kw in keywords:
            if fuzzy_word_match(tok, kw, threshold):
                return True
    return False


def fuzzy_search(text: str, keywords: list[str], threshold: float = 0.72) -> bool:
    """
    Search *text* for any of the *keywords* using:
      a) exact substring match
      b) fuzzy token-level match
    """
    if not text:
        return False
    for kw in keywords:
        if kw in text:
            return True
    return fuzzy_any_token(text, keywords, threshold)


# ─────────────────────────────────────────────────────────────────────────────
# 2.  Coordinate-based word extraction (standard + vertical chars)
# ─────────────────────────────────────────────────────────────────────────────

def extract_word_coords(pdf_bytes: bytes, max_pages: int = 4) -> list[dict]:
    """
    Extract all words with bounding boxes from the first *max_pages* pages.

    Uses PyMuPDF (fitz) as the primary extractor — ~5× faster than pdfplumber
    for word extraction.  Falls back to pdfplumber (with vertical/rotated char
    grouping) if fitz fails or returns nothing.

    Returns list of dicts: {text, x0, y0, x1, y1, cx, cy, page, source}
    Both fitz and pdfplumber use top-of-page origin (y increases downward) so
    coordinates are directly interchangeable.
    """
    words: list[dict] = []

    # ── Fast path: fitz (5-10× faster than pdfplumber) ───────────────────────
    try:
        import fitz as _fitz
        _doc = _fitz.open(stream=pdf_bytes, filetype="pdf")
        for page_idx in range(min(len(_doc), max_pages)):
            _pg = _doc[page_idx]
            for w in _pg.get_text("words"):
                # (x0, y0, x1, y1, "word", block_no, line_no, word_no)
                x0, y0, x1, y1, text = (
                    float(w[0]), float(w[1]), float(w[2]), float(w[3]), str(w[4])
                )
                if not text.strip():
                    continue
                words.append({
                    "text": text,
                    "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                    "cx": (x0 + x1) / 2, "cy": (y0 + y1) / 2,
                    "page": page_idx, "source": "standard",
                })
        _doc.close()
        if words:
            return words
    except Exception:
        pass

    # ── Fallback: pdfplumber (also groups vertical/rotated chars) ────────────
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page_idx, page in enumerate(pdf.pages[:max_pages]):

                # ── Standard horizontal words ────────────────────────────────
                for w in (page.extract_words() or []):
                    words.append({
                        "text": w["text"],
                        "x0": w["x0"],    "y0": w["top"],
                        "x1": w["x1"],    "y1": w["bottom"],
                        "cx": (w["x0"] + w["x1"]) / 2,
                        "cy": (w["top"] + w["bottom"]) / 2,
                        "page": page_idx,
                        "source": "standard",
                    })

                # ── Vertical / rotated characters ────────────────────────────
                chars = page.chars or []
                vert = [
                    c for c in chars
                    if len(c.get("matrix", [])) >= 6
                    and abs(c["matrix"][1]) > 0.1
                ]
                if vert:
                    vert_sorted = sorted(vert, key=lambda c: (round(c["x0"] / 20), c["top"]))
                    group: list = []
                    groups: list[list] = []
                    for c in vert_sorted:
                        if not group:
                            group.append(c)
                        else:
                            prev = group[-1]
                            if (abs(c["x0"] - prev["x0"]) < 25
                                    and abs(c["top"] - prev["top"]) < 40):
                                group.append(c)
                            else:
                                groups.append(group)
                                group = [c]
                    if group:
                        groups.append(group)

                    for grp in groups:
                        txt = "".join(c.get("text", "") for c in grp).strip()
                        if not txt:
                            continue
                        x0s = [c["x0"] for c in grp]
                        x1s = [c["x1"] for c in grp]
                        y0s = [c["top"] for c in grp]
                        y1s = [c["bottom"] for c in grp]
                        words.append({
                            "text": txt,
                            "x0": min(x0s), "y0": min(y0s),
                            "x1": max(x1s), "y1": max(y1s),
                            "cx": sum(x0s + x1s) / (2 * len(grp)),
                            "cy": sum(y0s + y1s) / (2 * len(grp)),
                            "page": page_idx,
                            "source": "vertical",
                        })
    except Exception:
        pass
    return words


# ─────────────────────────────────────────────────────────────────────────────
# 3.  Contextual zone search — fast bbox approach
# ─────────────────────────────────────────────────────────────────────────────

def words_near_anchor(all_words: list[dict],
                      anchor_keywords: list[str],
                      radius_px: float = 500.0) -> list[dict]:
    """
    Return every word within *radius_px* PDF-units of any occurrence of
    an anchor keyword (fuzzy-matched) on the same page.
    """
    anchor_boxes: list[dict] = []
    for w in all_words:
        if any(fuzzy_word_match(w["text"], kw) for kw in anchor_keywords):
            anchor_boxes.append(w)

    if not anchor_boxes:
        return []

    page_zones: dict[int, tuple] = {}
    for a in anchor_boxes:
        pg = a["page"]
        cx, cy = a["cx"], a["cy"]
        if pg not in page_zones:
            page_zones[pg] = (cx - radius_px, cy - radius_px,
                              cx + radius_px, cy + radius_px)
        else:
            z = page_zones[pg]
            page_zones[pg] = (min(z[0], cx - radius_px),
                              min(z[1], cy - radius_px),
                              max(z[2], cx + radius_px),
                              max(z[3], cy + radius_px))

    seen: set[tuple] = set()
    result: list[dict] = []
    for w in all_words:
        pg = w["page"]
        if pg not in page_zones:
            continue
        z = page_zones[pg]
        if z[0] <= w["cx"] <= z[2] and z[1] <= w["cy"] <= z[3]:
            key = (pg, round(w["x0"], 1), round(w["y0"], 1))
            if key not in seen:
                seen.add(key)
                result.append(w)
    return result


def words_to_text(words: list[dict]) -> str:
    """Join word texts into a single string."""
    return " ".join(w["text"] for w in words)


# ─────────────────────────────────────────────────────────────────────────────
# 4.  Layout-aware text extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_layout_text(pdf_bytes: bytes, max_pages: int = 6) -> str:
    parts: list[str] = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages[:max_pages]:
                t = page.extract_text(layout=True)
                if t:
                    parts.append(t)
    except Exception:
        pass
    return "\n".join(parts)


def _ocr_available() -> bool:
    try:
        import fitz        # noqa: F401
        import pytesseract # noqa: F401
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


_OCR_READY: Optional[bool] = None


def extract_ocr_fallback(pdf_bytes: bytes, max_pages: int = 3, dpi: int = 180) -> str:
    global _OCR_READY
    if _OCR_READY is None:
        _OCR_READY = _ocr_available()
    if not _OCR_READY:
        return ""

    import fitz
    import pytesseract
    from PIL import Image

    parts: list[str] = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page_num in range(min(len(doc), max_pages)):
            page = doc[page_num]
            mat  = fitz.Matrix(dpi / 72, dpi / 72)
            pix  = page.get_pixmap(matrix=mat, colorspace=fitz.csGRAY)
            arr  = __import__('numpy').frombuffer(pix.samples,
                       dtype=__import__('numpy').uint8).reshape(pix.height, pix.width)
            pil_img = Image.fromarray(arr)
            try:
                raw = pytesseract.image_to_string(pil_img, lang="heb+eng",
                                                   config="--psm 6 --oem 1")
                if raw.strip():
                    parts.append(raw)
            except Exception:
                pass
        doc.close()
    except Exception:
        pass
    return "\n".join(parts)


def extract_ocr_scale_focused(pdf_bytes: bytes, dpi: int = 270) -> str:
    """OCR focused on the bottom strip of each page (title-block area).

    DWF raster PDFs embed the drawing as a full-sheet image — the scale
    annotation lives in the title block at the bottom.  Rendering that strip
    at a higher DPI and using Tesseract's sparse-text mode ("--psm 11") gives
    much better recall for short strings like "1:100" or "קנ\"מ 1:50".

    Returns extracted text, or "" when OCR is unavailable or fails.
    """
    global _OCR_READY
    if _OCR_READY is None:
        _OCR_READY = _ocr_available()
    if not _OCR_READY:
        return ""

    import fitz
    import pytesseract
    from PIL import Image

    parts: list[str] = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page_num in range(min(len(doc), 2)):
            page = doc[page_num]
            mat  = fitz.Matrix(dpi / 72, dpi / 72)
            pix  = page.get_pixmap(matrix=mat, colorspace=fitz.csGRAY)
            arr  = __import__('numpy').frombuffer(pix.samples,
                       dtype=__import__('numpy').uint8).reshape(pix.height, pix.width)
            pil_img = Image.fromarray(arr)

            # Bottom 25 % of the sheet — where title blocks are drawn
            h      = pil_img.height
            strip  = pil_img.crop((0, int(h * 0.75), pil_img.width, h))
            try:
                # --psm 11: sparse text (no assumed layout) — best for title blocks
                raw = pytesseract.image_to_string(strip, lang="heb+eng",
                                                   config="--psm 11 --oem 1")
                if raw.strip():
                    parts.append(raw)
            except Exception:
                pass
        doc.close()
    except Exception:
        pass
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# 5.  Proximity pattern matching
# ─────────────────────────────────────────────────────────────────────────────

def nums_near_keywords(text: str,
                       keywords: list[str],
                       num_range: tuple[float, float],
                       window: int = 100) -> list[float]:
    results: list[float] = []
    num_pat = re.compile(r'\b(\d{1,4}(?:[.,]\d{1,2})?)\b')

    for kw in keywords:
        positions = [m.start() for m in re.finditer(re.escape(kw), text)]
        for tok_m in re.finditer(r'[\w\u0590-\u05FF."\'״׳]+', text):
            if fuzzy_word_match(tok_m.group(), kw):
                positions.append(tok_m.start())

        for pos in positions:
            lo = max(0, pos - window)
            hi = min(len(text), pos + len(kw) + window)
            for raw in num_pat.findall(text[lo:hi]):
                try:
                    v = float(raw.replace(",", "."))
                    if num_range[0] <= v <= num_range[1]:
                        results.append(v)
                except ValueError:
                    pass

    return results


def extract_nums_pattern(pattern: str, text: str,
                         flags: int = re.IGNORECASE) -> list[float]:
    out: list[float] = []
    for m in re.findall(pattern, text, flags):
        raw = str(m).replace(",", ".")
        try:
            out.append(float(raw))
        except ValueError:
            pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 6.  Main extraction pipeline
# ─────────────────────────────────────────────────────────────────────────────

def extract_all(pdf_bytes: bytes) -> dict:
    # Fast path: PyMuPDF (fitz) is ~5× faster than pdfplumber for plain text.
    flat_text = ""
    try:
        import fitz as _fitz
        _doc = _fitz.open(stream=pdf_bytes, filetype="pdf")
        for _pg in _doc:
            t = _pg.get_text("text")
            if t:
                flat_text += t + "\n"
        _doc.close()
    except Exception:
        flat_text = ""
    # Fallback to pdfplumber if fitz yielded no text
    if not flat_text.strip():
        try:
            with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                for page in pdf.pages:
                    t = page.extract_text()
                    if t:
                        flat_text += t + "\n"
        except Exception:
            pass

    # Skip the pdfplumber layout pass when fitz already produced rich text
    # (saves opening pdfplumber a second time — ~1-2 s on typical A1 plans).
    layout_text = ""
    if len(flat_text.strip()) < 300:
        layout_text = extract_layout_text(pdf_bytes)
    word_coords = extract_word_coords(pdf_bytes, max_pages=4)
    mamad_words = words_near_anchor(word_coords, MAMAD_KEYWORDS, radius_px=500)
    mamad_text  = words_to_text(mamad_words)

    combined_so_far = flat_text + layout_text
    ocr_text   = ""
    ocr_active = False
    if len(combined_so_far.strip()) < 80:
        ocr_text   = extract_ocr_fallback(pdf_bytes, max_pages=3)
        ocr_active = bool(ocr_text)
        # For raster-only PDFs (DWF raster path) the full-page OCR at 180 DPI
        # can miss the scale annotation in the title block.  Run a second, more
        # focused pass at higher DPI on the bottom strip — where title blocks
        # (and "1:50", "קנ\"מ 1:100", etc.) are typically drawn.
        _scale_in_ocr = detect_scale(ocr_text) if ocr_text else None
        if _scale_in_ocr is None:
            _strip_text = extract_ocr_scale_focused(pdf_bytes)
            if _strip_text:
                ocr_text   = (ocr_text + "\n" + _strip_text).strip()
                ocr_active = True

    seen_lines: set[str] = set()
    all_parts: list[str] = []
    for chunk in (flat_text, layout_text, mamad_text, ocr_text):
        for line in chunk.splitlines():
            stripped = line.strip()
            if stripped and stripped not in seen_lines:
                seen_lines.add(stripped)
                all_parts.append(stripped)
    all_text = "\n".join(all_parts)

    return {
        "flat_text":   flat_text,
        "layout_text": layout_text,
        "word_coords": word_coords,
        "mamad_words": mamad_words,
        "mamad_text":  mamad_text,
        "all_text":    all_text,
        "ocr_active":  ocr_active,
    }


# =============================================================================
# SECTION 7 — Scale Detection
# =============================================================================

_SCALE_PATTERNS: list[str] = [
    r"1\s*[:/]\s*(\d{2,4})",
    r"קנ[\"״\u05f4]מ\.?\s*(?:1\s*[:/]\s*)?(\d{2,4})",
    r"קנה\s*מידה\s*(?:1\s*[:/]\s*)?(\d{2,4})",
    r"מידה\s*(?:1\s*[:/]\s*)?(\d{2,4})",
    r"scale\s*(?:1\s*[:/]\s*)?(\d{2,4})",
]

COMMON_SCALES: frozenset[int] = frozenset({20, 25, 50, 100, 150, 200, 250, 500})


def detect_scale(text: str) -> int | None:
    candidates: list[int] = []
    for pat in _SCALE_PATTERNS:
        for m in re.findall(pat, text, re.IGNORECASE):
            if not m:
                continue
            try:
                v = int(m)
                if 10 <= v <= 5000:
                    candidates.append(v)
            except (ValueError, TypeError):
                pass
    if not candidates:
        return None
    for c in candidates:
        if c in COMMON_SCALES:
            return c
    return candidates[0]


def parse_scale_input(raw: str) -> int | None:
    raw = raw.strip()
    m = re.match(r'(?:1\s*[:/]\s*)?(\d{2,4})', raw)
    if m:
        v = int(m.group(1))
        if 10 <= v <= 5000:
            return v
    return None


# =============================================================================
# SECTION 8 — Geometric (Vector) Measurement Fallback
# =============================================================================

PT_TO_CM: float = 2.54 / 72.0   # ≈ 0.03528 cm per point


def pts_to_real_cm(pts: float, scale: int) -> float:
    """Convert PDF-space points to real-world centimetres using the drawing scale."""
    return pts * PT_TO_CM * scale


# Module-level cache: avoid re-parsing PDF lines on every geometry call.
# Keyed by MD5 hash of pdf_bytes; holds at most 8 files before clearing.
_LINES_CACHE: dict[str, list[dict]] = {}

# Per-page geometry cache: rects + curves for a single PDF page.
# Keyed as "<file_md5>:<page_idx>" so mamad rect-search, pipe detection
# and door-arc detection all share ONE pdfplumber open per page per file.
_PAGE_GEO_CACHE: dict[str, dict] = {}


def _get_page_geometry(pdf_bytes: bytes, page_idx: int) -> dict:
    """Return {rects, curves} for *page_idx* in *pdf_bytes*, cached in memory.

    Opens pdfplumber exactly once per (file, page) pair.  All callers that
    need shapes from a single page — mamad rect search, pipe detection,
    door-arc detection — get a cache hit on every call after the first,
    eliminating redundant pdfplumber file opens.
    """
    key = f"{hashlib.md5(pdf_bytes).hexdigest()}:{page_idx}"
    if key in _PAGE_GEO_CACHE:
        return _PAGE_GEO_CACHE[key]
    geo: dict = {"rects": [], "curves": []}
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as _pdf:
            if page_idx < len(_pdf.pages):
                _pg = _pdf.pages[page_idx]
                geo["rects"]  = _pg.rects  or []
                geo["curves"] = _pg.curves or []
    except Exception:
        pass
    if len(_PAGE_GEO_CACHE) >= 16:
        _PAGE_GEO_CACHE.clear()
    _PAGE_GEO_CACHE[key] = geo
    return geo


def _extract_lines_impl(pdf_bytes: bytes) -> list[dict]:
    """Parse all vector line segments from a PDF (uncached implementation)."""
    result: list[dict] = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page_idx, page in enumerate(pdf.pages):

                def _add(x0, y0, x1, y1):
                    dx = x1 - x0
                    dy = y1 - y0
                    length = math.sqrt(dx * dx + dy * dy)
                    if length >= 5:
                        result.append({
                            "x0": x0, "y0": y0,
                            "x1": x1, "y1": y1,
                            "length_pt": length,
                            "page": page_idx,
                        })

                for ln in (page.lines or []):
                    _add(ln["x0"], ln["top"], ln["x1"], ln["bottom"])
                for ed in (page.edges or []):
                    _add(ed["x0"], ed["top"], ed["x1"], ed["bottom"])
                for rc in (page.rects or []):
                    x0, y0 = rc["x0"], rc["top"]
                    x1, y1 = rc["x1"], rc["bottom"]
                    _add(x0, y0, x1, y0)
                    _add(x0, y1, x1, y1)
                    _add(x0, y0, x0, y1)
                    _add(x1, y0, x1, y1)
    except Exception:
        pass
    return result


def extract_lines_all(pdf_bytes: bytes) -> list[dict]:
    """
    Collect every vector line segment from all pages via pdfplumber.
    Returns list of dicts: {x0, y0, x1, y1, length_pt, page}

    Results are cached in-process by PDF content hash so the costly
    pdfplumber parse only runs once per unique file per server session.
    """
    key = hashlib.md5(pdf_bytes).hexdigest()
    if key in _LINES_CACHE:
        return _LINES_CACHE[key]
    lines = _extract_lines_impl(pdf_bytes)
    if len(_LINES_CACHE) >= 8:
        _LINES_CACHE.clear()
    _LINES_CACHE[key] = lines
    return lines


def _classify_lines(all_lines: list[dict],
                    min_length_pt: float = 50.0) -> tuple[list[dict], list[dict]]:
    """Split lines into horizontal and vertical buckets.

    min_length_pt raised from 30 → 50 pt so that tick-marks, hatch stubs,
    and short annotation lines are excluded before structural analysis.
    Structural walls in ממ"ד are at least 160 cm long; at 1:100 that is
    ~45 pt.  Using 50 pt gives a small safety margin without losing real walls.
    """
    h: list[dict] = []
    v: list[dict] = []
    for ln in all_lines:
        if ln["length_pt"] < min_length_pt:
            continue
        dx = abs(ln["x1"] - ln["x0"])
        dy = abs(ln["y1"] - ln["y0"])
        L  = ln["length_pt"]
        if dy / L < 0.10:
            h.append(ln)
        elif dx / L < 0.10:
            v.append(ln)
    return h, v


def _build_endpoint_index(
    lines: list[dict],
    max_len: float,
) -> dict[tuple[int, int], list[dict]]:
    """Spatial hash of lines shorter than *max_len* keyed by their midpoint
    rounded to a 10-pt grid.  Used for fast proximity look-ups when detecting
    dimension-line tick marks.
    """
    idx: dict[tuple[int, int], list[dict]] = {}
    for ln in lines:
        if ln["length_pt"] > max_len:
            continue
        mx = int(((ln["x0"] + ln["x1"]) / 2) // 10)
        my = int(((ln["y0"] + ln["y1"]) / 2) // 10)
        for cell in ((mx, my), (mx + 1, my), (mx - 1, my),
                     (mx, my + 1), (mx, my - 1)):
            idx.setdefault(cell, []).append(ln)
    return idx


def _filter_dimension_lines(
    lines: list[dict],
    all_lines: list[dict],
) -> list[dict]:
    """Remove dimension lines from *lines*.

    A dimension line has short perpendicular tick marks (arrowheads /
    extension-line stubs) near both endpoints.  We detect them by checking
    whether each endpoint of a candidate line has at least one short
    perpendicular companion within TICK_PROX_PT points.

    Lines where ticks are found at *both* endpoints are classified as
    dimension lines and dropped.  All others are kept — this errs on the
    side of keeping structural lines.

    Parameters
    ----------
    lines     : already-classified horizontal or vertical lines to filter.
    all_lines : full set of vector segments (used to build the tick index).
    """
    TICK_MAX_LEN = 18.0    # tick marks / stubs are short
    TICK_PROX_PT = 14.0    # endpoint must be within this distance of the tick
    PERP_THRESH  = 0.65    # cos(~50°) — "perpendicular enough"

    # Build a coarse spatial index of short lines for O(1) endpoint look-ups
    tick_idx = _build_endpoint_index(all_lines, max_len=TICK_MAX_LEN)

    structural: list[dict] = []
    for ln in lines:
        dx = ln["x1"] - ln["x0"]
        dy = ln["y1"] - ln["y0"]
        L  = ln["length_pt"]
        if L < 1:
            structural.append(ln)
            continue

        # Unit vector of this line
        ux, uy = dx / L, dy / L

        endpoints = [(ln["x0"], ln["y0"]), (ln["x1"], ln["y1"])]
        ticked = 0

        for ex, ey in endpoints:
            # Look in neighbouring grid cells
            gcx = int(ex // 10)
            gcy = int(ey // 10)
            candidates: list[dict] = []
            for cell in ((gcx, gcy), (gcx + 1, gcy), (gcx - 1, gcy),
                         (gcx, gcy + 1), (gcx, gcy - 1)):
                candidates.extend(tick_idx.get(cell, []))

            for t in candidates:
                # Distance from tick midpoint to our endpoint
                tmx = (t["x0"] + t["x1"]) / 2
                tmy = (t["y0"] + t["y1"]) / 2
                dist = math.sqrt((tmx - ex) ** 2 + (tmy - ey) ** 2)
                if dist > TICK_PROX_PT:
                    continue
                # Check perpendicularity: |dot(tick_unit, line_unit)| should be LOW
                tL = t["length_pt"]
                if tL < 1:
                    continue
                tdx = (t["x1"] - t["x0"]) / tL
                tdy = (t["y1"] - t["y0"]) / tL
                dot = abs(ux * tdx + uy * tdy)   # 0 = perpendicular, 1 = parallel
                if dot < PERP_THRESH:             # close to perpendicular
                    ticked += 1
                    break                          # one tick per endpoint is enough

        # Only drop if ticks found at BOTH endpoints
        if ticked < 2:
            structural.append(ln)

    return structural


def _x_overlap(a: dict, b: dict) -> float:
    lo = max(min(a["x0"], a["x1"]), min(b["x0"], b["x1"]))
    hi = min(max(a["x0"], a["x1"]), max(b["x0"], b["x1"]))
    return max(0.0, hi - lo)


def _y_overlap(a: dict, b: dict) -> float:
    lo = max(min(a["y0"], a["y1"]), min(b["y0"], b["y1"]))
    hi = min(max(a["y0"], a["y1"]), max(b["y0"], b["y1"]))
    return max(0.0, hi - lo)


def _deduplicate_measurements(vals: list[float], tolerance_cm: float = 5.0) -> list[float]:
    """
    Group measurements within *tolerance_cm* of each other and keep the
    median of each cluster.  Removes duplicate wall readings caused by
    triple-line CAD notation (inner face / cavity / outer face → two gaps
    instead of one clean thickness).
    """
    if not vals:
        return []
    sorted_v = sorted(vals)
    groups: list[list[float]] = [[sorted_v[0]]]
    for v in sorted_v[1:]:
        if v - groups[-1][-1] <= tolerance_cm:
            groups[-1].append(v)
        else:
            groups.append([v])
    return [sorted(g)[len(g) // 2] for g in groups]


def _vec_gap_pairs(
    centers:    "np.ndarray",
    lows:       "np.ndarray",
    highs:      "np.ndarray",
    scale:      int,
    min_cm:     float,
    max_cm:     float,
    min_ov_pt:  float = 30.0,
) -> "np.ndarray":
    """Vectorised pairwise gap finder (NumPy).

    Parameters
    ----------
    centers   : 1-D sorted array of line centre coordinates along the gap axis
    lows/highs: 1-D arrays of the perpendicular span of each line
    Returns a 1-D array of gap sizes in cm (upper-triangle pairs only).
    """
    n = len(centers)
    if n < 2:
        return np.array([], dtype=np.float64)

    # gaps_pt[i,j] = centers[j] - centers[i]  (positive for j > i)
    gaps_pt = centers[np.newaxis, :] - centers[:, np.newaxis]   # (n,n)
    gaps_cm = gaps_pt * PT_TO_CM * scale

    # Perpendicular overlap
    ov = (np.minimum(highs[:, np.newaxis], highs[np.newaxis, :])
          - np.maximum(lows[:, np.newaxis], lows[np.newaxis, :]))
    np.maximum(ov, 0.0, out=ov)

    mask = (
        np.triu(np.ones((n, n), dtype=bool), k=1)
        & (gaps_pt  >  3.0)
        & (gaps_cm  >= min_cm)
        & (gaps_cm  <= max_cm * 1.5)
        & (ov       >= min_ov_pt)
    )
    return np.round(gaps_cm[mask], 1)


def measure_wall_thicknesses_geo(
    pdf_bytes: bytes,
    scale: int,
    min_cm: float = 10.0,
    max_cm: float = 80.0,
    min_overlap_pt: float = 30.0,
) -> list[float]:
    """
    Detect wall thickness by finding pairs of parallel lines close together.
    Returns list of deduplicated thicknesses in cm.
    Uses NumPy broadcasting — no Python nested loops.
    """
    all_lines = extract_lines_all(pdf_bytes)
    h_lines, v_lines = _classify_lines(all_lines)
    raw: list[float] = []

    if h_lines:
        h_lines = sorted(h_lines, key=lambda l: (l["page"], (l["y0"] + l["y1"]) * 0.5))
        yc  = np.array([(l["y0"] + l["y1"]) * 0.5 for l in h_lines])
        lx0 = np.array([min(l["x0"], l["x1"]) for l in h_lines])
        lx1 = np.array([max(l["x0"], l["x1"]) for l in h_lines])
        raw.extend(_vec_gap_pairs(yc, lx0, lx1, scale, min_cm, max_cm, min_overlap_pt).tolist())

    if v_lines:
        v_lines = sorted(v_lines, key=lambda l: (l["page"], (l["x0"] + l["x1"]) * 0.5))
        xc  = np.array([(l["x0"] + l["x1"]) * 0.5 for l in v_lines])
        ly0 = np.array([min(l["y0"], l["y1"]) for l in v_lines])
        ly1 = np.array([max(l["y0"], l["y1"]) for l in v_lines])
        raw.extend(_vec_gap_pairs(xc, ly0, ly1, scale, min_cm, max_cm, min_overlap_pt).tolist())

    return _deduplicate_measurements(raw)


def measure_room_areas_geo(
    pdf_bytes: bytes,
    scale: int,
    min_m2: float = 3.0,
    max_m2: float = 60.0,
) -> list[float]:
    areas: list[float] = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                for rc in (page.rects or []):
                    w_pt = abs(rc["x1"] - rc["x0"])
                    h_pt = abs(rc["bottom"] - rc["top"])
                    if w_pt < 10 or h_pt < 10:
                        continue
                    w_cm = pts_to_real_cm(w_pt, scale)
                    h_cm = pts_to_real_cm(h_pt, scale)
                    area_m2 = round((w_cm / 100.0) * (h_cm / 100.0), 2)
                    if min_m2 <= area_m2 <= max_m2:
                        areas.append(area_m2)
    except Exception:
        pass
    return areas


def measure_heights_geo(
    pdf_bytes: bytes,
    scale: int,
    min_m: float = 1.5,
    max_m: float = 5.0,
) -> list[float]:
    all_lines = extract_lines_all(pdf_bytes)
    _, v_lines = _classify_lines(all_lines)
    heights: list[float] = []
    for ln in v_lines:
        span_pt = abs(ln["y1"] - ln["y0"])
        h_m = round(pts_to_real_cm(span_pt, scale) / 100.0, 2)
        if min_m <= h_m <= max_m:
            heights.append(h_m)
    return heights


# =============================================================================
# SECTION 9 — ממ"ד Room Locator & Perimeter-Only Wall Measurement
# =============================================================================

def _find_mamad_from_lines(all_lines: list[dict],
                            page_idx: int,
                            acx: float, acy: float,
                            scale: int) -> "dict | None":
    """
    Line-based room boundary locator (Strategy 2 for find_mamad_room_bbox).

    Cast rays from the ממ"ד label centroid outward in all four cardinal
    directions.  Find the outermost *structural wall pair* — two parallel
    lines whose gap is 18–55 cm at scale — that is at least 90 cm from the
    anchor (filters out interior annotation / hatch / dimension lines which
    are typically very close to the label).

    The *inner face* of that pair becomes the room boundary edge, giving the
    net interior area.  The 90 cm minimum distance guarantee means the green
    box should always cover at least the minimum 9 m² ממ"ד interior.

    Returns {page, x0, top, x1, bottom} or None.
    """
    h_lines, v_lines = _classify_lines(all_lines)

    min_wall_pt   = 18.0 / (PT_TO_CM * scale)   # 18 cm structural minimum
    max_wall_pt   = 55.0 / (PT_TO_CM * scale)   # 55 cm outer wall max
    # Structural walls must be at least 117 cm from the label centroid
    # (was 90 cm — raised by 30 % to search further and capture full room).
    min_dist_pt   = 117.0 / (PT_TO_CM * scale)  # 117 cm minimum half-span

    def _h_spans(ln: dict, x: float, margin: float = 30.0) -> bool:
        return (min(ln["x0"], ln["x1"]) - margin) <= x <= (max(ln["x0"], ln["x1"]) + margin)

    def _v_spans(ln: dict, y: float, margin: float = 30.0) -> bool:
        return (min(ln["y0"], ln["y1"]) - margin) <= y <= (max(ln["y0"], ln["y1"]) + margin)

    def _cy(ln: dict) -> float:
        return (ln["y0"] + ln["y1"]) / 2

    def _cx(ln: dict) -> float:
        return (ln["x0"] + ln["x1"]) / 2

    # Lines on this page that span across the anchor axis
    h_pg = [l for l in h_lines if l["page"] == page_idx and _h_spans(l, acx)]
    v_pg = [l for l in v_lines if l["page"] == page_idx and _v_spans(l, acy)]

    # Sort nearest-to-anchor first
    h_above = sorted([l for l in h_pg if _cy(l) < acy], key=lambda l: -_cy(l))
    h_below = sorted([l for l in h_pg if _cy(l) > acy], key=lambda l:  _cy(l))
    v_left  = sorted([l for l in v_pg if _cx(l) < acx], key=lambda l: -_cx(l))
    v_right = sorted([l for l in v_pg if _cx(l) > acx], key=lambda l:  _cx(l))

    def _inner_face(candidates: list[dict], coord_fn,
                    anchor_coord: float) -> "float | None":
        """
        Walk candidates nearest-to-anchor first.
        Skip any line closer than min_dist_pt (annotation / hatch guard).
        Find the first pair in the structural wall-thickness range and return
        the inner face (the line closest to the anchor in that pair).
        Fall back to the first line beyond min_dist if no pair is found.
        """
        coords = [coord_fn(l) for l in candidates]

        # Only consider lines that are far enough from the anchor
        far_idx = [i for i, c in enumerate(coords)
                   if abs(c - anchor_coord) >= min_dist_pt]

        for i in far_idx:
            for j in range(i + 1, min(i + 12, len(coords))):
                gap = abs(coords[j] - coords[i])
                if min_wall_pt <= gap <= max_wall_pt:
                    return coords[i]       # inner face of the wall pair

        # Fallback: first line beyond min distance
        for i in far_idx:
            return coords[i]

        # Last resort: nearest line regardless of distance
        return coords[0] if coords else None

    top_y    = _inner_face(h_above, _cy, acy)
    bottom_y = _inner_face(h_below, _cy, acy)
    left_x   = _inner_face(v_left,  _cx, acx)
    right_x  = _inner_face(v_right, _cx, acx)

    if None in (top_y, bottom_y, left_x, right_x):
        return None

    w_pt = right_x - left_x
    h_pt = bottom_y - top_y
    if w_pt < 10 or h_pt < 10:
        return None

    area_m2 = (pts_to_real_cm(w_pt, scale) / 100.0) * (pts_to_real_cm(h_pt, scale) / 100.0)
    if not (3.0 <= area_m2 <= 35.0):
        return None

    return {"page": page_idx, "x0": left_x, "top": top_y, "x1": right_x, "bottom": bottom_y}


def find_mamad_room_bbox(pdf_bytes: bytes,
                         word_coords: list[dict] | None = None,
                         scale: int | None = None) -> dict | None:
    """
    Locate the ממ"ד room bounding box.

    Strategy (in priority order):
      1. Find ממ"ד anchor word(s) from word_coords (or extract them).
      2. Smallest pdfplumber *rect* enclosing the anchor — area 5–25 m².
         Works when the PDF uses closed-polygon notation.
      3. **Line-based wall boundary search** — rays from anchor in 4 cardinal
         directions, stopping at the first structural wall pair (18–55 cm gap).
         Works when walls are drawn as individual line segments.
      4. Generous fallback bbox (±280 pt) around the label.

    Returns {page, x0, top, x1, bottom} in pdfplumber point coords, or None.
    """
    if not word_coords:
        word_coords = extract_word_coords(pdf_bytes, max_pages=4)

    anchors = [
        w for w in word_coords
        if any(fuzzy_word_match(w["text"], kw) for kw in MAMAD_KEYWORDS)
    ]
    if not anchors:
        return None

    anchor   = min(anchors, key=lambda w: (w["page"],))
    pg       = anchor["page"]
    acx, acy = anchor["cx"], anchor["cy"]

    # ── Strategy 1: smallest enclosing rect (5–25 m²) ────────────────────────
    # Uses _get_page_geometry (cached) so detect_pipe_symbols / detect_door_arc
    # called right after reuse the same data — zero extra pdfplumber opens.
    best_rect = None
    best_area = float("inf")
    try:
        _geo = _get_page_geometry(pdf_bytes, pg)
        for rc in _geo["rects"]:
            if not (rc["x0"] <= acx <= rc["x1"]
                    and rc["top"] <= acy <= rc["bottom"]):
                continue
            w_pt = rc["x1"] - rc["x0"]
            h_pt = rc["bottom"] - rc["top"]
            if scale:
                w_cm    = pts_to_real_cm(w_pt, scale)
                h_cm    = pts_to_real_cm(h_pt, scale)
                area_m2 = (w_cm / 100.0) * (h_cm / 100.0)
                # Require at least 8 m² — rules out title blocks,
                # hatching rects, and tiny annotation boxes that happen
                # to contain the label.  Cap at 30 m².
                if not (8.0 <= area_m2 <= 30.0):
                    continue
            area_pt = w_pt * h_pt
            if area_pt < best_area:
                best_area = area_pt
                best_rect = {
                    "page": pg,
                    "x0": rc["x0"], "top": rc["top"],
                    "x1": rc["x1"], "bottom": rc["bottom"],
                }
    except Exception:
        pass

    if best_rect is not None:
        return best_rect

    # ── Strategy 2: line-based wall boundary search ───────────────────────────
    if scale:
        all_lines = extract_lines_all(pdf_bytes)
        line_rect = _find_mamad_from_lines(all_lines, pg, acx, acy, scale)
        if line_rect is not None:
            return line_rect

    # ── Fallback: generous bbox around the label ──────────────────────────────
    r = 364.0   # +30 % over old 280 pt  →  ~4.6 m half-span at 1:100
    return {
        "page": pg,
        "x0":     max(0.0, acx - r),  "top":    max(0.0, acy - r),
        "x1":     acx + r,             "bottom": acy + r,
    }


def snap_structural(cm: float) -> float:
    """
    Round a measured wall thickness to the nearest standard ממ"ד structural
    value.  CAD hatch lines produce readings slightly below the true face-to-face
    distance; snapping corrects for that artefact.

      25–34 cm  →  30 cm  (standard inner / blast wall)
      35–46 cm  →  40 cm  (standard external / reinforced wall)

    Values outside those bands are returned unchanged.
    Public alias so app.py can call ee.snap_structural().
    """
    if 25 <= cm <= 34:
        return 30.0
    if 35 <= cm <= 46:
        return 40.0
    return cm


def measure_mamad_walls(pdf_bytes: bytes,
                        scale: int,
                        mamad_bbox: dict | None = None) -> list[float]:
    """
    Measure perimeter wall thicknesses for lines inside the ממ"ד bounding box.

    Strategy
    --------
    1. Collect vector lines; raise minimum length to 50 pt (structural walls
       are long — thin ticks, hatching, and annotation stubs are excluded).
    2. Filter out dimension lines: lines with perpendicular tick marks at both
       endpoints are classified as dimension/annotation lines and dropped.
    3. Restrict to lines overlapping the ממ"ד zone (with a 30 pt outward pad
       so the outer wall face is always included).
    4. Run the NumPy gap scanner in the structural range (20–80 cm).
    5. "Look deeper" pass: any isolated gap in [14, 27] cm that has no
       corresponding structural partner is re-examined using a relaxed overlap
       filter (min_ov = 15 pt, max wall = 36 cm).  If a wider measurement
       emerges, the shallow reading is replaced.
    6. Cluster with 9 cm tolerance; keep the maximum in each cluster.
    7. Apply structural snapping (25–34 → 30, 35–46 → 40).

    Returns sorted, snapped list of wall thicknesses in cm.
    """
    all_lines = extract_lines_all(pdf_bytes)
    # Step 1 — longer minimum (50 pt) to drop short annotation geometry
    h_lines, v_lines = _classify_lines(all_lines, min_length_pt=50.0)

    # Step 2 — remove dimension lines (tick-filtered)
    h_lines = _filter_dimension_lines(h_lines, all_lines)
    v_lines = _filter_dimension_lines(v_lines, all_lines)

    # Step 3 — restrict to ממ"ד zone
    if mamad_bbox:
        pg  = mamad_bbox["page"]
        pad = 30.0
        zx0, zt = mamad_bbox["x0"] - pad, mamad_bbox["top"]  - pad
        zx1, zb = mamad_bbox["x1"] + pad, mamad_bbox["bottom"] + pad

        def _in_zone(ln: dict) -> bool:
            if ln["page"] != pg:
                return False
            lx0 = min(ln["x0"], ln["x1"])
            lx1 = max(ln["x0"], ln["x1"])
            ly0 = min(ln["y0"], ln["y1"])
            ly1 = max(ln["y0"], ln["y1"])
            return lx1 >= zx0 and lx0 <= zx1 and ly1 >= zt and ly0 <= zb

        h_lines = [l for l in h_lines if _in_zone(l)]
        v_lines = [v for v in v_lines if _in_zone(v)]

    MIN_WALL_CM = 20.0
    MAX_WALL_CM = 80.0
    raw: list[float] = []

    # Step 4 — NumPy-vectorised gap scan
    if h_lines:
        yc  = np.array([(l["y0"] + l["y1"]) * 0.5 for l in h_lines])
        lx0 = np.array([min(l["x0"], l["x1"]) for l in h_lines])
        lx1 = np.array([max(l["x0"], l["x1"]) for l in h_lines])
        raw.extend(_vec_gap_pairs(yc, lx0, lx1, scale, MIN_WALL_CM, MAX_WALL_CM).tolist())

    if v_lines:
        xc  = np.array([(l["x0"] + l["x1"]) * 0.5 for l in v_lines])
        ly0 = np.array([min(l["y0"], l["y1"]) for l in v_lines])
        ly1 = np.array([max(l["y0"], l["y1"]) for l in v_lines])
        raw.extend(_vec_gap_pairs(xc, ly0, ly1, scale, MIN_WALL_CM, MAX_WALL_CM).tolist())

    # Step 5 — "Look deeper" for shallow readings in [14, 27] cm
    # A 22 cm reading is often a hatch sub-gap inside a 30 cm structural wall.
    # Relax the overlap filter and widen the search to [14, 36] cm to find the
    # true outer face.  If a deeper reading is found, replace the shallow one.
    SHALLOW_LO, SHALLOW_HI = 14.0, 27.0
    has_shallow = any(SHALLOW_LO <= g <= SHALLOW_HI for g in raw)
    if has_shallow:
        deep: list[float] = []
        if h_lines:
            deep.extend(_vec_gap_pairs(
                yc, lx0, lx1, scale,
                min_cm=SHALLOW_LO, max_cm=36.0,
                min_ov_pt=15.0,          # relaxed overlap requirement
            ).tolist())
        if v_lines:
            deep.extend(_vec_gap_pairs(
                xc, ly0, ly1, scale,
                min_cm=SHALLOW_LO, max_cm=36.0,
                min_ov_pt=15.0,
            ).tolist())
        # Keep any deeper reading that replaces a shallow one
        structural_deep = [g for g in deep if g > SHALLOW_HI]
        if structural_deep:
            # Drop shallow readings that have a structural partner nearby (≤ 12 cm)
            upgraded = set()
            for sh in [g for g in raw if SHALLOW_LO <= g <= SHALLOW_HI]:
                for dp in structural_deep:
                    if abs(dp - sh) <= 12.0:
                        upgraded.add(sh)
                        break
            raw = [g for g in raw if g not in upgraded] + structural_deep

    # Step 6 — Cluster (9 cm tolerance); keep maximum per cluster
    # • 22 + 30 → cluster → max = 30 ✓   • 30 + 40 → separate ✓
    if not raw:
        return []
    sorted_raw = sorted(raw)
    groups: list[list[float]] = [[sorted_raw[0]]]
    for v in sorted_raw[1:]:
        if v - groups[-1][-1] <= 9.0:
            groups[-1].append(v)
        else:
            groups.append([v])

    # Step 7 — Snap to structural standards
    result = sorted(snap_structural(max(g)) for g in groups)
    return result


# =============================================================================
# SECTION 10 — Heuristic Symbol Detection (Pipes & Door Arcs)
# =============================================================================

def _bbox_in_zone(x0: float, top: float, x1: float, bottom: float,
                  zone: dict, pad: float = 60.0) -> bool:
    cx = (x0 + x1) / 2
    cy = (top + bottom) / 2
    return (zone["x0"] - pad <= cx <= zone["x1"] + pad
            and zone["top"] - pad <= cy <= zone["bottom"] + pad)


def detect_pipe_symbols(pdf_bytes: bytes,
                        scale: int | None = None,
                        mamad_bbox: dict | None = None) -> list[dict]:
    """
    Detect 4-inch pipe cross-section circles (10–12 cm diameter).
    Returns list of {page, x0, top, x1, bottom, cx, cy, radius_cm}.
    """
    if mamad_bbox is None:
        return []

    PIPE_MIN_CM = 10.0
    PIPE_MAX_CM = 12.0

    if scale:
        min_pt = PIPE_MIN_CM / (PT_TO_CM * scale)
        max_pt = PIPE_MAX_CM / (PT_TO_CM * scale)
    else:
        return []

    target_pg = mamad_bbox["page"]
    zx0, zy0 = mamad_bbox["x0"], mamad_bbox["top"]
    zx1, zy1 = mamad_bbox["x1"], mamad_bbox["bottom"]

    results: list[dict] = []
    try:
        # _get_page_geometry is cached — no new pdfplumber open if
        # find_mamad_room_bbox already called it for the same page.
        _geo = _get_page_geometry(pdf_bytes, target_pg)
        for c in _geo["curves"]:
            x0 = c.get("x0", 0); x1 = c.get("x1", 0)
            t  = c.get("top", 0); b  = c.get("bottom", 0)
            w  = abs(x1 - x0);    h  = abs(b - t)
            if w < 0.5 or h < 0.5:
                continue
            aspect = w / h if h > 0 else 99
            if not (0.60 <= aspect <= 1.67):
                continue
            diam = (w + h) / 2
            if not (min_pt <= diam <= max_pt):
                continue
            cx = (x0 + x1) / 2
            cy = (t + b) / 2
            if not (zx0 <= cx <= zx1 and zy0 <= cy <= zy1):
                continue
            radius_cm = round(pts_to_real_cm(diam / 2, scale), 1)
            results.append({
                "page": target_pg,
                "x0": x0, "top": t, "x1": x1, "bottom": b,
                "cx": cx, "cy": cy,
                "radius_cm": radius_cm,
            })
    except Exception:
        pass
    return results


def detect_door_arc(pdf_bytes: bytes,
                    scale: int | None = None,
                    mamad_bbox: dict | None = None) -> list[dict]:
    """
    Detect door swing arcs (radius 70–100 cm).
    Returns list of {page, x0, top, x1, bottom, radius_cm}.
    """
    if mamad_bbox is None:
        return []

    DOOR_MIN_DIAM_CM = 140.0
    DOOR_MAX_DIAM_CM = 200.0

    if scale:
        min_pt = DOOR_MIN_DIAM_CM / (PT_TO_CM * scale)
        max_pt = DOOR_MAX_DIAM_CM / (PT_TO_CM * scale)
    else:
        return []

    target_pg = mamad_bbox["page"]
    PAD = 15.0
    zx0 = mamad_bbox["x0"] - PAD;  zy0 = mamad_bbox["top"] - PAD
    zx1 = mamad_bbox["x1"] + PAD;  zy1 = mamad_bbox["bottom"] + PAD

    results: list[dict] = []
    try:
        # Cache hit — same page already loaded by find_mamad_room_bbox and/or
        # detect_pipe_symbols; no additional pdfplumber open needed.
        _geo = _get_page_geometry(pdf_bytes, target_pg)
        for c in _geo["curves"]:
            x0 = c.get("x0", 0); x1 = c.get("x1", 0)
            t  = c.get("top", 0); b  = c.get("bottom", 0)
            w  = abs(x1 - x0);    h  = abs(b - t)
            if w < 1 or h < 1:
                continue
            aspect = w / h if h > 0 else 99
            if not (0.4 <= aspect <= 2.5):
                continue
            diam = (w + h) / 2
            if not (min_pt <= diam <= max_pt):
                continue
            cx = (x0 + x1) / 2
            cy = (t + b) / 2
            if not (zx0 <= cx <= zx1 and zy0 <= cy <= zy1):
                continue
            radius_cm = round(pts_to_real_cm(diam / 2, scale), 1)
            results.append({
                "page": target_pg,
                "x0": x0, "top": t, "x1": x1, "bottom": b,
                "radius_cm": radius_cm,
            })
    except Exception:
        pass
    return results


def get_all_visual_detections(pdf_bytes: bytes,
                               scale: int | None = None,
                               word_coords: list[dict] | None = None) -> dict:
    """
    Run all symbol detections and return a consolidated result dict.

    Returns:
        mamad_bbox   — {page, x0, top, x1, bottom} or None
        pipes        — list of pipe circle dicts
        door_arcs    — list of door arc dicts
        mamad_walls  — list of perimeter wall thicknesses in cm
    """
    mamad_bbox  = find_mamad_room_bbox(pdf_bytes, word_coords=word_coords, scale=scale)
    pipes       = detect_pipe_symbols(pdf_bytes, scale=scale, mamad_bbox=mamad_bbox)
    door_arcs   = detect_door_arc(pdf_bytes, scale=scale, mamad_bbox=mamad_bbox)
    mamad_walls = measure_mamad_walls(pdf_bytes, scale, mamad_bbox=mamad_bbox) if scale else []

    return {
        "mamad_bbox":  mamad_bbox,
        "pipes":       pipes,
        "door_arcs":   door_arcs,
        "mamad_walls": mamad_walls,
    }
