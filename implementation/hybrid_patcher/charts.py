"""
PIL-based high-quality chart rendering for the StatsWindow.

The GUI calls these functions, gets back a `PIL.Image`, wraps it in
`ImageTk.PhotoImage`, and displays it on a Canvas. Each chart renders at
2x the display resolution and then downsamples with LANCZOS so the lines
and text look smooth on Hi-DPI screens.

If Pillow is not installed at import time, every helper raises
`PILNotAvailable`. The GUI catches that and falls back to the older
Tk-Canvas chart code in gui.py.

Style is intentionally modest: flat fills, soft drop shadows, light
grid lines, rounded bar corners. No bevels, no 3D effects.
"""
from __future__ import annotations
from typing import List, Optional, Sequence, Tuple


class PILNotAvailable(RuntimeError):
    pass


try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_OK = True
except ImportError:
    _PIL_OK = False


# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

SCALE = 2                    # supersampling factor
BG_COLOR = "#fafafa"         # very light off-white
PLOT_BG = "#ffffff"
GRID_COLOR = "#e8e8e8"
AXIS_COLOR = "#cccccc"
TICK_COLOR = "#666666"
TEXT_COLOR = "#000000"       # pure black for headings, body text, legend
SUBTLE_TEXT = "#444444"      # axis ticks (a bit lighter than body)

# Bar corner radius. 0 = sharp rectangles (no rounding).
BAR_RADIUS = 0

# Slight gap between pie slices so adjacent same-value slices stay distinct.
PIE_GAP_DEG = 0.4
# Inner-radius / outer-radius. 0 = solid pie, > 0 = donut. Solid by request.
PIE_DONUT_RATIO = 0.0


# ---------------------------------------------------------------------------
# Font loading -- try Windows UI fonts first, then a common Linux/Mac set.
# ---------------------------------------------------------------------------

_FONT_CANDIDATES = [
    # Windows
    ("C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/segoeui.ttf"),
    ("C:/Windows/Fonts/calibrib.ttf", "C:/Windows/Fonts/calibri.ttf"),
    ("C:/Windows/Fonts/arialbd.ttf",  "C:/Windows/Fonts/arial.ttf"),
    # Linux
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    # macOS
    ("/System/Library/Fonts/Helvetica.ttc",
     "/System/Library/Fonts/Helvetica.ttc"),
]


def _load_fonts(size: int) -> Tuple["ImageFont.ImageFont", "ImageFont.ImageFont"]:
    """Return (regular_font, bold_font). Falls back to PIL's default
    bitmap font if no TTF is available."""
    if not _PIL_OK:
        raise PILNotAvailable("Pillow is not installed")
    bold = regular = None
    for bold_path, reg_path in _FONT_CANDIDATES:
        try:
            bold = ImageFont.truetype(bold_path, size)
            regular = ImageFont.truetype(reg_path, size)
            return regular, bold
        except (OSError, IOError):
            continue
    # Last-ditch: PIL's default (no scaling, but at least it draws text)
    return ImageFont.load_default(), ImageFont.load_default()


# ---------------------------------------------------------------------------
# Drawing primitives
# ---------------------------------------------------------------------------

def _new_canvas(w: int, h: int):
    """Allocate an RGBA image at SCALE * size, white-ish background."""
    if not _PIL_OK:
        raise PILNotAvailable("Pillow is not installed")
    img = Image.new("RGBA", (w * SCALE, h * SCALE), BG_COLOR)
    return img


def _finalize(img):
    """Downsample from SCALE x size to display size with LANCZOS."""
    target = (img.width // SCALE, img.height // SCALE)
    return img.resize(target, Image.Resampling.LANCZOS)


def _rounded_rect(draw, xy, radius, fill, outline=None):
    """Pillow >= 8 has create rounded_rectangle. Use it directly."""
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline)


def _hex_to_rgba(c: str, alpha: int = 255) -> Tuple[int, int, int, int]:
    c = c.lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    return (r, g, b, alpha)


def _text_size(draw, text, font):
    """Return (width, height) of text as it will be drawn."""
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def _format_int(v):
    """Add thousand separators to a number (PIL ints / floats)."""
    try:
        return f"{int(round(v)):,}"
    except Exception:
        return str(v)


# ---------------------------------------------------------------------------
# Pie / donut chart
# ---------------------------------------------------------------------------

def draw_pie(width: int, height: int,
             slices: Sequence[Tuple[str, float, str]],
             title: Optional[str] = None,
             donut: bool = True):
    """Adaptive pie-chart renderer.

    Chooses a side-by-side layout (pie left, legend right) on wide canvases
    (aspect >= 1.6) and a top-bottom layout (pie above, legend below) on
    near-square / tall canvases. Font sizes scale with min(width, height)
    so the chart remains visually balanced from the small GUI display
    (~900x280) up to the HD save (~2400x1600).

    slices = [(label, value, hex_color), ...]. Returns a PIL.Image at
    display size."""
    if not _PIL_OK:
        raise PILNotAvailable("Pillow is not installed")
    img = _new_canvas(width, height)
    draw = ImageDraw.Draw(img)
    s = SCALE

    # Adaptive font scale: 1.0 at 900x360 design size, scales up for larger
    # canvases so HD exports keep proportional typography.
    scale = max(0.85, min(2.6, min(width / 900.0, height / 360.0)))
    title_pt  = max(13, int(round(14 * scale)))
    legend_pt = max(11, int(round(13 * scale)))
    sub_pt    = max(10, int(round(11 * scale)))
    fr_small, _ = _load_fonts(sub_pt * s)
    _, fb_title  = _load_fonts(title_pt * s)
    fr_legend, _ = _load_fonts(legend_pt * s)

    # Title (always centered along the top)
    pad_top = int(round(6 * scale)) * s
    if title:
        tw, th = _text_size(draw, title, fb_title)
        draw.text(((width * s - tw) // 2, pad_top),
                  title, fill=TEXT_COLOR, font=fb_title)
        title_h = th + int(round(14 * scale)) * s
    else:
        title_h = 0

    total = sum(v for _, v, _ in slices) or 1.0
    visible = [(label, value, color) for label, value, color in slices
               if value > 0]

    # Pre-measure the legend so we know how much horizontal / vertical room
    # it needs in either layout.
    chip      = max(14 * s, int(round(16 * scale)) * s)
    line_h    = max(22 * s, int(round(26 * scale)) * s)
    chip_gap  = int(round(8 * scale)) * s
    legend_text_w = 0
    for label, value, color in visible:
        pct = 100.0 * value / total
        text = f"{label}    {_format_int(value)}  ({pct:.1f}%)"
        tw, _th = _text_size(draw, text, fr_legend)
        legend_text_w = max(legend_text_w, tw)
    legend_w = chip + chip_gap + legend_text_w
    legend_h = max(1, len(visible)) * line_h

    pad      = max(8 * s, int(round(12 * scale)) * s)
    aspect = (width * s) / max(height * s - title_h, 1)
    use_horizontal = aspect >= 1.6

    if use_horizontal:
        # Side-by-side: pie left, legend right. The pie's diameter is the
        # smaller of (canvas height minus title) and (canvas width minus
        # legend width minus paddings) so it always fills its area.
        avail_pie_w = (width * s) - legend_w - pad * 3
        avail_pie_h = (height * s) - title_h - pad * 2
        pie_d = max(60 * s, min(avail_pie_w, avail_pie_h))
        pie_block_x = pad
        pie_block_w = avail_pie_w + pad
        cx = pie_block_x + pie_block_w // 2
        cy = title_h + pad + avail_pie_h // 2

        legend_x = (width * s) - legend_w - pad
        legend_y = title_h + pad + (avail_pie_h - legend_h) // 2
    else:
        # Top-bottom: pie centered horizontally, legend below it. Used on
        # near-square / tall canvases (e.g. the HD-save case where the
        # display canvas grew vertical).
        avail_pie_h = (height * s) - title_h - legend_h - pad * 3
        avail_pie_w = (width * s) - pad * 2
        pie_d = max(60 * s, min(avail_pie_w, avail_pie_h))
        cx = (width * s) // 2
        cy = title_h + pad + avail_pie_h // 2

        legend_x = ((width * s) - legend_w) // 2
        legend_y = title_h + pad + avail_pie_h + pad

    r_outer = pie_d // 2 - 2 * s
    r_inner = int(r_outer * PIE_DONUT_RATIO) if donut else 0

    # Pie slices, drawn clockwise from 12 o'clock
    start = -90.0
    for label, value, color in visible:
        extent = 360.0 * value / total
        sweep_start = start + PIE_GAP_DEG / 2.0
        sweep_end = start + extent - PIE_GAP_DEG / 2.0
        if sweep_end <= sweep_start:
            sweep_end = sweep_start + 0.1
        draw.pieslice((cx - r_outer, cy - r_outer,
                       cx + r_outer, cy + r_outer),
                      sweep_start, sweep_end,
                      fill=_hex_to_rgba(color))
        start += extent

    # Donut hole
    if donut and r_inner > 0:
        draw.ellipse((cx - r_inner, cy - r_inner,
                      cx + r_inner, cy + r_inner),
                     fill=BG_COLOR)
        tot_str = _format_int(total)
        tw, th = _text_size(draw, tot_str, fb_title)
        draw.text((cx - tw // 2, cy - th // 2 - int(round(8 * scale)) * s),
                  tot_str, fill=TEXT_COLOR, font=fb_title)
        sub = "total"
        tw2, th2 = _text_size(draw, sub, fr_small)
        draw.text((cx - tw2 // 2, cy + th // 2 - int(round(6 * scale)) * s),
                  sub, fill=SUBTLE_TEXT, font=fr_small)

    # Legend
    ly = legend_y
    for label, value, color in visible:
        pct = 100.0 * value / total
        draw.rectangle((legend_x, ly, legend_x + chip, ly + chip),
                       fill=_hex_to_rgba(color))
        text = f"{label}    {_format_int(value)}  ({pct:.1f}%)"
        # Vertically centre the text against the chip.
        _tw, th = _text_size(draw, text, fr_legend)
        draw.text((legend_x + chip + chip_gap,
                   ly + (chip - th) // 2),
                  text, fill=TEXT_COLOR, font=fr_legend)
        ly += line_h

    return _finalize(img)


# ---------------------------------------------------------------------------
# Horizontal bar chart
# ---------------------------------------------------------------------------

def draw_hbar(width: int, height: int,
              rows: Sequence[Tuple[str, float, str]],
              title: Optional[str] = None,
              label_w: int = 100):
    """rows = [(label, value, hex_color), ...]. Returns PIL.Image."""
    if not _PIL_OK:
        raise PILNotAvailable("Pillow is not installed")
    img = _new_canvas(width, height)
    draw = ImageDraw.Draw(img)
    s = SCALE

    # Adaptive font scale: 1.0 at 1200x600 design size, scales up for HD.
    scale = max(0.85, min(2.6, min(width / 1200.0, height / 600.0)))
    body_pt  = max(11, int(round(12 * scale)))
    title_pt = max(13, int(round(15 * scale)))
    fr, fb = _load_fonts(body_pt * s)
    _, fb_title = _load_fonts(title_pt * s)

    pad = max(10 * s, int(round(12 * scale)) * s)
    y = pad
    if title:
        draw.text((pad, y), title, fill=TEXT_COLOR, font=fb_title)
        y += int(round(26 * scale)) * s

    if not rows:
        draw.text((pad, y), "(no data)", fill=SUBTLE_TEXT, font=fr)
        return _finalize(img)

    # Layout: label column | bars | value column
    label_w_s = label_w * s
    value_w_s = max(70, int(round(90 * scale))) * s
    bar_left = pad + label_w_s + 8 * s
    bar_right = width * s - pad - value_w_s - 8 * s
    bar_max_w = bar_right - bar_left
    n = len(rows)
    avail_h = height * s - y - pad
    # Bigger minimum row height so labels stay readable, scales with
    # canvas. Cap at 60 so few-row charts do not leave huge gaps.
    row_h_min = int(round(22 * scale)) * s
    row_h_max = int(round(60 * scale)) * s
    row_h = max(row_h_min, min(row_h_max, avail_h // n))
    bar_h = row_h - max(4 * s, int(round(6 * scale)) * s)

    max_v = max(v for _, v, _ in rows) or 1.0

    # Soft grid line at 25% / 50% / 75% of max
    for q in (0.25, 0.5, 0.75, 1.0):
        gx = int(bar_left + bar_max_w * q)
        draw.line((gx, y - 2 * s, gx, y + n * row_h + 2 * s),
                  fill=GRID_COLOR, width=1)

    for i, (label, value, color) in enumerate(rows):
        ry = y + i * row_h
        # Label
        ty = ry + (row_h - _text_size(draw, "Ag", fr)[1]) // 2
        draw.text((pad, ty), str(label), fill=TEXT_COLOR, font=fr)
        # Bar -- flat rectangle, no shadow.
        bw = int(bar_max_w * value / max_v) if max_v else 0
        if bw > 0:
            xy = (bar_left, ry + 3 * s,
                  bar_left + bw, ry + 3 * s + bar_h)
            draw.rectangle(xy, fill=_hex_to_rgba(color))
        # Value text right of bar
        vstr = _format_int(value)
        vw, vh = _text_size(draw, vstr, fr)
        draw.text((bar_left + bw + 6 * s,
                   ry + (row_h - vh) // 2),
                  vstr, fill=TEXT_COLOR, font=fr)

    return _finalize(img)


# ---------------------------------------------------------------------------
# Vertical bar chart (histogram)
# ---------------------------------------------------------------------------

def draw_vbar(width: int, height: int,
              rows: Sequence[Tuple[str, float, str]],
              title: Optional[str] = None,
              y_label: Optional[str] = None):
    """rows = [(label, value, hex_color), ...]. Returns PIL.Image."""
    if not _PIL_OK:
        raise PILNotAvailable("Pillow is not installed")
    img = _new_canvas(width, height)
    draw = ImageDraw.Draw(img)
    s = SCALE

    # Adaptive font scale: 1.0 at 900x420 design size, scales up for HD.
    scale = max(0.85, min(2.6, min(width / 900.0, height / 420.0)))
    body_pt  = max(10, int(round(11 * scale)))
    small_pt = max(9, int(round(10 * scale)))
    title_pt = max(13, int(round(14 * scale)))
    fr, fb = _load_fonts(body_pt * s)
    fr_small, _ = _load_fonts(small_pt * s)
    _, fb_title = _load_fonts(title_pt * s)

    pad = max(10 * s, int(round(12 * scale)) * s)
    y_top = pad
    if title:
        tw, th = _text_size(draw, title, fb_title)
        draw.text(((width * s - tw) // 2, y_top),
                  title, fill=TEXT_COLOR, font=fb_title)
        y_top += int(round(26 * scale)) * s

    # Reserve room for X-axis labels (multi-line wrap if needed)
    label_band = int(round(48 * scale)) * s
    plot_top = y_top
    plot_bot = height * s - pad - label_band
    plot_left = pad + int(round(48 * scale)) * s     # space for Y-axis ticks
    plot_right = width * s - pad
    plot_w = plot_right - plot_left
    plot_h = plot_bot - plot_top

    # Plot background
    draw.rectangle((plot_left, plot_top, plot_right, plot_bot),
                   fill=PLOT_BG)

    if not rows:
        draw.text((plot_left + 10 * s, plot_top + plot_h // 2),
                  "(no data)", fill=SUBTLE_TEXT, font=fr)
        return _finalize(img)

    max_v = max(v for _, v, _ in rows) or 1.0

    # Y-axis ticks (5 levels)
    for q in (0.0, 0.25, 0.5, 0.75, 1.0):
        ty = plot_bot - q * plot_h
        draw.line((plot_left, ty, plot_right, ty),
                  fill=GRID_COLOR if q != 0.0 else AXIS_COLOR,
                  width=1)
        tick_val = _format_int(q * max_v)
        tw, th = _text_size(draw, tick_val, fr_small)
        draw.text((plot_left - 8 * s - tw, ty - th // 2),
                  tick_val, fill=SUBTLE_TEXT, font=fr_small)

    # Y-axis label (rotated)
    if y_label:
        # Render text on a separate strip and rotate 90 degrees
        try:
            stub = Image.new("RGBA", (plot_h, 30 * s), (0, 0, 0, 0))
            sd = ImageDraw.Draw(stub)
            sd.text((0, 4 * s), y_label, fill=SUBTLE_TEXT, font=fr_small)
            stub = stub.rotate(90, expand=True, resample=Image.BICUBIC)
            img.alpha_composite(stub, (4 * s, plot_top))
        except Exception:
            pass

    # Bars
    n = len(rows)
    cell_w = plot_w / n
    bar_w = max(10 * s, int(cell_w * 0.62))
    for i, (label, value, color) in enumerate(rows):
        cx = plot_left + cell_w * i + cell_w / 2
        bh = int(plot_h * value / max_v) if max_v else 0
        x0 = int(cx - bar_w / 2)
        x1 = int(cx + bar_w / 2)
        y1 = plot_bot
        y0 = plot_bot - bh
        # Bar -- flat rectangle, no shadow.
        if bh > 0:
            draw.rectangle((x0, y0, x1, y1),
                           fill=_hex_to_rgba(color))

        # Value above bar
        vstr = _format_int(value)
        vw, vh = _text_size(draw, vstr, fr)
        vy = max(plot_top + 2, y0 - vh - 4 * s)
        draw.text((int(cx - vw / 2), int(vy)),
                  vstr, fill=TEXT_COLOR, font=fr)

        # Label below baseline (X-axis); allow up to 2 lines if a long
        # status name doesn't fit in one cell
        avail = int(cell_w - 6 * s)
        lines = _wrap_to_width(draw, str(label), fr_small, avail)
        ly = plot_bot + 8 * s
        for line in lines[:2]:
            lw, lh = _text_size(draw, line, fr_small)
            draw.text((int(cx - lw / 2), int(ly)),
                      line, fill=SUBTLE_TEXT, font=fr_small)
            ly += lh + 1 * s

    # X-axis baseline
    draw.line((plot_left, plot_bot, plot_right, plot_bot),
              fill=AXIS_COLOR, width=1)

    return _finalize(img)


def _wrap_to_width(draw, text: str, font, max_w: int) -> List[str]:
    """Greedy word wrap so each line is <= max_w pixels."""
    if not text:
        return [""]
    words = text.replace("_", "_ ").split(" ")   # break on underscore too
    lines: List[str] = []
    cur: List[str] = []
    for w in words:
        candidate = " ".join(cur + [w]).rstrip()
        if _text_size(draw, candidate, font)[0] <= max_w or not cur:
            cur.append(w)
        else:
            lines.append(" ".join(cur).strip())
            cur = [w]
    if cur:
        lines.append(" ".join(cur).strip())
    return [l.replace("_ ", "_") for l in lines]
