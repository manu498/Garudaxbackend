"""PDF documentation for a complaint (details, AI result, photos, before/after and full timeline)."""
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from PIL import Image as PILImage, ImageOps
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import config

NAVY = colors.HexColor("#10243A")
BLUE = colors.HexColor("#1C5FC5")
LIGHT = colors.HexColor("#EEF3F9")


def _photo(filename, max_w, max_h):
    if not filename:
        return None
    path = config.UPLOADS / filename
    if not path.is_file():
        return None
    try:
        with PILImage.open(path) as img:
            img = ImageOps.exif_transpose(img).convert("RGB")
            img.thumbnail((1000, 1000))
            buf = BytesIO()
            img.save(buf, "JPEG", quality=82)
            w, h = img.size
        scale = min(max_w / w, max_h / h)
        buf.seek(0)
        return Image(buf, width=w * scale, height=h * scale)
    except Exception:
        return None


def build_complaint_pdf(c: dict, history: list) -> bytes:
    """c = complaint dict (as returned by the API), history = list of timeline dicts."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"GarudaX Complaint GX-{c['id']:05d}", author="GarudaX")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], textColor=colors.white, fontSize=18, leading=22, alignment=0)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=NAVY, fontSize=12.5, spaceBefore=10, spaceAfter=5)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#5A6B7D"))
    P = lambda t, st=body: Paragraph(escape(str(t if t not in (None, "") else "-")), st)

    story = []
    banner = Table([[Paragraph("GarudaX — Road Damage Complaint Report", h1)],
                    [Paragraph(f"<font color='#BFD7F5'>Complaint #GX-{c['id']:05d} &nbsp;•&nbsp; Generated {datetime.now():%d %b %Y, %I:%M %p}</font>", body)]],
                   colWidths=[doc.width])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 12),
                                ("TOPPADDING", (0, 0), (-1, 0), 10), ("BOTTOMPADDING", (0, -1), (-1, -1), 10)]))
    story += [banner, Spacer(1, 8)]

    maps = f"https://maps.google.com/?q={c['latitude']},{c['longitude']}"
    conf = f"{c['confidence']}%" if c.get("confidence") is not None else "-"
    rows = [
        ["Status", c.get("status")], ["Priority", f"{c.get('priority_label')} (score {c.get('priority_score')})"],
        ["High emergency", "YES — open for more than %d days" % config.ESCALATION_DAYS if c.get("high_emergency") else "No"],
        ["Reported by", c.get("citizen_name")], ["Reported on", c.get("created_at")],
        ["Description", c.get("description")],
        ["AI detection (YOLOv8)", f"{c.get('damage_type') or '-'}  •  confidence {conf}" + ("  •  AI unsure: awaiting manual photo review" if c.get("ai_review") else "")],
        ["Location (GPS)", f"{c['latitude']:.6f}, {c['longitude']:.6f}"],
        ["Google Maps", maps],
        ["Also reported by", f"{c.get('support_count', 0)} other citizen(s)"],
        ["Assigned repair worker", c.get("worker_name") or "Not assigned"],
        ["Verification note", c.get("verification_note")],
        ["Completed on", c.get("completed_at")],
    ]
    t = Table([[P(k, ParagraphStyle("k", parent=body, fontName="Helvetica-Bold")), P(v)] for k, v in rows], colWidths=[48 * mm, doc.width - 48 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D6E4")), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story += [Paragraph("Complaint details", h2), t]

    story.append(Paragraph("Photographs", h2))
    reported = _photo(c.get("photo_filename"), doc.width, 75 * mm)
    story.append(reported if reported else P("Complaint photo not available.", small))
    story.append(Paragraph("Reported photo (taken with the citizen's camera, verified by AI)", small))
    before = _photo(c.get("before_photo_filename"), doc.width / 2 - 6, 60 * mm)
    after = _photo(c.get("after_photo_filename"), doc.width / 2 - 6, 60 * mm)
    if before or after:
        pics = Table([[before or P("No before photo yet", small), after or P("No after photo yet", small)],
                      [P("BEFORE repair", small), P("AFTER repair", small)]], colWidths=[doc.width / 2] * 2)
        pics.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story += [Spacer(1, 6), KeepTogether([Paragraph("Repair evidence", h2), pics])]

    story.append(Paragraph("Complaint timeline", h2))
    trows = [[P("Date & time", ParagraphStyle("th", parent=body, fontName="Helvetica-Bold", textColor=colors.white)),
              P("Status", ParagraphStyle("th2", parent=body, fontName="Helvetica-Bold", textColor=colors.white)),
              P("By", ParagraphStyle("th3", parent=body, fontName="Helvetica-Bold", textColor=colors.white)),
              P("Note", ParagraphStyle("th4", parent=body, fontName="Helvetica-Bold", textColor=colors.white))]]
    for h in history:
        trows.append([P(h.get("created_at")), P(h.get("status")), P(f"{h.get('actor_name')} ({h.get('actor_role')})"), P(h.get("note"))])
    tl = Table(trows, colWidths=[32 * mm, 34 * mm, 42 * mm, doc.width - 108 * mm], repeatRows=1)
    tl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), BLUE), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D6E4")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT])]))
    story += [tl, Spacer(1, 10), Paragraph("This document was generated automatically by the GarudaX Road Damage Detection and Repair Tracking System.", small)]
    doc.build(story)
    return buf.getvalue()
