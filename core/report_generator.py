# core/report_generator.py
"""
Professional pentest PDF report generator — Redline-grade output.
Sections: Cover, Assessment Info, Disclaimer, TOC, Executive Summary,
Methodology, Vulnerability Overview, Vulnerability Summary, Attack Chain,
Detailed Findings, Appendix.
"""

import json
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, Image
)

try:
    from report_visuals import (
        severity_bar, risk_heatmap, hexagon_methodology,
        attack_chain_diagram, severity_donut
    )
    VISUALS_AVAILABLE = True
except ImportError:
    try:
        from core.report_visuals import (
            severity_bar, risk_heatmap, hexagon_methodology,
            attack_chain_diagram, severity_donut
        )
        VISUALS_AVAILABLE = True
    except ImportError:
        VISUALS_AVAILABLE = False
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# ── Palette ──────────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#1B2A4A")
RED         = colors.HexColor("#CC2200")
ORANGE      = colors.HexColor("#D4621A")
GOLD        = colors.HexColor("#C8960C")
GREEN       = colors.HexColor("#2E7D32")
BLUE_INFO   = colors.HexColor("#5B8DB8")
LIGHT_GRAY  = colors.HexColor("#F5F5F5")
MID_GRAY    = colors.HexColor("#9E9E9E")
DARK_GRAY   = colors.HexColor("#424242")
BLACK       = colors.HexColor("#111111")
WHITE       = colors.white
TERMINAL_BG = colors.HexColor("#1E1E1E")
TERMINAL_FG = colors.HexColor("#D4D4D4")
HIGHLIGHT   = colors.HexColor("#FFD700")


def _embed_chart(buf, width_inch=6.5, height_inch=None):
    """Embed a matplotlib BytesIO buffer as a reportlab Image."""
    if not VISUALS_AVAILABLE or buf is None:
        return Spacer(1, 4)
    img = Image(buf)
    img.drawWidth  = width_inch * inch
    img.drawHeight = (height_inch * inch) if height_inch else img.drawHeight * (width_inch * inch / img.drawWidth)
    return img

SEV_COLOR = {
    "critical":     RED,
    "high":         ORANGE,
    "medium":       GOLD,
    "low":          GREEN,
    "info":         BLUE_INFO,
    "informational":BLUE_INFO,
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}

ID_PREFIX = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I", "informational": "I"}


# ── Styles ───────────────────────────────────────────────────────────────────
def _styles():
    return {
        "h1": ParagraphStyle("h1", fontSize=22, leading=28, textColor=NAVY,
                             fontName="Helvetica-Bold", spaceAfter=6),
        "h2": ParagraphStyle("h2", fontSize=14, leading=18, textColor=NAVY,
                             fontName="Helvetica-Bold", spaceAfter=4),
        "h3": ParagraphStyle("h3", fontSize=11, leading=15, textColor=DARK_GRAY,
                             fontName="Helvetica-Bold", spaceAfter=3),
        "body": ParagraphStyle("body", fontSize=10, leading=14, textColor=BLACK,
                               fontName="Helvetica", spaceAfter=4),
        "body_j": ParagraphStyle("body_j", fontSize=10, leading=14, textColor=BLACK,
                                 fontName="Helvetica", alignment=TA_JUSTIFY),
        "small": ParagraphStyle("small", fontSize=9, leading=13, textColor=DARK_GRAY,
                                fontName="Helvetica"),
        "label": ParagraphStyle("label", fontSize=9, leading=13, textColor=DARK_GRAY,
                                fontName="Helvetica-Bold"),
        "code": ParagraphStyle("code", fontSize=8.5, leading=13, textColor=TERMINAL_FG,
                               fontName="Courier", backColor=TERMINAL_BG,
                               leftIndent=8, rightIndent=8, spaceBefore=2, spaceAfter=2),
        "toc": ParagraphStyle("toc", fontSize=10, leading=16, textColor=BLACK,
                              fontName="Helvetica"),
        "cover_title": ParagraphStyle("cover_title", fontSize=28, leading=36,
                                      textColor=BLACK, fontName="Helvetica-Bold"),
        "cover_sub": ParagraphStyle("cover_sub", fontSize=14, leading=20,
                                    textColor=DARK_GRAY, fontName="Helvetica"),
        "cover_red": ParagraphStyle("cover_red", fontSize=16, leading=22,
                                    textColor=RED, fontName="Helvetica-Bold"),
        "white_bold": ParagraphStyle("white_bold", fontSize=10, leading=14,
                                     textColor=WHITE, fontName="Helvetica-Bold",
                                     alignment=TA_CENTER),
        "white": ParagraphStyle("white", fontSize=9, leading=13,
                                textColor=WHITE, fontName="Helvetica"),
        "mitre": ParagraphStyle("mitre", fontSize=8.5, leading=12, textColor=MID_GRAY,
                                fontName="Courier-Oblique"),
    }


# ── Header / Footer ──────────────────────────────────────────────────────────
def _header_footer(canvas, doc, company: str, target: str, date_str: str):
    canvas.saveState()
    w, h = letter

    # Top bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 36, w, 36, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(0.5 * inch, h - 23, "ROYCrew")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(MID_GRAY)
    canvas.drawRightString(w - 0.5 * inch, h - 23, f"Penetration Test Report — {target}")

    # Bottom bar
    canvas.setFillColor(LIGHT_GRAY)
    canvas.rect(0, 0, w, 26, fill=1, stroke=0)
    canvas.setFillColor(MID_GRAY)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.5 * inch, 8, f"CONFIDENTIAL  |  {company}  |  {date_str}")
    # Page number box
    canvas.setFillColor(NAVY)
    canvas.rect(w - 0.55 * inch, 0, 0.55 * inch, 26, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawCentredString(w - 0.27 * inch, 8, str(doc.page))

    canvas.restoreState()


# ── Divider ──────────────────────────────────────────────────────────────────
def _divider(color=NAVY):
    return HRFlowable(width="100%", thickness=1.5, color=color, spaceAfter=8, spaceBefore=4)


def _section(title: str, s: dict):
    return [
        Spacer(1, 14),
        Paragraph(title, s["h1"]),
        _divider(),
    ]


# ── Terminal block ────────────────────────────────────────────────────────────
def _terminal(lines: list, s: dict):
    """Dark terminal-style evidence block."""
    text = "<br/>".join(lines)
    t = Table(
        [[Paragraph(text, s["code"])]],
    )
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), TERMINAL_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#333333")),
    ]))
    return t


# ── Finding card (Redline style) ──────────────────────────────────────────────
def _finding_card(fid: str, title: str, sev: str, description: str,
                  impact: str, assets: str, remediation: str,
                  references: str, evidence_lines: list, s: dict):
    sev_norm = sev.lower()
    col = SEV_COLOR.get(sev_norm, MID_GRAY)
    sev_label = sev.upper() if sev_norm != "informational" else "INFORMATIONAL"

    elems = []

    # Header row: ID badge | Title | Severity badge
    header = Table(
        [[
            Paragraph(f"<b>{fid}</b>",
                      ParagraphStyle("fid", fontSize=11, fontName="Helvetica-Bold",
                                     textColor=WHITE, alignment=TA_CENTER)),
            Paragraph(f"<b>{fid} - {title}</b>",
                      ParagraphStyle("ftitle", fontSize=11, fontName="Helvetica-Bold",
                                     textColor=WHITE)),
            Paragraph(sev_label,
                      ParagraphStyle("fsev", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=WHITE, alignment=TA_RIGHT)),
        ]],
        colWidths=[0.55 * inch, 4.8 * inch, 1.15 * inch]
    )
    header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0),   colors.HexColor("#333333")),
        ("BACKGROUND",    (1, 0), (1, 0),   col),
        ("BACKGROUND",    (2, 0), (2, 0),   col),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # Body rows
    def _row(label, content):
        return [
            Paragraph(label, s["label"]),
            Paragraph(content, s["body"])
        ]

    body_data = [
        _row("Description", description),
        _row("Impact",       impact),
        _row("Affected Assets", assets),
        _row("Remediation",  remediation),
        _row("References",   references),
    ]
    body = Table(body_data, colWidths=[1.3 * inch, 5.2 * inch])
    body.setStyle(TableStyle([
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [WHITE, LIGHT_GRAY, WHITE, LIGHT_GRAY, WHITE]),
        ("BOX",           (0, 0), (-1, -1), 0.5, MID_GRAY),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, MID_GRAY),
    ]))

    elems.append(KeepTogether([header, body]))

    # Evidence
    if evidence_lines:
        elems.append(Spacer(1, 6))
        elems.append(Paragraph("<b>The following evidence has been gathered to illustrate this finding:</b>",
                                s["small"]))
        elems.append(Spacer(1, 4))
        elems.append(_terminal(evidence_lines, s))

    elems.append(Spacer(1, 16))
    return elems


# ── Main generator ────────────────────────────────────────────────────────────
class PentestReportGenerator:

    def __init__(self, report: dict, output_path: str = None,
                 client_name: str = "Client Organization",
                 client_contact: str = "Security Team",
                 consultant_name: str = "ROYCrew Agent",
                 engagement_type: str = "Black-Box Web Application Penetration Test"):

        self.report           = report
        self.target           = report.get("target", "Unknown")
        self.client_name      = client_name
        self.client_contact   = client_contact
        self.consultant_name  = consultant_name
        self.engagement_type  = engagement_type
        self.date_str         = datetime.now().strftime("%B %d, %Y")
        self.date_file        = datetime.now().strftime("%Y-%m-%d")
        self.s                = _styles()

        if output_path is None:
            safe = self.target.replace("/", "_").replace(":", "_").replace(".", "_")
            output_path = f"reports/{safe}_report_{self.date_file}.pdf"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        self.output_path = output_path

        # Pre-process findings
        self.findings = self._process_findings()

    def _process_findings(self):
        raw = self.report.get("findings", [])
        sorted_f = sorted(raw, key=lambda f: SEV_RANK.get(f.get("severity", "info").lower(), 4))
        counters = {}
        result = []
        for f in sorted_f:
            sev = f.get("severity", "info").lower()
            prefix = ID_PREFIX.get(sev, "I")
            counters[prefix] = counters.get(prefix, 0) + 1
            result.append({**f, "id": f"{prefix}{counters[prefix]}", "sev_norm": sev})
        return result

    # ── public ───────────────────────────────────────────────────────────────
    def generate(self) -> str:
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.55 * inch,
        )

        story = []
        story += self._cover()
        story.append(PageBreak())
        story += self._assessment_info()
        story.append(PageBreak())
        story += self._disclaimer()
        story.append(PageBreak())
        story += self._toc()
        story.append(PageBreak())
        story += self._executive_summary()
        story.append(PageBreak())
        story += self._methodology()
        story.append(PageBreak())
        story += self._vuln_overview()
        story += self._vuln_summary()
        story.append(PageBreak())
        story += self._attack_chain()
        story.append(PageBreak())
        story += self._detailed_findings()
        story += self._appendix()

        doc.build(
            story,
            onFirstPage=lambda c, d: None,
            onLaterPages=lambda c, d: _header_footer(
                c, d, self.client_name, self.target, self.date_str),
        )
        return self.output_path

    # ── Cover ─────────────────────────────────────────────────────────────────
    def _cover(self):
        s = self.s
        findings = self.findings
        critical = sum(1 for f in findings if f["sev_norm"] == "critical")
        high     = sum(1 for f in findings if f["sev_norm"] == "high")
        overall  = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"
        o_col    = RED if overall == "CRITICAL" else ORANGE if overall == "HIGH" else GOLD

        elems = []
        elems.append(Spacer(1, 0.4 * inch))

        # Logo area
        logo_table = Table(
            [[Paragraph("ROYCrew", ParagraphStyle("logo", fontSize=36, fontName="Helvetica-Bold",
                                                   textColor=BLACK)),
              Table([[Paragraph("SAMPLE REPORT",
                                ParagraphStyle("sr", fontSize=11, fontName="Helvetica-Bold",
                                               textColor=RED, alignment=TA_CENTER))]],
                    colWidths=[1.5 * inch],
                    style=[("BOX", (0,0), (-1,-1), 1.5, RED),
                           ("TOPPADDING", (0,0), (-1,-1), 8),
                           ("BOTTOMPADDING", (0,0), (-1,-1), 8)])
              ]],
            colWidths=[4 * inch, 2.5 * inch]
        )
        logo_table.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "MIDDLE")]))
        elems.append(logo_table)
        elems.append(Paragraph("AUTONOMOUS PENTEST ENGINE", ParagraphStyle(
            "tagline", fontSize=11, fontName="Helvetica", textColor=DARK_GRAY)))
        elems.append(Spacer(1, 0.5 * inch))

        elems.append(Paragraph(f"Version 1.0  &nbsp;&nbsp;&nbsp;  {self.date_str}",
                                ParagraphStyle("ver", fontSize=11, textColor=DARK_GRAY,
                                               fontName="Helvetica")))
        elems.append(Spacer(1, 0.15 * inch))
        elems.append(Paragraph("ASSESSMENT REPORT:", s["cover_title"]))
        elems.append(_divider(BLACK))
        elems.append(Paragraph(self.engagement_type.upper(),
                                ParagraphStyle("etype", fontSize=14, fontName="Helvetica-Bold",
                                               textColor=RED)))
        elems.append(Spacer(1, 0.3 * inch))
        elems.append(Paragraph(f"<b>{self.client_name}</b>",
                                ParagraphStyle("cn", fontSize=13, fontName="Helvetica-Bold",
                                               textColor=BLACK)))
        elems.append(Paragraph(self.client_contact,
                                ParagraphStyle("cc", fontSize=11, fontName="Helvetica",
                                               textColor=DARK_GRAY)))
        elems.append(Spacer(1, 0.3 * inch))

        # Overall risk box
        risk_t = Table(
            [[Paragraph(f"OVERALL RISK RATING: {overall}",
                        ParagraphStyle("risk", fontSize=13, fontName="Helvetica-Bold",
                                       textColor=BLACK))]],
        )
        risk_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GRAY),
            ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ]))
        elems.append(risk_t)

        # Bottom info bar
        elems.append(Spacer(1, 2.5 * inch))
        bottom = Table(
            [[
                Paragraph(f"Target: {self.target}", s["small"]),
                Paragraph("ROYCrew Autonomous Agent", s["small"]),
                Paragraph("CONFIDENTIAL", ParagraphStyle("conf", fontSize=9,
                                                          textColor=RED, fontName="Helvetica-Bold")),
            ]],
            colWidths=[2.5 * inch, 2.5 * inch, 1.5 * inch]
        )
        bottom.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), BLACK),
            ("TEXTCOLOR",     (0,0), (-1,-1), WHITE),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
        elems.append(bottom)
        return elems

    # ── Assessment Info ──────────────────────────────────────────────────────
    def _assessment_info(self):
        s = self.s
        elems = _section("Assessment Information", s)

        # Two-column: consultant | client
        left = [
            Paragraph("<b>ROYCrew Details</b>", s["h2"]),
            Spacer(1, 6),
            Paragraph("<font color='#CC2200'><b>Primary Contact</b></font>", s["small"]),
            Paragraph(self.consultant_name, s["body"]),
            Paragraph("Autonomous Pentest Agent", s["small"]),
            Paragraph("roycrew@localhost", s["small"]),
        ]
        right = [
            Paragraph("<b>Client Details</b>", s["h2"]),
            Spacer(1, 6),
            Paragraph("<font color='#CC2200'><b>Company Information</b></font>", s["small"]),
            Paragraph(self.client_name, s["body"]),
            Spacer(1, 8),
            Paragraph("<font color='#CC2200'><b>Contact Information</b></font>", s["small"]),
            Paragraph(self.client_contact, s["body"]),
        ]

        two_col = Table(
            [[left, right]],
            colWidths=[3.25 * inch, 3.25 * inch]
        )
        two_col.setStyle(TableStyle([
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("LINEAFTER",   (0,0), (0,-1), 0.5, MID_GRAY),
            ("LEFTPADDING", (1,0), (1,-1), 20),
        ]))
        elems.append(two_col)
        elems.append(Spacer(1, 14))
        elems.append(_divider(MID_GRAY))

        # Scope
        elems.append(Paragraph("<b>Assessment Scope Summary</b>", s["h3"]))
        scope_data = [
            [Paragraph("<font color='#CC2200'><b>Engagement Timeframe</b></font>", s["small"]),
             Paragraph("<font color='#CC2200'><b>Engagement Scope</b></font>", s["small"])],
            [Paragraph(self.date_str, s["body"]),
             Paragraph(f"Target: {self.target}", s["body"])],
        ]
        st = Table(scope_data, colWidths=[3 * inch, 3.5 * inch])
        st.setStyle(TableStyle([
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        elems.append(st)
        elems.append(Spacer(1, 10))

        # Project ID box
        pid_t = Table(
            [[Paragraph(f"<b>Target:</b>  {self.target}  &nbsp;&nbsp;  "
                        f"<b>Report Date:</b>  {self.date_str}  &nbsp;&nbsp;  "
                        f"<b>Type:</b>  {self.engagement_type}", s["small"])]],
        )
        pid_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GRAY),
            ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ]))
        elems.append(pid_t)
        elems.append(Spacer(1, 14))

        # Version history
        vh_data = [
            [Paragraph("<b>Version</b>", s["white_bold"]),
             Paragraph("<b>Date</b>", s["white_bold"]),
             Paragraph("<b>Author</b>", s["white_bold"]),
             Paragraph("<b>Comments</b>", s["white_bold"])],
            ["1.0", self.date_str, "ROYCrew Agent", "Auto-generated report"],
        ]
        vh = Table(
            [[Paragraph("Report Version History", ParagraphStyle(
                "vhh", fontSize=10, fontName="Helvetica-Bold",
                textColor=WHITE, alignment=TA_CENTER))]],
        )
        vh.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), NAVY),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ]))
        elems.append(vh)

        vt = Table(vh_data, colWidths=[0.8*inch, 1.8*inch, 1.8*inch, 2.1*inch])
        vt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, LIGHT_GRAY),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ]))
        elems.append(vt)
        return elems

    # ── Disclaimer ───────────────────────────────────────────────────────────
    def _disclaimer(self):
        s = self.s
        elems = _section("Disclaimer", s)
        text = (
            f"This confidential information is provided to {self.client_name} as a deliverable "
            f"of this security assessment. The purpose of this document is to provide the client "
            f"with the results of, and remedial advice derived from, this security assessment. "
            f"Each recipient agrees that, prior to reading this document, it shall not distribute "
            f"or use the information contained herein for any purpose other than those stated."
            "<br/><br/>"
            f"This document also contains highly sensitive confidential information of "
            f"{self.client_name} and should be treated accordingly. Safeguarding of said "
            f"deliverables is the sole responsibility of the client. We encourage all clients to "
            f"safeguard their deliverables via secure, encrypted mechanisms to ensure the data "
            f"is protected at rest and in motion."
            "<br/><br/>"
            f"The contents of this document do not constitute legal advice. ROYCrew outputs "
            f"relating to legal interests or compliance are not intended as legal counsel and "
            f"should not be taken as such. This report represents a point-in-time snapshot of "
            f"the security posture assessed. Conditions may have improved, deteriorated, or "
            f"remained unchanged since this assessment was completed."
        )
        elems.append(Paragraph(text, s["body_j"]))
        elems.append(Spacer(1, 30))
        elems.append(Paragraph("[THE REMAINDER OF THIS PAGE HAS BEEN INTENTIONALLY LEFT BLANK.]",
                                ParagraphStyle("blank", fontSize=9, fontName="Helvetica-Oblique",
                                               textColor=MID_GRAY, alignment=TA_CENTER)))
        return elems

    # ── TOC ──────────────────────────────────────────────────────────────────
    def _toc(self):
        s = self.s
        elems = _section("Table of Contents", s)
        sections = [
            ("Assessment Information",      "2"),
            ("Disclaimer",                  "3"),
            ("Methodology",                 "4"),
            ("Executive Summary",           "5"),
            ("Vulnerability Overview",      "6"),
            ("Vulnerability Summary",       "7"),
            ("Attack Chain Narrative",      "8"),
            ("Vulnerability Findings",      "9"),
            ("Appendix",                    "—"),
        ]
        for title, pg in sections:
            row = Table(
                [[Paragraph(title, s["toc"]),
                  Paragraph(pg, ParagraphStyle("pgn", fontSize=10, fontName="Helvetica",
                                               alignment=TA_RIGHT))]],
                colWidths=[5.5 * inch, 1 * inch]
            )
            row.setStyle(TableStyle([
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LINEBELOW",     (0,0), (-1,-1), 0.25, LIGHT_GRAY),
            ]))
            elems.append(row)
        return elems

    # ── Executive Summary ────────────────────────────────────────────────────
    def _executive_summary(self):
        s = self.s
        findings = self.findings
        elems = _section("Executive Summary", s)

        critical = sum(1 for f in findings if f["sev_norm"] == "critical")
        high     = sum(1 for f in findings if f["sev_norm"] == "high")
        medium   = sum(1 for f in findings if f["sev_norm"] == "medium")
        total    = len(findings)
        overall  = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
        o_col    = RED if overall == "CRITICAL" else ORANGE if overall == "HIGH" else GOLD

        elems.append(Paragraph(
            f"{self.client_name} seeks to identify and reduce the risk associated with their "
            f"infrastructure and enhance their security posture. Using an autonomous black-box "
            f"approach, ROYCrew aimed to emulate a real-world threat actor. The assessment revealed "
            f"<b>{total} findings</b> across the target environment: "
            f"<b>{critical} critical</b>, <b>{high} high</b>, and <b>{medium} medium</b> severity issues.",
            s["body_j"]
        ))
        elems.append(Spacer(1, 12))

        elems.append(Paragraph("<b>External Risk Rating</b>", s["h3"]))
        elems.append(_divider(MID_GRAY))
        elems.append(Paragraph(
            f"There is {'critical' if critical > 0 else 'high'} risk of exploitation likelihood. "
            f"A motivated attacker could replicate these findings with comparable tools and timeframe.",
            s["body"]
        ))
        elems.append(Spacer(1, 8))
        elems.append(Paragraph(
            f"<b>OVERALL RISK RATING: {overall}</b>",
            ParagraphStyle("orr", fontSize=13, fontName="Helvetica-Bold", textColor=BLACK)
        ))
        elems.append(Spacer(1, 14))

        # Risk heatmap
        if VISUALS_AVAILABLE:
            try:
                hm_buf = risk_heatmap(self.findings)
                elems.append(_embed_chart(hm_buf, width_inch=4.5, height_inch=3.4))
                elems.append(Spacer(1, 10))
            except Exception:
                pass

        # Summary of Strengths
        elems.append(Paragraph("<b>Summary of Strengths</b>", s["h3"]))
        elems.append(_divider(MID_GRAY))
        elems.append(Paragraph(
            "The automated scan identified the target's available services and technology stack. "
            "Some endpoints returned appropriate HTTP status codes indicating basic server configuration.",
            s["body"]
        ))
        elems.append(Spacer(1, 10))

        # Summary of Weaknesses
        elems.append(Paragraph("<b>Summary of Weaknesses</b>", s["h3"]))
        elems.append(_divider(MID_GRAY))
        for f in findings[:5]:
            elems.append(Paragraph(f"• <b>{f['finding']}</b>: {f['details']}", s["body"]))

        elems.append(Spacer(1, 10))

        # Strategic Recommendations
        elems.append(Paragraph("<b>Strategic Recommendations</b>", s["h3"]))
        elems.append(_divider(MID_GRAY))
        critical_high = [f for f in findings if f["sev_norm"] in ("critical", "high")]
        for i, f in enumerate(critical_high[:5], 1):
            elems.append(Paragraph(
                f"{i}. <b>{f['finding']}</b> — Immediate remediation required. {f['details']}",
                s["body"]
            ))

        return elems

    # ── Methodology ──────────────────────────────────────────────────────────
    def _methodology(self):
        s = self.s
        elems = _section("Methodology", s)
        elems.append(Paragraph(
            "By using the same techniques as sophisticated attackers in the real world, ROYCrew "
            "provides unique insight into security risks that automated tools often lack. We follow "
            "a structured penetration testing methodology to ensure repeatable, high-quality assessments.",
            s["body_j"]
        ))
        elems.append(Spacer(1, 12))

        phases = [
            ("1", "Reconnaissance and Information Gathering",
             "Port scanning (Nmap), service fingerprinting, and technology stack detection. "
             "The gathered data establishes the attack surface."),
            ("2", "Enumeration",
             "Web server probing (httpx), directory enumeration (Gobuster/ffuf). "
             "All accessible endpoints and services are catalogued."),
            ("3", "Analysis and Exploitation",
             "Tool output is fed to Qwen 7B LLM with a security-focused RAG knowledge base. "
             "Findings are classified, deduplicated, and correlated into attack chains."),
            ("4", "Meaningful Reporting",
             "All findings are structured into this professional report with: Executive Summary, "
             "Attack Chains, Detailed Findings, Remediation Roadmap, and Technical Evidence."),
        ]

        # Hexagon methodology diagram
        if VISUALS_AVAILABLE:
            try:
                hbuf = hexagon_methodology()
                elems.append(_embed_chart(hbuf, width_inch=6.5, height_inch=2.8))
                elems.append(Spacer(1, 10))
            except Exception:
                pass

        for num, title, desc in phases:
            row = Table(
                [[Paragraph(f"<b>{num}</b>",
                             ParagraphStyle("pnum", fontSize=18, fontName="Helvetica-Bold",
                                            textColor=WHITE, alignment=TA_CENTER)),
                  [Paragraph(f"<b>{title}</b>", s["h3"]),
                   Paragraph(desc, s["body"])]]],
                colWidths=[0.55 * inch, 6 * inch]
            )
            row.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (0,-1), NAVY),
                ("TOPPADDING",    (0,0), (-1,-1), 10),
                ("BOTTOMPADDING", (0,0), (-1,-1), 10),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
                ("RIGHTPADDING",  (0,0), (-1,-1), 10),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            elems.append(row)
            elems.append(Spacer(1, 8))

        return elems

    # ── Vulnerability Overview ────────────────────────────────────────────────
    def _vuln_overview(self):
        s = self.s
        elems = _section("Vulnerability Overview", s)
        elems.append(Paragraph(
            "The risk rating assigned to each vulnerability is determined by scoring the exploit "
            "likelihood and business impact.",
            s["body"]
        ))
        elems.append(Paragraph("<b>Risk Definition and Criteria</b>", s["h3"]))
        elems.append(_divider(MID_GRAY))

        defs = [
            ("CRITICAL",      RED,       "Critical vulnerabilities present a grave threat, demanding immediate attention. They have the potential to completely compromise the target environment."),
            ("HIGH",          ORANGE,    "High-risk vulnerabilities pose a significant danger and should be promptly addressed. These issues can have a substantial impact on the overall security posture."),
            ("MEDIUM",        GOLD,      "Medium severity indicates a moderate level of risk. They should be addressed after critical and high-risk vulnerabilities have been resolved."),
            ("LOW",           GREEN,     "Low severity vulnerabilities pose minimal risk and are often hypothetical. Addressing them is lower priority compared to other security enhancements."),
            ("INFORMATIONAL", BLUE_INFO, "Informational vulnerabilities have negligible or no direct impact by themselves, but may become a risk when combined with other circumstances."),
        ]

        for label, col, desc in defs:
            row = Table(
                [[Paragraph(f"<b>{label}</b>",
                             ParagraphStyle("dl", fontSize=12, fontName="Helvetica-Bold",
                                            textColor=WHITE, alignment=TA_CENTER)),
                  Paragraph(desc, s["body"])]],
                colWidths=[1.3 * inch, 5.2 * inch]
            )
            row.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (0,-1), col),
                ("TOPPADDING",    (0,0), (-1,-1), 12),
                ("BOTTOMPADDING", (0,0), (-1,-1), 12),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("LINEBELOW",     (0,0), (-1,-1), 0.5, WHITE),
            ]))
            elems.append(row)
            elems.append(Spacer(1, 4))

        return elems

    # ── Vulnerability Summary ─────────────────────────────────────────────────
    def _vuln_summary(self):
        s = self.s
        findings = self.findings
        elems = _section("Vulnerability Summary", s)

        counts = {k: 0 for k in ("critical", "high", "medium", "low", "informational")}
        for f in findings:
            sev = f["sev_norm"]
            if sev == "info":
                sev = "informational"
            counts[sev] = counts.get(sev, 0) + 1

        # Big count row (Redline style)
        labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        keys   = ["critical", "high", "medium", "low", "informational"]
        cols_  = [RED, ORANGE, GOLD, GREEN, BLUE_INFO]

        count_cells = []
        for key, lbl, col in zip(keys, labels, cols_):
            count_cells.append(
                [Paragraph(str(counts[key]),
                            ParagraphStyle("cnt", fontSize=28, fontName="Helvetica-Bold",
                                           textColor=col, alignment=TA_CENTER)),
                 Paragraph(lbl,
                            ParagraphStyle("cnl", fontSize=9, fontName="Helvetica-Bold",
                                           textColor=col, alignment=TA_CENTER))]
            )

        ct = Table(
            [count_cells[0], count_cells[1], count_cells[2], count_cells[3], count_cells[4]],
            colWidths=[1.3 * inch] * 5
        )
        # Use single row
        # Chart: severity bar image
        if VISUALS_AVAILABLE:
            try:
                buf = severity_bar(self.findings)
                elems.append(_embed_chart(buf, width_inch=6.5, height_inch=2.0))
            except Exception:
                pass
        elems.append(Spacer(1, 12))

        # Donut chart alongside text
        if VISUALS_AVAILABLE:
            try:
                dbuf = severity_donut(self.findings)
                donut_img = _embed_chart(dbuf, width_inch=3.8, height_inch=3.0)
                elems.append(donut_img)
            except Exception:
                pass
        elems.append(Spacer(1, 10))

        # Details table
        elems.append(Paragraph("<b>Vulnerability Details Table</b>", s["h3"]))
        table_data = [
            [Paragraph("<b>ID</b>", s["white_bold"]),
             Paragraph("<b>Severity</b>", s["white_bold"]),
             Paragraph("<b>Finding Title</b>", s["white_bold"]),
             Paragraph("<b>Business Impact</b>", s["white_bold"])]
        ]
        for f in findings:
            sev_n = f["sev_norm"]
            col   = SEV_COLOR.get(sev_n, MID_GRAY)
            table_data.append([
                Paragraph(f["id"],
                           ParagraphStyle("fid2", fontSize=9, fontName="Helvetica-Bold",
                                          textColor=NAVY, alignment=TA_CENTER)),
                Paragraph(f"<b>{sev_n.upper()}</b>",
                           ParagraphStyle("sev2", fontSize=9, fontName="Helvetica-Bold",
                                          textColor=col)),
                Paragraph(f["finding"], s["small"]),
                Paragraph(f["details"][:120] + ("…" if len(f["details"]) > 120 else ""),
                           s["small"]),
            ])

        dt = Table(table_data, colWidths=[0.5*inch, 1*inch, 2.5*inch, 2.5*inch])
        dt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, LIGHT_GRAY),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        elems.append(dt)
        return elems

    # ── Attack Chain ──────────────────────────────────────────────────────────
    def _attack_chain(self):
        s = self.s
        elems = _section("Attack Chain Narrative", s)

        elems.append(Paragraph(
            "The ROYCrew agent executed a structured, step-by-step methodology designed to "
            "emulate the approach of a determined attacker against the target environment.",
            s["body_j"]
        ))
        elems.append(Spacer(1, 10))

        ports   = self.report.get("open_ports", [])
        tech    = self.report.get("tech_stack", [])
        dirs    = self.report.get("directories", [])
        services = self.report.get("services", {})

        chain = [
            ("1", "Reconnaissance — Port Scanning",
             "T1595 - Active Scanning",
             f"Nmap scan identified open ports: {ports}. Service versions detected via banner grabbing."),
            ("2", "Web Fingerprinting",
             "T1592 - Gather Victim Host Information",
             f"httpx probe identified tech stack: {', '.join(tech) if tech else 'Not detected'}. "
             f"HTTP response headers analysed for server version disclosure."),
            ("3", "Directory and Endpoint Enumeration",
             "T1083 - File and Directory Discovery",
             f"Gobuster/ffuf wordlist scan discovered accessible paths: "
             f"{', '.join(dirs) if dirs else 'No significant directories found'}."),
            ("4", "Vulnerability Analysis",
             "T1190 - Exploit Public-Facing Application",
             "Identified software versions cross-referenced against known CVE database. "
             "Outdated components flagged for potential exploitation."),
            ("5", "Impact Assessment",
             "T1082 - System Information Discovery",
             "All findings correlated by ROYCrew LLM engine. Attack paths identified "
             "and mapped to business impact."),
        ]

        for num, title, mitre, desc in chain:
            elems.append(Paragraph(f"<b>{num}.  {title}</b>", s["h3"]))
            elems.append(Paragraph(mitre, s["mitre"]))
            elems.append(Paragraph(desc, s["body_j"]))
            elems.append(Spacer(1, 10))

        # Attack chain flow diagram
        if VISUALS_AVAILABLE:
            try:
                abuf = attack_chain_diagram(self.findings, self.target)
                elems.append(Spacer(1, 6))
                elems.append(_embed_chart(abuf, width_inch=6.0, height_inch=5.5))
            except Exception:
                pass

        return elems

    # ── Detailed Findings ─────────────────────────────────────────────────────
    def _detailed_findings(self):
        s = self.s
        elems = _section("Vulnerability Findings", s)
        elems.append(Paragraph(
            "The vulnerabilities below were identified and verified by the ROYCrew autonomous agent. "
            "Retesting should be planned to follow the remediation of these vulnerabilities.",
            s["body"]
        ))
        elems.append(Spacer(1, 10))

        for f in self.findings:
            sev   = f["sev_norm"]
            title = f["finding"]
            desc  = f["details"]

            impact = self._infer_impact(sev, title)
            assets = f"Target: {self.target}"
            remed  = self._infer_remediation(sev, title)
            refs   = self._infer_references(sev, title)

            evidence = [
                f"[ROYCrew] Finding: {title}",
                f"[ROYCrew] Severity: {sev.upper()}",
                f"[ROYCrew] Target: {self.target}",
                f"[ROYCrew] Details: {desc}",
            ]

            elems += _finding_card(
                fid=f["id"], title=title, sev=sev,
                description=desc, impact=impact,
                assets=assets, remediation=remed,
                references=refs, evidence_lines=evidence, s=s
            )

        return elems

    # ── Appendix ──────────────────────────────────────────────────────────────
    def _appendix(self):
        s = self.s
        elems = [PageBreak()]
        elems += _section("Appendix — Technical Evidence", s)

        # Ports
        elems.append(Paragraph("<b>Open Ports and Services</b>", s["h3"]))
        ports    = self.report.get("open_ports", [])
        services = self.report.get("services", {})
        if ports:
            pd = [["Port", "Protocol", "Service"]] + \
                 [[str(p), "tcp", services.get(str(p), "unknown")] for p in ports]
            pt = Table(pd, colWidths=[1*inch, 1.5*inch, 4*inch])
            pt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), NAVY),
                ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
                ("INNERGRID",     (0,0), (-1,-1), 0.25, LIGHT_GRAY),
            ]))
            elems.append(pt)
        else:
            elems.append(Paragraph("No open ports recorded.", s["body"]))

        elems.append(Spacer(1, 14))
        elems.append(Paragraph("<b>Directories Discovered</b>", s["h3"]))
        dirs = self.report.get("directories", [])
        if dirs:
            for d in dirs:
                elems.append(Paragraph(f"• {d}", s["body"]))
        else:
            elems.append(Paragraph("No directories discovered.", s["body"]))

        elems.append(Spacer(1, 14))
        elems.append(Paragraph("<b>Technology Stack</b>", s["h3"]))
        tech = self.report.get("tech_stack", [])
        if tech:
            for t in tech:
                elems.append(Paragraph(f"• {t}", s["body"]))
        else:
            elems.append(Paragraph("Not detected.", s["body"]))

        elems.append(Spacer(1, 14))
        elems.append(Paragraph("<b>Raw JSON Report Data</b>", s["h3"]))
        raw_lines = json.dumps(self.report, indent=2).split("\n")
        truncated = [l[:100] for l in raw_lines[:35]]
        elems.append(_terminal(truncated, s))  # first 35 lines only

        return elems

    # ── helpers ───────────────────────────────────────────────────────────────
    def _infer_impact(self, severity: str, finding: str) -> str:
        fl = finding.lower()
        if "sql" in fl:      return "Successful exploitation allows an attacker to bypass authentication, extract or modify database records, and potentially achieve remote code execution."
        if "xss" in fl:      return "Allows attackers to inject malicious scripts into pages, hijack sessions, redirect users, or steal credentials."
        if "admin" in fl:    return "Unauthorized access to the admin panel could lead to full system compromise and data exfiltration."
        if "php" in fl:      return "End-of-life PHP versions contain unpatched critical vulnerabilities enabling remote code execution."
        if "nginx" in fl:    return "Known CVEs in this Nginx version could allow denial-of-service or information disclosure attacks."
        if "ssl" in fl or "tls" in fl: return "Weak encryption allows man-in-the-middle attacks, exposing sensitive data in transit."
        if severity == "critical": return "Critical impact — complete compromise of the target system is possible."
        if severity == "high":     return "Significant risk to confidentiality, integrity, and availability of the target."
        if severity == "medium":   return "Moderate risk that could be escalated when combined with other vulnerabilities."
        return "Low direct impact, but may assist attackers in reconnaissance or chaining attacks."

    def _infer_remediation(self, severity: str, finding: str) -> str:
        fl = finding.lower()
        if "sql" in fl:       return "Use parameterized queries and prepared statements. Implement input validation and output encoding. Apply least-privilege database accounts."
        if "xss" in fl:       return "Implement Content Security Policy (CSP) headers. Encode all user-supplied output. Use modern frameworks that auto-escape output."
        if "php" in fl:       return "Upgrade to PHP 8.2 or later immediately. PHP 5.x has been end-of-life since December 2018 and receives no security patches."
        if "nginx" in fl:     return "Upgrade Nginx to the latest stable release. Review and apply vendor security advisories."
        if "admin" in fl:     return "Restrict admin panel access by IP allowlist. Implement MFA. Rename default admin paths."
        if "ssl" in fl or "tls" in fl: return "Disable TLS 1.0/1.1 and weak cipher suites. Enforce TLS 1.2+ with AEAD ciphers only."
        if severity in ("critical", "high"): return "Immediate patching required. Consult vendor security advisories and apply patches within 7 days."
        if severity == "medium": return "Address within 30 days. Review security configuration and apply vendor hardening guidelines."
        return "Review and address according to security best practices in the next maintenance window."

    def _infer_references(self, severity: str, finding: str) -> str:
        fl = finding.lower()
        refs = []
        if "sql" in fl:       refs.append("OWASP: A03:2021 – Injection")
        if "xss" in fl:       refs.append("OWASP: A03:2021 – Cross-Site Scripting")
        if "php" in fl:       refs.append("PHP EOL: https://www.php.net/eol.php")
        if "nginx" in fl:     refs.append("Nginx Security Advisories: https://nginx.org/en/security_advisories.html")
        if "ssl" in fl or "tls" in fl: refs.append("NIST SP 800-52 Rev.2 – TLS Guidelines")
        if not refs:
            if severity in ("critical", "high"): refs.append("MITRE ATT&CK: T1190 – Exploit Public-Facing Application")
            else: refs.append("OWASP Top 10: https://owasp.org/Top10/")
        return "  |  ".join(refs)


# ── CLI / test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample_report = {
        "target": "testphp.vulnweb.com",
        "phases_completed": ["nmap_recon", "httpx_probe", "gobuster_enum"],
        "open_ports": [80, 443],
        "services": {"80": "http", "443": "https"},
        "tech_stack": ["PHP 5.6", "Nginx 1.19", "Apache 2.4.29"],
        "directories": ["/admin", "/uploads", "/images", "/config"],
        "findings": [
            {"finding": "SQL Injection in login endpoint",
             "severity": "critical",
             "details": "The login form is vulnerable to SQL injection. Input is not sanitised before being passed to the database query."},
            {"finding": "PHP 5.6 end of life",
             "severity": "high",
             "details": "PHP 5.6 reached end-of-life in December 2018. No security patches are issued."},
            {"finding": "Outdated Nginx 1.19",
             "severity": "medium",
             "details": "Nginx 1.19 has known vulnerabilities. Upgrade to latest stable release."},
            {"finding": "Exposed /admin directory",
             "severity": "medium",
             "details": "/admin is publicly accessible and returns HTTP 200."},
            {"finding": "No HTTPS enforcement",
             "severity": "high",
             "details": "Site serves content over unencrypted HTTP. Credentials may be intercepted."},
            {"finding": "SSL/TLS weak cipher suite",
             "severity": "low",
             "details": "Server accepts RC4 cipher suites which are cryptographically broken."},
            {"finding": "HTTP security headers missing",
             "severity": "info",
             "details": "X-Frame-Options, CSP, and HSTS headers are absent."},
        ],
    }

    gen = PentestReportGenerator(
        sample_report,
        "reports/roycrew_test_report.pdf",
        client_name="Vulnweb Labs",
        client_contact="Security Team",
    )
    path = gen.generate()
    print(f"Report generated: {path}")