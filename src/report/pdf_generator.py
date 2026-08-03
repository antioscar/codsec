from __future__ import annotations
from datetime import datetime
import textwrap

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable

from src.models import ScanReport, Finding, Severity

SEVERITY_COLORS: dict[Severity, HexColor] = {
    Severity.CRITICAL: HexColor("#DC143C"),
    Severity.HIGH: HexColor("#FF4500"),
    Severity.MEDIUM: HexColor("#FFA500"),
    Severity.LOW: HexColor("#228B22"),
}

SEVERITY_BG: dict[Severity, HexColor] = {
    Severity.CRITICAL: HexColor("#FDE8E8"),
    Severity.HIGH: HexColor("#FFF3E0"),
    Severity.MEDIUM: HexColor("#FFF8E1"),
    Severity.LOW: HexColor("#E8F5E9"),
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=32,
        alignment=TA_CENTER,
        textColor=HexColor("#1a237e"),
        spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        fontName="Helvetica",
        fontSize=13,
        leading=18,
        alignment=TA_CENTER,
        textColor=HexColor("#455a64"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=HexColor("#1a237e"),
        spaceBefore=18,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=HexColor("#212121"),
        spaceBefore=8,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="CodeBlock",
        fontName="Courier",
        fontSize=8,
        leading=10,
        backColor=HexColor("#f5f5f5"),
        borderPadding=6,
        spaceAfter=6,
        spaceBefore=4,
    ))
    styles.add(ParagraphStyle(
        name="MetaText",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=HexColor("#616161"),
    ))
    return styles


def _build_cover(doc: SimpleDocTemplate, report: ScanReport, styles):
    elements = []
    critical = len(report.by_severity[Severity.CRITICAL])
    high = len(report.by_severity[Severity.HIGH])
    medium = len(report.by_severity[Severity.MEDIUM])
    low = len(report.by_severity[Severity.LOW])

    elements.append(Spacer(1, 60))
    elements.append(Paragraph("Informe de Análisis de Seguridad", styles["CoverTitle"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Análisis estático de código fuente", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="60%", thickness=1, color=HexColor("#cfd8dc")))
    elements.append(Spacer(1, 20))

    info_data = [
        ["Proyecto:", report.target_path],
        ["Fecha:", datetime.now().strftime("%d/%m/%Y %H:%M")],
        ["Archivos analizados:", str(report.total_files_scanned)],
        ["Total de hallazgos:", str(report.total_findings)],
        ["Duración del escaneo:", f"{report.scan_duration_seconds:.1f} segundos"],
    ]
    info_table = Table(info_data, colWidths=[100, 300])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#37474f")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 30))

    sev_data = [
        [Paragraph("<b>Severidad</b>", styles["MetaText"]),
         Paragraph("<b>Cantidad</b>", styles["MetaText"])],
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = len(report.by_severity[sev])
        sev_data.append([
            Paragraph(f'<font color="{SEVERITY_COLORS[sev]}">■</font> {str(sev)}', styles["MetaText"]),
            Paragraph(str(count), styles["MetaText"]),
        ])

    sev_table = Table(sev_data, colWidths=[140, 80])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#eceff1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#37474f")),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cfd8dc")),
    ]))
    elements.append(sev_table)

    elements.append(PageBreak())
    return elements


def _finding_to_elements(finding: Finding, idx: int, styles, available_width: float) -> list:
    color = SEVERITY_COLORS[finding.severity]
    bg = SEVERITY_BG[finding.severity]

    sev_info = f"{idx}. [{str(finding.severity).upper()}] {finding.category.replace('_', ' ').title()} — <font color='{color}'>{finding.cwe}</font>"

    location = f"<b>Archivo:</b> {finding.file_path}:{finding.line_number}"
    confidence_label = {"high": "Alta", "medium": "Media", "low": "Baja"}.get(finding.confidence, finding.confidence)
    meta = [
        Paragraph(location, styles["MetaText"]),
        Spacer(1, 2),
        Paragraph(f"<b>Confianza:</b> {confidence_label}  |  <b>Lenguaje:</b> {finding.language}", styles["MetaText"]),
    ]

    desc = finding.description
    desc_para = Paragraph(f"<b>Descripción:</b> {desc}", styles["MetaText"])

    code_text = finding.code_snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(code_text) > 600:
        code_text = code_text[:600] + "\n..."
    code_block = Paragraph(
        f"<pre>{code_text}</pre>",
        styles["CodeBlock"],
    )

    rem_text = finding.remediation.split("\n")
    rem_items = "".join(f"<li>{line.strip().lstrip('0123456789. ')}</li>" for line in rem_text if line.strip())
    remediation = Paragraph(
        f"<b>Remediación:</b><br/><ul>{rem_items}</ul>",
        styles["MetaText"],
    )

    table_data = [
        [sev_info],
    ]
    td = Table(table_data, colWidths=[available_width])
    td.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (-1, -1), color),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))

    elements = [td]
    elements.extend(meta)
    elements.append(Spacer(1, 4))
    elements.append(desc_para)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph("<b>Código:</b>", styles["MetaText"]))
    elements.append(code_block)
    elements.append(Spacer(1, 4))
    elements.append(remediation)
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#eceff1")))

    return elements


def _build_body(doc: SimpleDocTemplate, report: ScanReport, styles):
    elements = []

    sorted_findings = sorted(report.findings, key=lambda f: (f.severity.order, f.category, f.file_path))

    elements.append(Paragraph("Hallazgos de Seguridad", styles["SectionTitle"]))
    elements.append(Spacer(1, 8))

    if not sorted_findings:
        elements.append(Paragraph("No se encontraron fallas de seguridad en el código analizado.", styles["Normal"]))
    else:
        for idx, finding in enumerate(sorted_findings, 1):
            finding_elems = _finding_to_elements(finding, idx, styles, doc.width)
            elements.extend(finding_elems)

    return elements


def generate_pdf_report(report: ScanReport, output_path: str) -> None:
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="Informe de Análisis de Seguridad",
        author="Analizador de Código",
    )

    styles = _build_styles()

    cover_elements = _build_cover(doc, report, styles)
    body_elements = _build_body(doc, report, styles)

    elements = cover_elements + body_elements
    doc.build(elements)
