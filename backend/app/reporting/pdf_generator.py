from io import BytesIO
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from typing import Dict, Any, List

def generate_pdf_report(incident: Dict[str, Any], alerts: List[Dict[str, Any]], comments: List[Dict[str, Any]]) -> BytesIO:
    buffer = BytesIO()
    
    # 1. Page Setup & Document Template
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        rightMargin=36, 
        leftMargin=36, 
        topMargin=36, 
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom colors
    PRIMARY_COLOR = colors.HexColor("#0f172a") # Navy/Slate dark
    SECONDARY_COLOR = colors.HexColor("#3b82f6") # Blue
    TEXT_COLOR = colors.HexColor("#1e293b")
    MUTED_TEXT = colors.HexColor("#64748b")
    
    # Color mapping for severity
    SEV_COLORS = {
        "Low": colors.HexColor("#3b82f6"),     # Blue
        "Medium": colors.HexColor("#eab308"),  # Yellow
        "High": colors.HexColor("#f97316"),    # Orange
        "Critical": colors.HexColor("#ef4444")  # Red
    }
    
    sev = incident.get("severity", "Low")
    sev_color = SEV_COLORS.get(sev, colors.HexColor("#64748b"))
    
    # Styles Setup
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.white,
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'Heading1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=PRIMARY_COLOR,
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=SECONDARY_COLOR,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=TEXT_COLOR,
        leading=14,
        spaceAfter=8
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=PRIMARY_COLOR
    )
    
    meta_val_style = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=TEXT_COLOR
    )
    
    story = []
    
    # Header Banner (using Table)
    banner_data = [
        [
            Paragraph("AI SECURITY INCIDENT REPORT", title_style), 
            Paragraph(f"RISK: {incident.get('risk_score', 0)}/100<br/>SEVERITY: {sev.upper()}", ParagraphStyle(
                'BannerStats', 
                parent=title_style, 
                fontSize=12, 
                alignment=2 # Right align
            ))
        ]
    ]
    banner_table = Table(banner_data, colWidths=[380, 160])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PRIMARY_COLOR),
        ('PADDING', (0,0), (-1,-1), 12),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('TOPPADDING', (0,0), (-1,-1), 16),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 15))
    
    # Title Section
    story.append(Paragraph(f"Incident #{incident.get('id', 0)}: {incident.get('title')}", ParagraphStyle(
        'IncTitle', 
        parent=styles['Normal'], 
        fontName='Helvetica-Bold', 
        fontSize=16, 
        textColor=PRIMARY_COLOR,
        spaceAfter=15
    )))
    
    # 2. Executive Summary Table
    story.append(Paragraph("Executive Summary", h1_style))
    created_at_str = incident.get("created_at")
    if isinstance(created_at_str, datetime.datetime):
        created_at_str = created_at_str.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        created_at_str = str(created_at_str)
        
    summary_data = [
        [Paragraph("Incident ID:", meta_label_style), Paragraph(str(incident.get("id")), meta_val_style),
         Paragraph("Created At:", meta_label_style), Paragraph(created_at_str, meta_val_style)],
        
        [Paragraph("Affected Host:", meta_label_style), Paragraph(incident.get("host_affected") or "N/A", meta_val_style),
         Paragraph("Affected User:", meta_label_style), Paragraph(incident.get("user_affected") or "N/A", meta_val_style)],
        
        [Paragraph("Status:", meta_label_style), Paragraph(incident.get("status"), meta_val_style),
         Paragraph("Assigned Analyst:", meta_label_style), Paragraph(incident.get("assigned_analyst") or "Unassigned", meta_val_style)],
    ]
    summary_table = Table(summary_data, colWidths=[100, 170, 100, 170])
    summary_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#f8fafc")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # 3. Description & AI Investigation Summary
    story.append(Paragraph("AI-Generated Investigation Details", h1_style))
    ai_summary_raw = incident.get("ai_summary") or "No AI summary has been generated for this incident."
    
    # Convert simple markdown headers/bullet points to HTML-like formats for reportlab
    formatted_summary = ai_summary_raw.replace("\n", "<br/>").replace("### ", "<b>").replace("## ", "<b>").replace("**", "<b>").replace("</b> ", "</b>")
    # Clean tags mismatch
    for term in ["What Happened", "Why it is suspicious", "Attacker Objective", "Investigation Next Steps"]:
        formatted_summary = formatted_summary.replace(f"<b>{term}", f"<br/><b>{term}</b>")
        
    story.append(Paragraph(formatted_summary, body_style))
    story.append(Spacer(1, 15))
    
    # 4. Containment Playbook
    story.append(Paragraph("AI-Recommended Remediation Playbook", h1_style))
    ai_playbook_raw = incident.get("ai_playbook") or "No playbook generated."
    formatted_playbook = ai_playbook_raw.replace("\n", "<br/>").replace("### ", "<b>").replace("## ", "<b>").replace("**", "<b>")
    
    story.append(Paragraph(formatted_playbook, body_style))
    story.append(Spacer(1, 15))
    
    # 5. Attack Timeline (Correlated Alerts)
    story.append(Paragraph("Attack Timeline & Correlated Events", h1_style))
    
    timeline_data = [
        [
            Paragraph("Timestamp", meta_label_style), 
            Paragraph("Triggered Detection Rule", meta_label_style), 
            Paragraph("Source", meta_label_style), 
            Paragraph("Severity", meta_label_style)
        ]
    ]
    
    for alert in sorted(alerts, key=lambda a: a.get('timestamp') or datetime.datetime.min):
        t_stamp = alert.get('timestamp')
        if isinstance(t_stamp, datetime.datetime):
            t_stamp = t_stamp.strftime("%H:%M:%S")
        else:
            t_stamp = str(t_stamp)
            
        timeline_data.append([
            Paragraph(t_stamp, meta_val_style),
            Paragraph(alert.get('rule_name'), meta_val_style),
            Paragraph(alert.get('log_source') or "sysmon", meta_val_style),
            Paragraph(alert.get('severity'), ParagraphStyle('SevCol', parent=meta_val_style, fontName='Helvetica-Bold', textColor=SEV_COLORS.get(alert.get('severity'), TEXT_COLOR)))
        ])
        
    timeline_table = Table(timeline_data, colWidths=[90, 240, 110, 100])
    timeline_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 15))
    
    # 6. Comments Timeline (if any exist)
    if comments:
        story.append(Paragraph("Analyst Investigation Notes", h1_style))
        for comment in comments:
            c_time = comment.get('created_at')
            if isinstance(c_time, datetime.datetime):
                c_time = c_time.strftime("%Y-%m-%d %H:%M UTC")
            story.append(Paragraph(
                f"<b>{comment.get('author')}</b> ({c_time}): {comment.get('content')}",
                ParagraphStyle('CommentItem', parent=body_style, leftIndent=15)
            ))
            
    # Build Document
    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica-Oblique', 8)
        canvas.setFillColor(MUTED_TEXT)
        canvas.drawString(36, 20, "CONFIDENTIAL - AI-Powered Threat Hunting & Detection Platform")
        canvas.drawRightString(doc.pagesize[0]-36, 20, f"Page {doc.page}")
        canvas.restoreState()
        
    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    buffer.seek(0)
    return buffer
