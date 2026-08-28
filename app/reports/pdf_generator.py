from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def generate_pdf(scan, findings, remediations) -> bytes:
    """Portable PDF companion report; HTML remains the detailed browser report."""
    output = BytesIO(); doc = SimpleDocTemplate(output, pagesize=letter); styles = getSampleStyleSheet(); story = []
    story += [Paragraph("CyberAudit Security Posture Report", styles["Title"]), Paragraph(f"Scan: {scan.id}", styles["Normal"]),
              Paragraph(f"Posture score: {scan.posture_score if scan.posture_score is not None else 'Unavailable'}", styles["Normal"]), Spacer(1, 12)]
    for f in findings:
        story += [Paragraph(f"{f.severity.value}: {f.title}", styles["Heading3"]), Paragraph(f.description, styles["Normal"]),
                  Paragraph(f"Recommendation: {f.recommendation}", styles["Normal"]), Spacer(1, 8)]
    story.append(Paragraph("CyberAudit provides security posture assessment and risk detection. No automated security assessment can guarantee complete protection against all threats.", styles["Italic"]))
    doc.build(story); return output.getvalue()
