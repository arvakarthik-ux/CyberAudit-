from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import PROJECT_ROOT

env = Environment(loader=FileSystemLoader(PROJECT_ROOT / "app" / "templates"), autoescape=select_autoescape(["html"]))


def render_report(scan, findings, remediations) -> str:
    return env.get_template("report.html").render(scan=scan, findings=findings, remediations=remediations,
        disclaimer="CyberAudit provides security posture assessment and risk detection. No automated security assessment can guarantee complete protection against all threats.")
