from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_report(target: str, data: dict, output_path: Path) -> Path:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    open_port_count = sum(len(v) for v in data.get("port_results", {}).values())

    html = template.render(
        target=target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        data=data,
        open_port_count=open_port_count,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
