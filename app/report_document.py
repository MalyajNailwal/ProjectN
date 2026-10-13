"""Evidence-based, offline human-readable exports for a saved scan.

The document is rebuilt from one stored report on each download. Scanner diagnostics
and raw stage payloads are deliberately excluded from shareable files.
"""

from __future__ import annotations

import html
import io
import os
import re
import subprocess
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape

from app.core import ROOT, SECRET_TEXT


def safe(value: object) -> str:
    """Apply the same secret redaction used for scanner diagnostics before export."""
    value = str(value if value is not None else "")
    value = re.sub(r"https?://[^\s<>\"']+", lambda match: urlunsplit(urlsplit(match.group())._replace(query="", fragment="")), value)
    value = SECRET_TEXT.sub(lambda match: (match.group(1) or "") + "[redacted]", value)
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", value)


def revision(value: object) -> str:
    value = str(value or "")
    return value if re.fullmatch(r"[0-9a-fA-F]{7,40}", value) else safe(value or "not recorded")


def date(value: object) -> str:
    try:
        # Windows C runtimes reject some valid Unix timestamps before 1970.
        moment = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=float(value))
        try:
            moment = moment.astimezone()
        except (OSError, OverflowError):
            # An early UTC instant may still be in 1969 in the local timezone.
            pass
        return moment.strftime("%d %B %Y, %H:%M %Z")
    except (TypeError, ValueError, OverflowError):
        return "Not recorded"


def impact(finding: dict) -> str:
    title = str(finding.get("title", "")).lower()
    scanner = str(finding.get("scanner", ""))
    if scanner == "accessibility":
        return "People using assistive technology or keyboard navigation may have difficulty completing this task. Validate the affected page with users and assistive tools."
    if scanner == "performance":
        return "The measured page may load or respond more slowly under the tested conditions. Validate with repeat measurements and field data where available."
    if "sql injection" in title:
        return "If the input reaches a database query unsafely, data could be exposed or changed. Scanner evidence alone does not establish exploitability."
    if "cross-site scripting" in title or "xss" in title:
        return "If executable input reaches a browser response, a user session or page content could be affected. Confirm the actual response context."
    if "content security policy" in title or "csp" in title:
        return "Without an effective CSP, an injected script has fewer browser restrictions. CSP does not replace output encoding."
    if "cookie" in title:
        return "Missing cookie attributes may weaken transport or browser isolation; the correct attributes depend on the cookie's purpose."
    if "secret" in title or scanner == "secrets":
        return "An exposed credential may permit unauthorized access until it is revoked. Confirm validity without reproducing the value in tickets."
    if "certificate" in title or "tls" in title:
        return "A confirmed TLS issue can reduce connection confidentiality or availability, depending on the affected client and route."
    if "dependency" in title or scanner == "dependencies":
        return "A vulnerable dependency may expose the application if the affected code path is reachable. Check the installed version and advisory conditions."
    return "Potential impact depends on the affected asset and whether the observation is reproducible. Validate before assigning a concrete security effect."


def blocks_for(scan: dict) -> tuple[list[tuple], str, str]:
    report = scan["result"]
    target = report.get("target") or scan.get("target") or {}
    target_name = safe(target.get("url") or target.get("repo_url") or target.get("local_path") or "Unknown target")
    scan_id = str(scan["id"])
    findings = report.get("findings") or []
    stages = report.get("stages") or []
    limits = report.get("limitations") or []
    counts = Counter(str(item.get("severity", "unknown")) for item in findings)
    states = Counter(str(item.get("state", "unknown")) for item in stages)
    blocks: list[tuple] = []
    add = blocks.append

    add(("title", "Assessment & developer remediation brief", "Security · Accessibility · Performance"))
    add(("para", f"TARGET  {target_name}"))
    add(("para", f"SCAN ID  {scan_id}  |  PROFILE  {safe(target.get('profile') or scan.get('target', {}).get('profile') or 'not recorded')}"))
    add(("para", f"SCAN WINDOW  {date(report.get('started_at'))} to {date(report.get('finished_at'))}"))
    if report.get("retry_of"):
        add(("para", f"Selected-check retry of {safe(report['retry_of'])}. Only {', '.join(map(safe, report.get('requested_steps') or [])) or 'selected checks'} ran here. Counts are not combined with the earlier scan."))
    if report.get("cancelled"):
        add(("para", "This scan was stopped. The saved result is partial."))
    add(("para", "Point-in-time scanner observations. Findings need validation; zero findings never proves that a target is secure or fully covered."))

    add(("heading", "1. Executive overview", 1))
    add(("table", ["Recorded signal", "Result"], [
        ["Findings", str(len(findings))],
        ["Severity labels", ", ".join(f"{level}: {counts[level]}" for level in ("critical", "high", "medium", "low", "info", "unknown") if counts[level]) or "None recorded"],
        ["Check completion", f"{states['completed']} completed; {len(stages) - states['completed']} incomplete or skipped"],
        ["Coverage limitations", str(len(limits))],
    ]))
    add(("para", "Severity scales may differ between tools. Accessibility 'critical' is not a confirmed critical security vulnerability. Alerts with needs-review confidence require human validation."))

    add(("heading", "2. Developer action plan", 1))
    groups: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for item in findings:
        groups[(str(item.get("scanner", "")), str(item.get("title", "")), str(item.get("rule", "")), str(item.get("severity", "unknown")))].append(item)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if not groups:
        add(("para", "No findings were recorded in this scan. Review the coverage section before interpreting this result."))
    for number, ((scanner, title, rule, severity), items) in enumerate(sorted(groups.items(), key=lambda pair: (rank.get(pair[0][3], 5), pair[0][0], pair[0][1])), 1):
        example = items[0]
        add(("heading", f"2.{number}  {safe(title)}", 2))
        add(("table", ["Field", "Observed or recommended"], [
            ["Priority / scope", f"{safe(severity).upper()} · {len(items)} finding(s) · {safe(scanner)} · rule {safe(rule or 'not recorded')}"],
            ["Evidence example", safe(example.get("evidence") or "No evidence text recorded")],
            ["Potential effect", impact(example)],
            ["Developer action", safe(example.get("remediation") or "Investigate the affected component and document the validated fix.")],
            ["Verify the fix", safe(example.get("verification") or "Repeat the relevant check on the affected asset and compare evidence.")],
            ["Interpretation", "Needs human validation" if any(x.get("confidence") == "needs-review" for x in items) else "See individual confidence labels below"],
        ]))

    add(("heading", "3. Finding inventory and evidence", 1))
    add(("para", "Every finding from this selected scan is listed below. Similar alerts can describe one underlying issue; counts are scanner observations, not independently verified vulnerabilities."))
    if not findings:
        add(("para", "No finding records were produced."))
    for index, item in enumerate(findings, 1):
        stage = next((stage for stage in stages if stage.get("id") == item.get("scanner")), {})
        add(("heading", f"F{index:03d}  {safe(item.get('title') or 'Untitled finding')}", 2))
        add(("table", ["Field", "Record"], [
            ["Level / confidence", f"{safe(item.get('severity') or 'unknown')} / {safe(item.get('confidence') or 'not recorded')}"],
            ["Affected asset", safe(item.get("location") or "Not recorded")],
            ["Scanner / rule", f"{safe(item.get('scanner') or 'not recorded')} / {safe(item.get('rule') or 'not recorded')}"],
            ["Scanner version", safe(stage.get("runtime_version") or stage.get("source_version") or "Not recorded")],
            ["Source / rules revision", f"{revision(stage.get('source_revision'))} / {revision(stage.get('rules_revision'))}"],
            ["Evidence", safe(item.get("evidence") or "Not recorded")],
            ["Fix", safe(item.get("remediation") or "Investigate and correct the underlying issue.")],
            ["Verification", safe(item.get("verification") or "Repeat the relevant check after the change.")],
        ]))

    add(("heading", "4. Check coverage", 1))
    if stages:
        add(("table", ["Check", "State", "Observed result / versions"], [[
            safe(stage.get("label") or stage.get("id") or "Unknown"),
            safe(stage.get("state") or "unknown"),
            safe(stage.get("summary") or "No summary") + "\nRuntime: " + safe(stage.get("runtime_version") or "not recorded") + " · Source: " + revision(stage.get("source_revision")) + " · Rules: " + revision(stage.get("rules_revision")),
        ] for stage in stages]))
    else:
        add(("para", "No check stages were recorded."))
    options = target.get("full_options") or {}
    if options:
        add(("para", "Configured Full scope: " + "; ".join(f"{safe(key)}: {safe(value)}" for key, value in options.items() if value is not None)))

    add(("heading", "5. Limitations and next steps", 1))
    if limits:
        add(("table", ["Check / limitation", "Observed condition", "Next action"], [[safe(item.get("scanner") or "Assessment") + " · " + safe(item.get("code") or "unknown"), safe(item.get("message") or "No detail recorded"), safe(item.get("resolution") or "Review check setup and rerun") ] for item in limits]))
    else:
        add(("para", "No limitation records were saved. Coverage is still limited to the configured scope and observed responses."))
    add(("para", "To close a ticket, reproduce the observation on an authorized environment, apply the fix, and rerun the same check and asset. If a check was partial or skipped, a missing alert on a later run is not by itself proof of remediation."))
    add(("para", "Source: ProjectN local scan history. This document includes the selected scan's finding records and stage summaries. Download JSON from the same scan for raw structured inventories and additional stage details. No new target request is sent when exporting."))
    return blocks, target_name, scan_id


def _run(value: str, bold: bool = False, color: str | None = None, size: int | None = None) -> str:
    props = ("<w:b/>" if bold else "") + (f'<w:color w:val="{color}"/>' if color else "") + (f'<w:sz w:val="{size}"/>' if size else "")
    return f'<w:r><w:rPr>{props}</w:rPr><w:t xml:space="preserve">{escape(value)}</w:t></w:r>'


def _para(value: str, style: str = "Normal") -> str:
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{"<w:br/>".join(_run(part) for part in value.split(chr(10)))}</w:p>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [9300 // len(headers)] * len(headers)
    def cell(value: str, width: int, shade: str = "") -> str:
        fill = f'<w:shd w:fill="{shade}"/>' if shade else ""
        return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{fill}</w:tcPr>{_para(value)}</w:tc>'
    head = '<w:tr><w:trPr><w:tblHeader w:val="true"/></w:trPr>' + ''.join(cell(value, widths[i], "DDEBEC") for i, value in enumerate(headers)) + '</w:tr>'
    body = ''.join('<w:tr>' + ''.join(cell(value, widths[i], "F4F8F8" if n % 2 else "") for i, value in enumerate(row)) + '</w:tr>' for n, row in enumerate(rows))
    return '<w:tbl><w:tblPr><w:tblW w:w="9300" w:type="dxa"/><w:tblBorders><w:bottom w:val="single" w:sz="4" w:color="DCE5E9"/><w:insideH w:val="single" w:sz="4" w:color="DCE5E9"/></w:tblBorders></w:tblPr>' + head + body + '</w:tbl>'


def make_docx(blocks: list[tuple], target: str, scan_id: str) -> bytes:
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    body = []
    for block in blocks:
        if block[0] == "title":
            body.extend((_para("PROJECTN / LOCAL ASSESSMENT", "Kicker"), _para(block[1], "Title"), _para(block[2], "Subtitle")))
        elif block[0] == "heading":
            body.append(_para(block[1], "Heading1" if block[2] == 1 else "Heading2"))
        elif block[0] == "para":
            body.append(_para(block[1]))
        elif block[0] == "table":
            body.append(_table(block[1], block[2]))
    document = f'<?xml version="1.0" encoding="UTF-8"?><w:document {ns}><w:body>{"".join(body)}<w:sectPr><w:headerReference w:type="default" r:id="rId2"/><w:footerReference w:type="default" r:id="rId3"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1150" w:right="1200" w:bottom="1100" w:left="1200"/></w:sectPr></w:body></w:document>'
    styles = '''<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="19"/><w:color w:val="203345"/></w:rPr></w:rPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Kicker"><w:name w:val="Kicker"/><w:rPr><w:b/><w:color w:val="087980"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:color w:val="123344"/><w:sz w:val="38"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:rPr><w:color w:val="587283"/><w:sz w:val="23"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:rPr><w:b/><w:color w:val="087980"/><w:sz w:val="27"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="Heading 2"/><w:rPr><w:b/><w:color w:val="123344"/><w:sz w:val="22"/></w:rPr></w:style></w:styles>'''
    header = f'<?xml version="1.0" encoding="UTF-8"?><w:hdr {ns}>{_para("PROJECTN  /  " + target[:95])}</w:hdr>'
    footer = f'<?xml version="1.0" encoding="UTF-8"?><w:ftr {ns}><w:p>{_run("SCAN " + scan_id[:8] + "  ·  LOCAL EVIDENCE  ·  PAGE ", color="587283", size=16)}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>'
    types = '''<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>'''
    root_rels = '''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
    doc_rels = '''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>'''
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as package:
        for name, content in {"[Content_Types].xml": types, "_rels/.rels": root_rels, "word/document.xml": document, "word/styles.xml": styles, "word/header1.xml": header, "word/footer1.xml": footer, "word/_rels/document.xml.rels": doc_rels}.items():
            package.writestr(name, content)
    return output.getvalue()


def make_html(blocks: list[tuple], target: str, scan_id: str) -> str:
    h = lambda value: html.escape(value).replace("\n", "<br>")
    parts = []
    for block in blocks:
        if block[0] == "title":
            parts.append(f'<section class="hero"><div class="eyebrow">PROJECTN · ASSESSMENT BRIEF</div><h1>{h(block[1])}</h1><div class="subtitle">{h(block[2])}</div></section>')
        elif block[0] == "heading":
            tag = "h2" if block[2] == 1 else "h3"
            parts.append(f'<{tag}>{h(block[1])}</{tag}>')
        elif block[0] == "para":
            parts.append(f'<p>{h(block[1])}</p>')
        elif block[0] == "table":
            parts.append('<table><thead><tr>' + ''.join(f'<th>{h(v)}</th>' for v in block[1]) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{h(v)}</td>' for v in row) + '</tr>' for row in block[2]) + '</tbody></table>')
    css = '''@page{size:A4;margin:22mm 16mm 19mm}*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;color:#203345;font-size:10.2px;line-height:1.47;margin:0}.hero{border-top:6px solid #087980;padding:24px 0 23px;border-bottom:1px solid #ccdfe1;margin-bottom:25px}.eyebrow{color:#087980;font-weight:800;letter-spacing:1.4px;font-size:10px}h1{font-size:31px;line-height:1.12;margin:10px 0;color:#123344}.subtitle{font-size:16px;color:#587283}h2{font-size:18px;color:#087980;margin:26px 0 10px;break-after:avoid}h3{font-size:13px;color:#123344;margin:20px 0 8px;break-after:avoid}p{margin:0 0 11px;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed;margin:9px 0 17px;font-size:9.2px}thead{display:table-header-group}th{background:#ddebeb;color:#123344;text-align:left;font-weight:700}td,th{padding:8px 9px;border:1px solid #dce5e9;vertical-align:top;overflow-wrap:anywhere}tr:nth-child(even) td{background:#f4f8f8}tr{break-inside:avoid}'''
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>' + h(target) + ' · ProjectN report</title><style>' + css + '</style><body>' + ''.join(parts) + '</body></html>'


def make_pdf(blocks: list[tuple], target: str, scan_id: str) -> bytes:
    runtime = ROOT / "tools" / "venvs" / "browser-journeys" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    browser_path = ROOT / "tools" / "web" / "browser-journeys" / "runtime"
    if not runtime.is_file():
        raise RuntimeError("PDF browser runtime is unavailable. Run scripts/setup_native.py browser, then try again.")
    with tempfile.TemporaryDirectory(prefix="projectn-export-") as directory:
        html_path = Path(directory) / "report.html"
        pdf_path = Path(directory) / "report.pdf"
        html_path.write_text(make_html(blocks, target, scan_id), encoding="utf-8")
        code = '''from pathlib import Path
from playwright.sync_api import sync_playwright
import sys
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.route("**/*", lambda route: route.continue_() if route.request.url.startswith("file:") else route.abort())
    page.goto(Path(sys.argv[1]).as_uri(), wait_until="load")
    page.pdf(path=sys.argv[2], format="A4", print_background=True, display_header_footer=True, margin={"top":"22mm","bottom":"19mm","left":"16mm","right":"16mm"}, header_template=sys.argv[3], footer_template=sys.argv[4])
    browser.close()
'''
        header = '<div style="width:100%;margin:0 16mm;font:8px Arial;color:#087980;border-bottom:1px solid #087980;padding-bottom:4px">PROJECTN / ' + html.escape(target[:95]) + '</div>'
        footer = '<div style="width:100%;margin:0 16mm;font:8px Arial;color:#587283;border-top:1px solid #dce5e9;padding-top:4px">SCAN ' + html.escape(scan_id[:8]) + ' · LOCAL EVIDENCE <span style="float:right">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
        try:
            result = subprocess.run([str(runtime), "-c", code, str(html_path), str(pdf_path), header, footer], env={**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(browser_path)}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("PDF generation timed out. Download Word or JSON and retry after reducing report size.") from exc
        if result.returncode or not pdf_path.is_file():
            raise RuntimeError("PDF renderer failed. Check the local Chromium setup with scripts/doctor.py, then retry.")
        return pdf_path.read_bytes()
