#!/usr/bin/env python3
"""Maintain the CVE archive.

    python scripts/cves.py build               regenerate pages from data/cves.json
    python scripts/cves.py sync [2026-Nov ...]  pull new Microsoft credits from MSRC, then build

`sync` reads Microsoft's monthly CVRF documents (the last three months by default),
adds every CVE whose acknowledgments credit nevul37, and rebuilds. Remove an entry by
adding its ID to "exclude" in data/cves.json so the next sync does not bring it back.
"""

import datetime
import html
import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "cves.json"
ARCHIVE_PAGE = ROOT / "pages" / "more-cves.html"
COUNT_PAGES = [ROOT / "index.html", ARCHIVE_PAGE]

CREDIT = re.compile(r"nevul37|jong\s*seong\s*kim", re.I)
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

GROUPS = [
    ("windows", "Windows"),
    ("office", "Office & Server"),
    ("apple", "Apple"),
    ("third-party", "Third-party"),
]
IMPACTS = [
    ("eop", "Elevation of privilege"),
    ("rce", "Remote code execution"),
    ("info", "Information disclosure"),
    ("spoofing", "Spoofing"),
    ("dos", "Denial of service"),
    ("other", "Other"),
]
# The chart folds Apple and third-party vendors together so it stays at three series.
CHART_SERIES = [
    ("windows", "Windows", ("windows",)),
    ("office", "Office & Server", ("office",)),
    ("other", "Other vendors", ("apple", "third-party")),
]


def group_of(cve):
    if cve["vendor"] == "Apple":
        return "apple"
    if cve["vendor"] != "Microsoft":
        return "third-party"
    if re.search(r"Office|Excel|Word|SharePoint|Exchange|\.NET", cve["title"]):
        return "office"
    return "windows"


def impact_of(cve):
    title = cve["title"]
    for key, pattern in [
        ("eop", "Elevation of Privilege"),
        ("rce", "Remote Code Execution"),
        ("info", "Information Disclosure"),
        ("spoofing", "Spoofing"),
        ("dos", "Denial of Service"),
    ]:
        if pattern.lower() in title.lower():
            return key
    return "other"


def sort_key(cve):
    _, year, num = cve["id"].split("-")
    return (cve["date"], int(year), int(num))


def month_label(date):
    year, month = date.split("-")
    return f"{MONTHS[int(month) - 1]} {year}"


def load():
    return json.loads(DATA.read_text(encoding="utf-8"))


def save(data):
    data["cves"].sort(key=sort_key, reverse=True)
    DATA.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ sync --

def fetch_cvrf(month):
    req = urllib.request.Request(
        f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}",
        headers={"Accept": "application/json", "User-Agent": "nevul37.github.io"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)


def recent_months(n=3):
    today = datetime.date.today()
    out = []
    for back in range(n - 1, -1, -1):
        y, m = divmod(today.year * 12 + today.month - 1 - back, 12)
        out.append(f"{y}-{MONTHS[m]}")
    return out


def sync(months):
    data = load()
    known = {c["id"] for c in data["cves"]} | set(data.get("exclude", []))
    added = []
    for month in months:
        try:
            doc = fetch_cvrf(month)
        except Exception as exc:  # a month that is not published yet returns 404
            print(f"{month}: skipped ({exc})")
            continue
        year, mon = month.split("-")
        for vuln in doc.get("Vulnerability") or []:
            names = " ".join(
                n.get("Value", "")
                for ack in vuln.get("Acknowledgments") or []
                for n in ack.get("Name") or []
            )
            cve_id = vuln.get("CVE")
            if not cve_id or cve_id in known or not CREDIT.search(names):
                continue
            entry = {
                "id": cve_id,
                "title": (vuln.get("Title") or {}).get("Value", "").strip(),
                "vendor": "Microsoft",
                "date": f"{year}-{MONTHS.index(mon) + 1:02d}",
                "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
            }
            data["cves"].append(entry)
            known.add(cve_id)
            added.append(entry)
    for entry in added:
        print(f"+ {entry['id']}  {entry['title']}")
    print(f"{len(added)} new CVE(s)")
    save(data)
    build()


# ----------------------------------------------------------------- build --

def esc(text):
    return html.escape(str(text), quote=True)


def render_filters(cves):
    counts = {key: 0 for key, _ in GROUPS + IMPACTS}
    for c in cves:
        counts[c["group"]] += 1
        counts[c["impact"]] += 1
    out = [
        f'<button class="chip" type="button" data-filter="group" data-value="all" aria-pressed="true">'
        f'All <span class="mono">{len(cves)}</span></button>'
    ]
    for key, label in GROUPS:
        out.append(
            f'<button class="chip" type="button" data-filter="group" data-value="{key}" aria-pressed="false">'
            f'{esc(label)} <span class="mono">{counts[key]}</span></button>'
        )
    out.append('<span class="chips__sep" aria-hidden="true"></span>')
    for key, label in IMPACTS:
        if counts[key]:
            out.append(
                f'<button class="chip chip--quiet" type="button" data-filter="impact" data-value="{key}" aria-pressed="false">'
                f'{esc(label)} <span class="mono">{counts[key]}</span></button>'
            )
    return "\n".join(out)


def render_chart(cves):
    years = sorted({c["date"][:4] for c in cves})
    totals = {key: 0 for key, _, _ in CHART_SERIES}
    per_year = {}
    for year in years:
        row = {}
        for key, _, groups in CHART_SERIES:
            row[key] = sum(1 for c in cves if c["date"][:4] == year and c["group"] in groups)
            totals[key] += row[key]
        per_year[year] = row
    peak = max(sum(r.values()) for r in per_year.values())

    legend = "\n".join(
        f'<li><i class="cve-chart__key" style="--c: var(--series-{i})"></i>{esc(label)} '
        f'<span class="mono">{totals[key]}</span></li>'
        for i, (key, label, _) in enumerate(CHART_SERIES, 1)
    )
    cols = []
    for year in years:
        row = per_year[year]
        total = sum(row.values())
        segs = "".join(
            f'<span class="cve-chart__seg" style="--c: var(--series-{i}); flex-grow: {row[key]}"></span>'
            for i, (key, _, _) in enumerate(CHART_SERIES, 1)
            if row[key]
        )
        tip = "; ".join(f"{label} {row[key]}" for key, label, _ in CHART_SERIES)
        data = " ".join(f'data-{key}="{row[key]}"' for key, _, _ in CHART_SERIES)
        cols.append(
            f'<a class="cve-chart__col" href="#y{year}" data-year="{year}" data-total="{total}" {data} '
            f'aria-label="{year}: {total} CVEs ({esc(tip)})">'
            f'<span class="cve-chart__value">{total}</span>'
            f'<span class="cve-chart__bar" style="--h: {total / peak:.3f}">{segs}</span>'
            f'<span class="cve-chart__year">{year}</span></a>'
        )
    return (
        f'<ul class="cve-chart__legend">\n{legend}\n</ul>\n'
        f'<div class="cve-chart__plot">\n' + "\n".join(cols) + "\n</div>"
    )


def render_archive(cves):
    out = []
    for year in sorted({c["date"][:4] for c in cves}, reverse=True):
        rows = [c for c in cves if c["date"][:4] == year]
        out.append(f'<section class="year" id="y{year}" data-year="{year}">')
        out.append(f'    <h2 class="year__label">{year} <span class="mono">{len(rows)}</span></h2>')
        for c in rows:
            when = month_label(c["date"])
            search = " ".join([c["id"], c["title"], c["vendor"], dict(GROUPS)[c["group"]], when]).lower()
            out.append(
                f'    <a class="cve-row" data-group="{c["group"]}" data-impact="{c["impact"]}" '
                f'data-search="{esc(search)}" href="{esc(c["url"])}" target="_blank" rel="noreferrer">\n'
                f'        <span class="cve-row__id">{esc(c["id"])}</span>\n'
                f'        <span class="cve-row__desc">{esc(c["title"])}</span>\n'
                f'        <span class="cve-row__vendor">{esc(c["vendor"])}</span>\n'
                f'        <span class="cve-row__date">{when}</span>\n'
                f"    </a>"
            )
        out.append("</section>")
    return "\n".join(out)


def splice(text, name, body):
    pattern = re.compile(rf"(<!-- cve:{name} -->)(.*?)(\s*<!-- /cve:{name} -->)", re.S)
    match = pattern.search(text)
    if not match:
        sys.exit(f"marker cve:{name} not found in {ARCHIVE_PAGE.name}")
    indent = re.search(r"([ \t]*)<!-- cve:" + name, text).group(1)
    block = "\n".join(indent + line if line else line for line in body.split("\n"))
    return text[: match.start()] + match.group(1) + "\n" + block + match.group(3) + text[match.end():]


def build():
    cves = sorted(load()["cves"], key=sort_key, reverse=True)
    for c in cves:
        c["group"] = group_of(c)
        c["impact"] = impact_of(c)

    page = ARCHIVE_PAGE.read_text(encoding="utf-8")
    page = splice(page, "filters", render_filters(cves))
    page = splice(page, "chart", render_chart(cves))
    page = splice(page, "archive", render_archive(cves))
    ARCHIVE_PAGE.write_text(page, encoding="utf-8")

    counts = {"total": len(cves)}
    for key, _ in GROUPS:
        counts[key] = sum(1 for c in cves if c["group"] == key)
    counts["microsoft"] = counts["windows"] + counts["office"]
    counts["first-year"] = min(c["date"][:4] for c in cves)
    counts["last-year"] = max(c["date"][:4] for c in cves)
    for path in COUNT_PAGES:
        text = path.read_text(encoding="utf-8")
        text = re.sub(
            r'(<span data-cve-count="([\w-]+)">)[^<]*(</span>)',
            lambda m: f"{m.group(1)}{counts.get(m.group(2), '?')}{m.group(3)}",
            text,
        )
        path.write_text(text, encoding="utf-8")
    print(f"built {len(cves)} CVEs ({counts['microsoft']} Microsoft, "
          f"{counts['apple']} Apple, {counts['third-party']} third-party)")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("build", "sync"):
        sys.exit(__doc__)
    if sys.argv[1] == "build":
        build()
    else:
        sync(sys.argv[2:] or recent_months())
