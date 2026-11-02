# jongseong.kim

Personal site, served by GitHub Pages from `main`. Plain HTML and CSS, no build step.

## Updating the CVE list

The CVE archive (`pages/more-cves.html`) and the CVE counts on the home page are generated
from `data/cves.json`.

```
python scripts/cves.py sync               # pull new Microsoft credits for the last three months
python scripts/cves.py sync 2026-Nov      # or for specific Patch Tuesday months
python scripts/cves.py build              # regenerate after editing data/cves.json by hand
```

`sync` reads Microsoft's CVRF feed and adds every CVE whose acknowledgments credit `nevul37`.
Apple and third-party CVEs are added to `data/cves.json` by hand. To drop an entry for good,
add its ID to `"exclude"` so the next sync does not bring it back.
