H4RV3ST3R is a lightweight web crawler that extracts URLs from given sources and filters suspicious links based on a custom file hoster list. Built for anonymous, append-only data collection.

- Crawl depth control
- Hoster detection (mega.nz, dropbox.com, etc.)
- TXT/CSV output
- All results saved to results/




## Files

- `sources.txt` - URLs to crawl
- `hoster.txt` - File hosters to detect

## Usage

```bash
python h4rv3st3r.py -c -d 1 -o scan


```
## Commands

```
-c : Crawl (required)

-o : Output name

-d : Depth (default: 1)

-m : Min score (default: 30)

-v : Verbose

--delay : Seconds between requests

--format csv : CSV output
```
```
Scoring System
URLs are analyzed without opening them. Score factors:

Factor	Score	Example
File hoster detected	+30	mega.nz, dropbox.com, rapidgator.net
Suspicious path pattern	+20	/file/abc123, /d/xyz789
Suspicious parameter	+15	?key=, ?pwd=, ?token=, ?dl=
Long cryptic segment	+15	/7XfK2p9Qx4m1n5b2v8c3l6k9j0
Suspicious TLD	+10	.xyz, .top, .club, .click
Multiple subdomains	+5	dl-123.cdn.mega.nz
Threshold: Score ≥ 30 → flagged as suspicious

Recommendation: Score ≥ 50 → highly suspicious, manual review recommended
