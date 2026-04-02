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
