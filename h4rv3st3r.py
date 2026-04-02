#!/usr/bin/env python3

import os
import re
import csv
import time
import random
import argparse
import sys
import signal
from urllib.parse import urlparse, urljoin, unquote
from urllib.robotparser import RobotFileParser
from collections import Counter
from datetime import datetime
from typing import Set, List, Dict, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Opr/104.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
]

PATH_PATTERNS = [
    r'/[A-Za-z0-9_-]{20,}/',
    r'/[A-Za-z0-9]{32,}',
    r'/[a-f0-9]{32,}',
    r'/file/[\w-]+',
    r'/d/[\w-]+',
    r'/folder/[\w-]+',
    r'/f/[\w-]+',
    r'[?&]key=[A-Za-z0-9]+',
    r'[?&]pwd=[A-Za-z0-9]+',
    r'[?&]code=[A-Za-z0-9]+',
    r'[?&]token=[A-Za-z0-9]+',
    r'\.(zip|rar|7z|tar|gz|exe|apk|bin|img|iso|mp4|mkv|avi|mov|wmv|flv|webm)$',
]

SUSPICIOUS_PARAMS = ['key', 'pwd', 'code', 'token', 'auth', 'dl', 'download', 'file', 'id']
SUSPICIOUS_TLDS = {'xyz', 'top', 'club', 'online', 'site', 'win', 'bid', 'date', 'click', 'link'}

ACCEPT_LANGUAGES = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'de-DE,de;q=0.9', 'fr-FR,fr;q=0.8', 'es-ES,es;q=0.7']
ACCEPT_HEADERS = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
]

aborted = False

def signal_handler(sig, frame):
    global aborted
    aborted = True
    print("\n\n[!] Aborted by user")
    print("[!] Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def load_hoster_list() -> Set[str]:
    hosters = set()
    hoster_file = "hoster.txt"
    if not os.path.exists(hoster_file):
        print(f"[!] {hoster_file} not found")
        sys.exit(1)
    with open(hoster_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                hosters.add(line.lower())
    print(f"[+] loaded {len(hosters)} hosters")
    return hosters


def load_sources() -> List[str]:
    sources = []
    source_file = "sources.txt"
    if not os.path.exists(source_file):
        print(f"[!] {source_file} not found")
        sys.exit(1)
    with open(source_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                sources.append(line)
    print(f"[+] loaded {len(sources)} sources")
    return sources


class LinkExtractor:
    def __init__(self, delay: float = 2.0):
        self.delay = delay
        self.session = self._create_session()
        self.visited = set()
        self.errors = []
        self.link_count = 0
        self.should_stop = False

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, read=2, connect=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = True
        return session

    def _get_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def _get_random_headers(self) -> Dict:
        headers = {
            'User-Agent': self._get_ua(),
            'Accept': random.choice(ACCEPT_HEADERS),
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }
        if random.random() > 0.8:
            headers['DNT'] = '1'
        return {k: v for k, v in headers.items() if v}

    def extract(self, url: str, depth: int = 0, current_depth: int = 0, verbose: bool = False) -> Set[str]:
        if self.should_stop:
            return set()
        if current_depth > depth or url in self.visited:
            return set()
        self.visited.add(url)

        try:
            if verbose:
                print(f"    [{datetime.now().strftime('%H:%M:%S')}] GET {url[:70]}")

            time.sleep(self.delay + random.uniform(0, self.delay))
            resp = self.session.get(url, timeout=20, headers=self._get_random_headers(), allow_redirects=True)
            resp.raise_for_status()

            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return set()

            soup = BeautifulSoup(resp.text, 'lxml')
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()

            links = set()
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    absolute = urljoin(url, href)
                    if absolute.startswith(('http://', 'https://')):
                        links.add(absolute)
                        if verbose:
                            print(f"      [+] {absolute}")

            text = soup.get_text()
            for match in re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text):
                if match.startswith(('http://', 'https://')):
                    links.add(match)
                    if verbose:
                        print(f"      [+] {match}")

            if current_depth < depth:
                for link in list(links)[:15]:
                    if self.should_stop:
                        return links
                    links.update(self.extract(link, depth, current_depth + 1, verbose))

            return links

        except Exception as e:
            self.errors.append((url, str(e)[:40]))
            if verbose:
                print(f"    [!] error: {e}")
            return set()

    def extract_from_sources(self, depth: int = 0, output_file: str = None, verbose: bool = False) -> Set[str]:
        urls = load_sources()
        all_links = set()
        total = len(urls)

        print(f"\n{'='*60}")
        print(f"[*] TARGETS: {total}")
        print(f"[*] DEPTH: {depth}")
        print(f"[*] DELAY: {self.delay}s")
        print(f"[*] Press Ctrl+C to abort")
        print(f"{'='*60}\n")

        for i, url in enumerate(urls, 1):
            if self.should_stop:
                break
            print(f"\n[{i}/{total}] {url}")
            print(f"    [>] scanning...")
            
            start_time = time.time()
            links = self.extract(url, depth, verbose=verbose)
            elapsed = time.time() - start_time
            
            new_links = len(links)
            all_links.update(links)
            self.link_count += new_links
            
            print(f"    [<] {new_links} new links ({elapsed:.1f}s) | total: {len(all_links)}")

        if self.should_stop:
            print(f"\n[!] Aborted after {i}/{total} sources")

        print(f"\n{'='*60}")
        print(f"[+] COMPLETE: {len(all_links)} links from {i if self.should_stop else total} sources")
        if self.errors:
            print(f"[!] ERRORS: {len(self.errors)}")
        print(f"{'='*60}")

        if output_file and all_links:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(f"\n# session: {timestamp}\n")
                f.write(f"# depth: {depth}\n")
                for link in sorted(all_links):
                    f.write(f"{link}\n")
            print(f"\n[+] saved: {output_file} ({len(all_links)} links)")

        return all_links


class SuspiciousFilter:
    def __init__(self, hosters: Set[str]):
        self.hosters = hosters
        self.patterns = [re.compile(p, re.IGNORECASE) for p in PATH_PATTERNS]

    def analyze(self, url: str) -> Dict:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = unquote(parsed.path.lower())
        query = parsed.query.lower()

        reasons = []
        score = 0

        for hoster in self.hosters:
            if hoster in domain:
                reasons.append(f"hoster:{hoster}")
                score += 30
                break

        for pattern in self.patterns:
            if pattern.search(path):
                reasons.append(f"pattern")
                score += 20
                break

        for param in SUSPICIOUS_PARAMS:
            if f'{param}=' in query:
                reasons.append(f"param:{param}")
                score += 15
                break

        segments = [s for s in path.split('/') if s]
        long_segs = [s for s in segments if len(s) > 20 and not any(c in s for c in '.-_')]
        if long_segs:
            reasons.append(f"long")
            score += 15

        if domain.count('.') >= 3:
            reasons.append("subdomains")
            score += 5

        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"tld:.{tld}")
            score += 10

        return {
            'url': url,
            'domain': domain,
            'score': min(score, 100),
            'reasons': reasons,
            'hoster': self._detect_hoster(domain)
        }

    def _detect_hoster(self, domain: str) -> str:
        for hoster in self.hosters:
            if hoster in domain:
                return hoster
        return ''

    def filter(self, urls: Set[str], min_score: int = 30, verbose: bool = False) -> Tuple[List[Dict], List[Dict]]:
        suspicious = []
        clean = []
        total = len(urls)

        print(f"\n{'='*60}")
        print(f"[*] ANALYZING {total} URLs")
        print(f"[*] MIN SCORE: {min_score}")
        print(f"{'='*60}\n")

        for i, url in enumerate(urls, 1):
            analysis = self.analyze(url)
            if analysis['score'] >= min_score:
                suspicious.append(analysis)
                print(f"[{i}/{total}] 🔴 FOUND [{analysis['score']}] {analysis['hoster']}")
                print(f"         {analysis['url']}")
            else:
                clean.append(analysis)
                if verbose:
                    print(f"[{i}/{total}] ⚪ clean")

        print(f"\n{'='*60}")
        print(f"[+] SUSPICIOUS: {len(suspicious)}")
        print(f"[+] CLEAN: {len(clean)}")
        print(f"{'='*60}")

        suspicious.sort(key=lambda x: x['score'], reverse=True)
        return suspicious, clean


def export_csv_append(items: List[Dict], filename: str, source: str = ""):
    file_exists = os.path.isfile(filename)
    with open(filename, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['timestamp', 'source', 'score', 'hoster', 'domain', 'reasons', 'url'])
        for item in items:
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                source,
                item['score'],
                item['hoster'],
                item['domain'],
                '; '.join(item['reasons']),
                item['url']
            ])
    print(f"\n[+] saved: {filename} ({len(items)} new links)")


def export_txt_append(urls: Set[str], filename: str, source: str = ""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(f"\n# session: {timestamp}\n")
        f.write(f"# source: {source}\n")
        for url in sorted(urls):
            f.write(f"{url}\n")
    print(f"\n[+] saved: {filename} ({len(urls)} new links)")


def main():
    p = argparse.ArgumentParser(description="h4rv3st3r")
    p.add_argument('-c', '--crawl', action='store_true', help='crawl sources.txt')
    p.add_argument('-o', '--output', default='scan')
    p.add_argument('--format', choices=['txt', 'csv'], default='txt')
    p.add_argument('-d', '--depth', type=int, default=1)
    p.add_argument('--delay', type=float, default=2.0)
    p.add_argument('-m', '--min-score', type=int, default=30)
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('--stats', action='store_true')

    args = p.parse_args()

    if not args.crawl:
        print("[!] ERROR: -c (--crawl) is required")
        sys.exit(1)

    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n{'#'*60}")
    print(f"# H4RV3ST3R")
    print(f"# TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")

    hosters = load_hoster_list()
    extractor = LinkExtractor(delay=args.delay)
    
    all_links_file = os.path.join(results_dir, f"{args.output}_all.txt")
    
    try:
        urls = extractor.extract_from_sources(args.depth, output_file=all_links_file, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(0)

    if not urls:
        print("\n[!] no urls found")
        return

    flt = SuspiciousFilter(hosters)
    suspicious, clean = flt.filter(urls, min_score=args.min_score, verbose=args.verbose)

    if not args.stats and suspicious:
        if args.format == 'csv':
            report_file = os.path.join(results_dir, f"{args.output}_suspicious.csv")
            export_csv_append(suspicious, report_file, "sources.txt")
        else:
            report_file = os.path.join(results_dir, f"{args.output}_suspicious.txt")
            export_txt_append({u['url'] for u in suspicious}, report_file, "sources.txt")

    print(f"\n[+] DONE")
    print(f"[+] results in: {results_dir}/")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Aborted by user")
        print("[!] Exiting gracefully...")
        sys.exit(0)