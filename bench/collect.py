#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect a SARIF file of Xinpect scanning the OWASP Benchmark corpus.

Two separate steps on purpose:

    collect.py scan   --key <license key> --out raw.jsonl
        Talks to a running Xinpect engine and stores, per case, the raw issues
        the engine returned. Slow (2740 scans, ~8 min) and needs a licence.

    collect.py sarif  --raw raw.jsonl --out xinpect.sarif
        Pure transform: raw issues -> one SARIF 2.1.0 file. No network, no
        licence. Anyone can rerun this on the published raw file and get the
        identical SARIF, byte for byte.

The split exists so that the step which could quietly favour us -- turning our
own issue records into a standard format -- is auditable and repeatable without
trusting the machine that produced the raw data.

WHAT THE TRANSFORM DOES, in full
--------------------------------
1. One issue -> one SARIF result, with `ruleId` = the engine's check_id.
2. Two rules need a qualifier, because one check_id covers several vulnerability
   types. They get it appended to the rule id:
       E3-TAINT-JAVA-001/{sink_kind}     e.g. .../sql_injection
       E2-SEC-JCRP-001/{hash|crypto}     decided by whether the finding is about
                                         MessageDigest/hash or Cipher/encryption
   This is what SARIF rule ids are for: identify the rule, not just the checker.
3. Issues carry `also_detected_by` / `root_cause_merged`: other rules that hit
   the same place and were folded into this one for display. They are emitted as
   extra results at the same location, because the engine really did report them.
   Where such a folded entry has no `sink_kind`, its category is read from the
   title with the small keyword table below -- and the number of results that
   depended on that keyword fallback is printed and stored in the SARIF
   properties, so nobody has to guess how much of the score rests on it.
4. Nothing is dropped and nothing is invented. Every rule id that appears in the
   output has an entry in mapping.json; rules that mean nothing on this corpus
   are mapped to the sentinel category `non-owasp`, where they can never match a
   case's category. That is deliberately not the same as filtering them out: an
   unmapped rule is fatal in xinpect-bench, and a hidden filter is worse.
"""
import argparse
import csv
import glob
import json
import os
import sys
import time
import urllib.request
from collections import Counter

BASE = os.environ.get('BENCH_BASE', '/home/ubuntu/BenchmarkJava')
SRC_DIR = os.path.join(BASE, 'src/main/java/org/owasp/benchmark/testcode')
PROPS = os.path.join(BASE, 'src/main/resources/benchmark.properties')
EXPECTED = os.path.join(BASE, 'expectedresults-1.2.csv')

# Title keywords used only when a folded-in finding carries no sink_kind.
# Deliberately small and printed in the output: every use is counted.
TITLE_KEYWORDS = [
    ('SQL 注入', 'sql_injection'),
    ('SQL注入', 'sql_injection'),
    ('XSS', 'xss'),
    ('跨站', 'xss'),
    ('命令注入', 'command_injection'),
    ('路径穿越', 'path_traversal'),
    ('路径遍历', 'path_traversal'),
    ('越权', 'trust_boundary'),
    ('信任边界', 'trust_boundary'),
    ('XPATH', 'xpath_injection'),
    ('LDAP', 'ldap_injection'),
    ('反序列化', 'deserialization'),
]


def load_expected():
    rows = {}
    with open(EXPECTED, encoding='utf-8') as fh:
        next(fh)
        for line in csv.reader(fh):
            if len(line) < 4:
                continue
            rows[line[0].strip()] = (line[1].strip(), line[2].strip().lower() == 'true')
    return rows


def rule_id_of(check_id, sink_kind='', title=''):
    """Attach the qualifier that makes the rule id identify a vulnerability type."""
    check_id = check_id or 'UNKNOWN'
    if check_id == 'E3-TAINT-JAVA-001':
        return '%s/%s' % (check_id, sink_kind or 'unspecified')
    if check_id == 'E2-SEC-JCRP-001':
        t = title or ''
        if 'MessageDigest' in t or '哈希' in t or 'Hash' in t:
            return '%s/hash' % check_id
        if 'Cipher' in t or '加密' in t or 'Encrypt' in t:
            return '%s/crypto' % check_id
        return '%s/unspecified' % check_id
    return check_id


def category_hint_from_title(title):
    t = title or ''
    tu = t.upper()
    for kw, kind in TITLE_KEYWORDS:
        if kw.upper() in tu:
            return kind
    return ''


def cmd_scan(args):
    api = 'http://127.0.0.1:%d/scan' % args.port
    with open(PROPS, encoding='utf-8', errors='ignore') as fh:
        props = fh.read()
    expected = load_expected()
    files = sorted(glob.glob(os.path.join(SRC_DIR, 'BenchmarkTest*.java')))
    files = [f for f in files if os.path.basename(f).replace('.java', '') in expected]
    if args.expect_cases and len(files) != args.expect_cases and not args.limit:
        print('FAIL corpus drift: %d cases, expected %d' % (len(files), args.expect_cases))
        return 1
    if args.limit:
        files = files[: args.limit]
    print('api=%s cases=%d out=%s' % (api, len(files), args.out), flush=True)

    t0 = time.time()
    n_issues = 0
    failed = []
    done = set()
    if args.resume and os.path.exists(args.out):
        with open(args.out, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    done.add(json.loads(line)['case'])
                except Exception:  # noqa: BLE001 - a truncated last line is just skipped
                    pass
        print('resume: %d cases already collected' % len(done), flush=True)
        todo = [f for f in files if os.path.basename(f) not in done]
    else:
        todo = files
    print('to scan this run: %d' % len(todo), flush=True)

    mode = 'a' if done else 'w'
    with open(args.out, mode, encoding='utf-8') as out:
        for idx, f in enumerate(todo):
            name = os.path.basename(f)
            with open(f, encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
            payload = json.dumps({'code_files': {name: content, 'benchmark.properties': props},
                                  'scan_mode': 'free', 'brains': ['1', '2']}).encode()
            rec = None
            for _attempt in range(3):
                try:
                    req = urllib.request.Request(api, data=payload, headers={
                        'Content-Type': 'application/json', 'X-API-Key': args.key})
                    data = json.loads(urllib.request.urlopen(req, timeout=60).read())
                    issues = []
                    for _bid, r in (data.get('results') or {}).items():
                        issues.extend(r.get('issues') or [])
                    rec = {'case': name, 'version': data.get('version', ''),
                           'scan_id': data.get('scan_id', ''), 'issues': issues}
                    break
                except Exception as e:  # noqa: BLE001 - any transport error retries
                    rec = None
                    last = e
                    time.sleep(0.5)
            if rec is None:
                failed.append(name)
                print('  ! %s failed: %s' % (name, last), file=sys.stderr)
            else:
                n_issues += len(rec['issues'])
                out.write(json.dumps(rec, ensure_ascii=False) + '\n')
                out.flush()
            if (idx + 1) % 100 == 0:
                el = time.time() - t0
                print('  %d/%d  %.1fs  %.2f/s  issues=%d'
                      % (idx + 1, len(todo), el, (idx + 1) / el, n_issues), flush=True)

    if failed:
        print('FAIL %d cases failed, refusing to produce a score: %s'
              % (len(failed), failed[:10]))
        return 1
    print('done: %d cases, %d issues, %.1fs -> %s'
          % (len(files), n_issues, time.time() - t0, args.out))
    return 0


def cmd_sarif(args):
    stats = Counter()
    results = []
    rules_seen = {}
    version = ''

    with open(args.raw, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            stats['cases'] += 1
            version = version or rec.get('version', '')
            case = rec['case']
            uri = 'file:///BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/%s' % case
            for it in rec.get('issues') or []:
                stats['issues'] += 1
                check_id = it.get('check_id') or ''
                sink_kind = it.get('sink_kind') or ''
                title = str(it.get('title') or it.get('message') or '')
                rid = rule_id_of(check_id, sink_kind, title)
                results.append({
                    'ruleId': rid,
                    'level': 'error' if it.get('severity') in ('critical', 'high') else 'warning',
                    'message': {'text': title},
                    'locations': [{'physicalLocation': {
                        'artifactLocation': {'uri': uri},
                        'region': {'startLine': int(it.get('line') or 1)},
                    }}],
                })
                rules_seen[rid] = title[:120]

                for key in ('also_detected_by', 'root_cause_merged'):
                    for m in (it.get(key) or []):
                        stats['merged_entries'] += 1
                        m_rule = m.get('rule_id') or m.get('name') or ''
                        if not m_rule:
                            stats['merged_no_rule'] += 1
                            continue
                        m_kind = m.get('sink_kind') or ''
                        m_title = str(m.get('title') or '')
                        if not m_kind and m_rule == 'E3-TAINT-JAVA-001':
                            m_kind = category_hint_from_title(m_title)
                            if m_kind:
                                stats['merged_by_title_keyword'] += 1
                        m_rid = rule_id_of(m_rule, m_kind, m_title)
                        if m_rid == rid:
                            stats['merged_duplicate_of_top'] += 1
                            continue
                        results.append({
                            'ruleId': m_rid,
                            'level': 'warning',
                            'message': {'text': m_title or ('also reported by %s' % m_rule)},
                            'locations': [{'physicalLocation': {
                                'artifactLocation': {'uri': uri},
                                'region': {'startLine': int(it.get('line') or 1)},
                            }}],
                            'properties': {'folded_into': rid},
                        })
                        rules_seen[m_rid] = m_title[:120] or rules_seen.get(m_rid, '')

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/'
                   'Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'Xinpect', 'version': version,
                'informationUri': 'https://xinpect.xingwangzhineng.com',
                'rules': [{'id': rid, 'shortDescription': {'text': desc}}
                          for rid, desc in sorted(rules_seen.items())],
            }},
            'results': results,
            'properties': {
                'corpus': 'OWASP Benchmark v1.2',
                'transform': 'bench/collect.py sarif',
                'top_level_issues': stats['issues'],
                'folded_entries': stats['merged_entries'],
                'folded_classified_by_title_keyword': stats['merged_by_title_keyword'],
                'folded_without_rule': stats['merged_no_rule'],
                'folded_duplicate_dropped': stats['merged_duplicate_of_top'],
                'results_written': len(results),
            },
        }],
    }
    # newline='' keeps the newlines as they are on Windows too. Without it the
    # same raw file produces a byte-different SARIF depending on the OS, and
    # "rerun the transform and you get the same file" stops being true.
    with open(args.out, 'w', encoding='utf-8', newline='') as fh:
        json.dump(sarif, fh, ensure_ascii=False, indent=1)

    print('cases=%d  top-level issues=%d  folded entries=%d (by title keyword: %d)'
          % (stats['cases'], stats['issues'], stats['merged_entries'],
             stats['merged_by_title_keyword']))
    print('results written=%d  distinct rule ids=%d' % (len(results), len(rules_seen)))
    print('rule ids:')
    for rid in sorted(rules_seen):
        print('  %-40s %s' % (rid, rules_seen[rid]))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('scan', help='scan the corpus and store raw issues')
    s.add_argument('--port', type=int, default=8620)
    s.add_argument('--key', required=True)
    s.add_argument('--out', required=True)
    s.add_argument('--expect-cases', type=int, default=2740)
    s.add_argument('--limit', type=int, default=0, help='only the first N cases (for a smoke test)')
    s.add_argument('--resume', action='store_true',
                   help='skip cases already present in --out (a killed run can continue)')
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser('sarif', help='transform raw issues into one SARIF file')
    t.add_argument('--raw', required=True)
    t.add_argument('--out', required=True)
    t.set_defaults(func=cmd_sarif)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
