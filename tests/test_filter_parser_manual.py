import sys, logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
sys.path.insert(0, r'C:\void.access\ezio')
from ezio.llm import _parse_filter_response, _heuristic_filter

cases = [
    ('[1, 4, 7, 12]',                       [1, 4, 7, 12]),
    ('```json\n[1, 4, 7]\n```',              [1, 4, 7]),
    ('I recommend [1, 2, 5]',               [1, 2, 5]),
    ('Based on 15 results: [1,2,3]',        [1, 2, 3]),
    ('1, 4, 8, 9, 10',                      [1, 4, 8, 9, 10]),
    ('garbage response xyz',                list(range(1, 16))),
]

print('=== _parse_filter_response tests ===')
all_pass = True
for response, expected in cases:
    result = _parse_filter_response(response, max_index=20, top_n=15)
    ok = result == expected
    all_pass = all_pass and ok
    status = 'PASS' if ok else 'FAIL'
    print(f'{status} | input={response[:40]!r}')
    if not ok:
        print(f'       expected: {expected}')
        print(f'       got:      {result}')

print()
print('=== Heuristic filter test (no-llm) ===')
mock_results = [
    {'link': 'http://searchengine.onion/index?q=foo',          'title': 'Index',                   'content': 'x'*100},
    {'link': 'http://abcmarket.onion/product/lockbit-leak',    'title': 'LockBit ransomware leak', 'content': 'x'*3000},
    {'link': 'http://forumsearch.onion/directory',             'title': 'Directory',               'content': 'x'*200},
    {'link': 'http://xyzcorp.onion/about',                     'title': 'About us',                'content': 'x'*150},
    {'link': 'http://ransomwatcher.onion/lockbit-report',      'title': 'Cobalt LockBit analysis', 'content': 'x'*2500},
    {'link': 'http://clearnet-example.com/lockbit-info',       'title': 'LockBit info',            'content': 'x'*1200},
    {'link': 'http://badorphan.onion/home',                    'title': 'Home',                    'content': 'x'*50},
    {'link': 'http://news.onion/cobalt-strike-vendor',         'title': 'Cobalt Strike vendor',    'content': 'x'*1800},
    # Extra substantive pages so the noise URLs get pushed out of the top 5.
    {'link': 'http://threatintel.onion/lockbit-cobalt-strike-ttps',  'title': 'LockBit and Cobalt Strike TTPs',     'content': 'x'*4000},
    {'link': 'http://analyst.onion/lockbit-ransomware-deepdive',      'title': 'LockBit ransomware deep dive',        'content': 'x'*3500},
    {'link': 'http://clearnet-mag.com/lockbit-cobalt-strike-attack',  'title': 'LockBit Cobalt Strike attack chain',  'content': 'x'*2800},
]
picked = _heuristic_filter(mock_results, query='cobalt strike lockbit', top_n=5)
picked_links = [mock_results[i-1]['link'] for i in picked]
print('Picked indexes:', picked)
print('Picked URLs:')
for url in picked_links:
    print(f'  - {url}')

bad_keywords = ['/index', '/directory', '/home', '/about']
bad_present = [u for u in picked_links if any(b in u for b in bad_keywords)]
if bad_present:
    print('FAIL: noise URLs made it into top picks:', bad_present)
    all_pass = False
else:
    print('PASS: no index/directory/home/about URLs in top picks')

print()
print('=== Overall ===')
print('ALL PASS' if all_pass else 'SOME FAILED')
