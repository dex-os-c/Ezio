import sys, logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(name)s: %(message)s')
sys.path.insert(0, r'C:\void.access\ezio')

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from ezio.llm import filter_results


def make_mock_llm(response):
    """FakeListChatModel returns canned messages; StrOutputParser reads .content."""
    return FakeListChatModel(responses=[response])


mock_results = [
    {'link': f'http://example{i}.onion/page{i}', 'title': f'Page {i}', 'content': 'x' * (100 * i)}
    for i in range(1, 21)
]

print('--- Test 1: LLM returns clean JSON ---')
llm = make_mock_llm('[1, 4, 7, 12]')
out = filter_results(llm, 'lockbit ransomware', mock_results, top_n=15)
print('Got', len(out), 'results')
print('First 3 picked URLs:', [r['link'] for r in out[:3]])

print()
print('--- Test 2: LLM returns preamble + JSON (old behavior would extract "15" too) ---')
llm = make_mock_llm('Based on my analysis of the 15 results, I recommend indexes [1, 2, 5]')
out = filter_results(llm, 'cobalt strike', mock_results, top_n=15)
print('Got', len(out), 'results')
print('First 3 picked URLs:', [r['link'] for r in out[:3]])
assert len(out) == 3, f"Expected 3 results, got {len(out)}"
print('OK: only 3 pages picked, "15" was correctly excluded')

print()
print('--- Test 3: LLM returns nothing parseable → falls back to first-N ---')
llm = make_mock_llm('garbage response xyz')
out = filter_results(llm, 'apt29', mock_results, top_n=15)
print('Got', len(out), 'results')
assert len(out) == 15, f"Expected 15 fallback, got {len(out)}"
print('OK: 15 fallback results')

print()
print('--- Test 4: llm=None → heuristic filter ---')
out = filter_results(None, 'cobalt strike lockbit', mock_results, top_n=15)
print('Got', len(out), 'results')
assert len(out) == 15, f"Expected 15 heuristic, got {len(out)}"
print('OK: 15 heuristic results')

print()
print('All end-to-end tests passed.')
