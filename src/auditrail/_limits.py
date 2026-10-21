"""Generated from SECURITY.md by tools/gen_limits.py. Do not edit.

The bold lead sentence of every limit in SECURITY.md ("What v0.2 does NOT do" and "Where the tests do not
reach"), and the SHA-256 of the SECURITY.md text (line endings normalised to LF) they were taken from."""

SOURCE_SHA256 = '54e2e3393e9662e4f2130dd21be6bdff560db3caf8ddd0e0f6cb6f7eefa8c694'

ITEMS = (
    ('About the evidence', 'It cannot prove a tool call was recorded if the tool was never wrapped.'),
    ('About the evidence', 'Records after the last anchor are not covered.'),
    ('About the evidence', 'Nothing helps if the recorder host or key is compromised.'),
    ('About the evidence', 'The witness must be independent.'),
    ('About the evidence', 'Anchors you never publish prove nothing.'),
    ('About the evidence', 'No dependency on trusted time.'),
    ('About the evidence', 'Args and results are stored as digests only.'),
    ('About the policy and messages', 'No prompt-injection detection, and none of the content of a message is judged.'),
    ('About the policy and messages', 'The trifecta rule is category-based and the categories are labelled by you.'),
    ('About the policy and messages', 'Workflow tracking needs the link.'),
    ('About the policy and messages', 'Categories that arrive with a signed message are counted, not name-checked.'),
    ('About the policy and messages', 'Messages need your key registry to be right.'),
    ('About the policy and messages', 'Replay protection is in memory by default.'),
    ('About isolation', '`isolate=True` is not a sandbox.'),
    ('About isolation', 'The environment filter is an allow-list'),
    ('About scope', 'No supply-chain verification (ASI04), no memory/context-poisoning detection (ASI06), no cascading-failure containment (ASI08)'),
    ('About scope', 'No steganography detection.'),
    ('About scope', "`auditrail report` is a rendering of the verifier's output, not new evidence."),
    ('About scope', 'Not a certified compliance product.'),
    ('Where the tests do not reach', 'Inconclusive results and the algorithm-mismatch rule.'),
    ('Where the tests do not reach', 'Algorithm agility is reserved, not implemented.'),
    ('Where the tests do not reach', 'Platforms.'),
    ('Where the tests do not reach', 'Constant-time token comparison.'),
    ('Where the tests do not reach', 'Key rotation (Key custody, step 5).'),
    ('Where the tests do not reach', 'Timestamping services as a witness.'),
    ('Where the tests do not reach', 'The release workflow'),
    ('Where the tests do not reach', 'Tests that need the Rust binary'),
    ('Where the tests do not reach', 'The Windows ACL check'),
    ('Where the tests do not reach', 'Key files.'),
    ('Where the tests do not reach', 'Cross-section label consistency is enforced when a tool is wrapped'),
    ('Where the tests do not reach', 'Duplicate YAML keys are not reported'),
    ('Where the tests do not reach', 'Shutdown paths not exercised'),
)
