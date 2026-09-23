# Draft X / Twitter posts (NOT posted — for your review only)

Read the note at the bottom before posting anything. Replace every
`[bracketed]` placeholder first.

---

## English thread (recommended primary — GitHub/OSS audience on X skews English)

**1/**
Shipped a small OSS tool: `auditrail` — a tamper-evident audit trail +
"lethal trifecta" policy guard for AI agents.

EchoLeak, Slack AI, ForcedLeak, the GitHub MCP leak, Replit's deleted
prod DB — different products, same shape. This targets that shape.

🔗 [github.com/REPLACE_ME/auditrail]

**2/**
The "lethal trifecta" (h/t @simonw): an agent session with (1) private
data access + (2) untrusted content + (3) external comms, all at once,
is how prompt injection becomes real exfiltration.

auditrail refuses the 3rd tool call *before it runs* if 1+2 are already
in the session.

**3/**
Every allow/deny/sandboxed decision is appended to a hash-chained
evidence log (same construction as Certificate Transparency). Tamper
with one record and `auditrail verify` tells you exactly which one.

Args/results are stored as digests only — the log itself was never
meant to become the next thing that leaks.

**4/**
It also signs agent-to-agent messages (HMAC + replay protection) —
OWASP's Top 10 for Agentic Applications 2026 calls this "insecure
inter-agent communication" (ASI07).

**5/**
v0.1. Proof of concept. No PyPI release yet, no independent security
review, isolation is process-level not container-level — all of that is
written down honestly in SECURITY.md, not buried.

Wraps your real tool functions in ~5 lines. No API key needed to try the
demo: `python -m examples.mock_demo`

**6/**
Built this out of a longer research pass on the AI-security/audit
landscape — incidents, regulation (NYC LL144, EU AI Act, Taiwan's AI
Basic Act), and where the actual gaps are vs. what's already well served.

If you're building/auditing agents and this is useful or wrong about
something, I'd genuinely like to hear it. Issues and PRs open.

---

## Traditional Chinese thread（次要，給中文圈受眾）

**1/**
做了一個小型開源工具：`auditrail`——給 AI 代理用的防篡改稽核日誌 +
「致命三要素」政策防護。

EchoLeak、Slack AI、ForcedLeak、GitHub MCP 洩露、Replit 刪除正式資料庫——
產品不同，結構相同。這個工具就是針對這個結構做的。

🔗 [github.com/REPLACE_ME/auditrail]

**2/**
「致命三要素」（lethal trifecta，概念來自 Simon Willison）：一個 AI
代理的工作階段同時擁有（1）私人資料存取、（2）不可信內容、（3）對外通訊——
提示注入就會變成真正的資料外洩。

auditrail 會在完成第三項之前直接擋下，不是事後才發現。

**3/**
每一次允許／拒絕／沙盒執行的決策，都會寫進一份雜湊鏈結的證據日誌（跟
Certificate Transparency 用的是同一種結構）。動過其中一筆，
`auditrail verify` 會直接告訴你是哪一筆。

日誌只存參數與結果的雜湊，不存明文——避免日誌本身變成下一個外洩來源。

**4/**
也處理代理跟代理之間的通訊：HMAC 簽章 + 防重放。這正是 OWASP
《Top 10 for Agentic Applications 2026》講的「不安全的代理間通訊」（ASI07）。

**5/**
v0.1，概念驗證階段。還沒上 PyPI、沒有第三方資安審查、沙盒目前只是
process 層級不是容器層級——這些限制都老實寫在 SECURITY.md，沒有藏起來。

包一個現有的工具函式只要五行。不需要金鑰就能跑 demo：
`python -m examples.mock_demo`

**6/**
這是我做完一輪 AI 資安／稽核產業研究後的產出——事件、各國法規
（美國 LL144、歐盟 AI Act、台灣人工智慧基本法）、以及市場上到底還缺什麼。

如果你在做或在稽核 AI 代理，覺得這東西有用、或哪裡想錯了，都歡迎講。
Issue 跟 PR 都開放。

---

## Notes before you post

1. Replace `[github.com/REPLACE_ME/auditrail]` with the real repo URL
   once it exists (see the checklist in chat for what needs to happen
   first: repo created, code pushed, CI green).
2. Consider posting the English thread from the account/handle you want
   associated with this project long-term — GitHub stars and follows
   compound on whichever identity posts first.
3. Pin the repo link in your profile if this is meant to represent the
   company going forward.
4. I have not posted anything — these are drafts for you to review, edit,
   and post yourself (or explicitly tell me to post, from your logged-in
   session, if you want help with that instead).
