# Scoring changes in 1.1.0

These changes alter scores relative to v1.0.0. Anyone upgrading should expect
different verdicts for the user agents below. Thresholds are unchanged: block
at 0.75 or more, flag at 0.55, challenge at 0.40.

## Generic HTTP clients are weak evidence (issue #356)

`curl/`, `wget/`, `python-requests`, `python-httpx`, `aiohttp`, `Go-http-client`,
`Java/`, `okhttp` and `libwww-perl` no longer produce `ua_ai_bot`. They produce
`ua_generic_client` (value 0.5, weight 0.25). A bare `curl/8.5.0` request moves
from `block` (0.92, "known AI bot pattern") to `flag` (0.61). Scripts, monitors
and developers use these clients, so a client string alone is no longer a block.
`enrich_ua` reports 0.4 for them.

## Bare "bot", "crawler" and "spider" no longer match (issue #357)

`ua_scraper` matched any user agent containing "bot", "crawler" or "spider", which
blocked Googlebot, Bingbot, UptimeRobot and Slackbot. Those words are removed.
Named automation tools (sqlmap, nikto, masscan, scrapy, selenium, puppeteer,
playwright, headless browsers and similar) still match. Named AI crawlers are now
listed explicitly in `ua_ai_bot`, including ClaudeBot, Claude-User, OAI-SearchBot,
Amazonbot, Applebot-Extended, meta-externalagent, Diffbot and Perplexity-User.

Request Guard cannot verify who a client is. A user agent that claims to be
Googlebot gets no special trust from this service, and one that does not look like
a bot gets none of the bot signals either. Verify crawler identity with reverse
DNS and forward confirmation in the caller. Renaming a user agent still evades
user-agent rules.

Side effect: a user agent with a "/" and no "Mozilla" (for example Slackbot's) still
gets `ua_non_browser` and scores 0.70 (`flag`).

## Optional robots.txt violation signal (issue #360)

`classify` accepts an optional boolean `robots_violation`. See
[tool contracts](tool-contracts.md). It adds the `robots_violation` signal
(value 1.0, weight 0.9). Omitted or `false` changes no score. A browser user agent
on an ordinary path with the flag set scores 1.00 (`block`). The cache namespace
marker moved to `classification-v4` so no v1.0.0 verdict is reused.

## Before and after (same requests, real `classify` tool)

| Request | v1.0.0 / main before | After |
|---|---|---|
| curl/8.5.0 | block 0.92 | flag 0.61 |
| python-requests, wget, Go-http-client | block 0.92 | flag 0.61 |
| GPTBot/1.1 | block 0.92 | block 0.92 |
| ClaudeBot | block 1.00 (as scraper) | block 1.00 (as AI bot) |
| Googlebot, Bingbot, UptimeRobot | block 1.00 | allow 0.00 |
| Slackbot | block 0.91 | flag 0.70 |
| sqlmap/1.8 | block 0.91 | block 0.91 |
| Firefox on /pricing | allow 0.00 | allow 0.00 |
| Firefox on /admin | block 1.00 | block 1.00 |
| Firefox on /private/reports, robots_violation=true | rejected (-400) | block 1.00 |
