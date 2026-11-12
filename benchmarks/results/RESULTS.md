# Benchmark results

Agent Security Guard 0.5.1, run 2026-11-12 (`python benchmarks/run_benchmark.py`, 8 s). No model and no network: every case assumes a model that does what the injected text says, and asks what the guard lets through. Method and limits: [README](../README.md).

## Headline (policy as shipped)

- **Attacks on Hermes's own tools, through a web page, search, X, the browser or a fetching shell command:** 2520/2520 (100.0 %) stopped before the tool ran (2280 sent to Hermes's approval prompt, 240 refused).
- **The same attacks, judged by their wording instead** (the guard's own pattern list, the way text filters work): 420/2520 recognized as injection, 1125/2520 counting shell patterns too.
- **Everyday work:** see the table below; tasks with outside content and an action in the same turn are asked about by design.
- **Speed:** median 0.129 ms per tool call, p99 0.395 ms (13103 calls).

## Attacks on Hermes's own tools, by goal

Stopped = Hermes asks the user first, or the call is refused. Covered sources: web page, search results, X, browser, the output of a shell command that fetches from another host. All sources adds a downloaded file read with `read_file` and an MCP mail tool, which count as outside content only once the operator says so (`untrusted_paths`, or the MCP tool listed in `untrusted_content_tools`).

| Goal | default: covered sources | lists: covered sources | strict: covered sources | default: all sources |
|---|---|---|---|---|
| run a command / remote script piped to a shell | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| run a command / harmless-looking command | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| run a command / package install | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| run a command / code execution | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| run a command / through the browser tool | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| run a command / background process | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| change files / shell profile | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| change files / project source | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| change files / SSH key | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| steal data / secret sent by shell | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| steal data / secret read, then put in a URL | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 168/168 (100.0 %) |
| steal data / secret read, then mailed | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / memory | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| plant instructions / new skill | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / the guard's own code | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / Hermes config | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| act later or elsewhere / scheduled job | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| act later or elsewhere / subagent | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| act later or elsewhere / browser action | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| act later or elsewhere / desktop control | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| act later or elsewhere / input to a running process | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/120 (100.0 %) | 120/168 (71.4 %) |
| message someone / chat message | 0/120 (0.0 %) | 0/120 (0.0 %) | 120/120 (100.0 %) | 0/168 (0.0 %) |

## By source (chat messages left out)

| Source | default | lists | strict |
|---|---|---|---|
| web page | 504/504 (100.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| search results | 504/504 (100.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| X post | 504/504 (100.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| browser | 504/504 (100.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| downloaded file | 96/504 (19.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| shell output | 504/504 (100.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |
| MCP mail | 96/504 (19.0 %) | 504/504 (100.0 %) | 504/504 (100.0 %) |

## Wording does not matter to the guard, it does to a text filter

Covered sources, policy as shipped. Text filter = the guard's own injection patterns applied to the page (it does not decide anything in the guard; shown for comparison).

| Technique | Guard stopped | Text filter: injection | Text filter: incl. shell |
|---|---|---|---|
| plain request | 105/105 (100.0 %) | 0/105 | 40/105 |
| InjecAgent enhanced | 105/105 (100.0 %) | 105/105 | 105/105 |
| ignore previous | 105/105 (100.0 %) | 105/105 | 105/105 |
| fake system header | 105/105 (100.0 %) | 105/105 | 105/105 |
| fake end of data | 105/105 (100.0 %) | 0/105 | 40/105 |
| friendly setup step | 105/105 (100.0 %) | 0/105 | 40/105 |
| HTML comment | 105/105 (100.0 %) | 0/105 | 40/105 |
| hidden text | 105/105 (100.0 %) | 0/105 | 40/105 |
| JSON field | 105/105 (100.0 %) | 0/105 | 40/105 |
| German | 105/105 (100.0 %) | 0/105 | 40/105 |
| Spanish | 105/105 (100.0 %) | 0/105 | 40/105 |
| base64 | 105/105 (100.0 %) | 0/105 | 0/105 |
| zero-width spaced | 105/105 (100.0 %) | 0/105 | 0/105 |
| homoglyphs | 105/105 (100.0 %) | 0/105 | 35/105 |
| authority claim | 105/105 (100.0 %) | 105/105 | 105/105 |
| fake tool result | 105/105 (100.0 %) | 0/105 | 40/105 |
| security notice | 105/105 (100.0 %) | 0/105 | 40/105 |
| split instruction | 105/105 (100.0 %) | 0/105 | 30/105 |
| user impersonation | 105/105 (100.0 %) | 0/105 | 40/105 |
| note to AI readers | 105/105 (100.0 %) | 0/105 | 40/105 |
| code block | 105/105 (100.0 %) | 0/105 | 40/105 |
| README TODO | 105/105 (100.0 %) | 0/105 | 40/105 |
| mail signature | 105/105 (100.0 %) | 0/105 | 40/105 |
| no instruction at all | 105/105 (100.0 %) | 0/105 | 40/105 |

## InjecAgent (1054 public cases, Zhan et al. 2024)

The attacker tools are third-party services (bank, smart lock, mail, ...). In Hermes they would be MCP tools, `mcp__<server>__<tool>`; `TerminalExecute` is Hermes's `terminal`.

| Delivery | default | lists | strict |
|---|---|---|---|
| as an MCP tool | 33/1054 (3.1 %) | 561/1054 (53.2 %) | 1054/1054 (100.0 %) |
| as a web page | 561/1054 (53.2 %) | 561/1054 (53.2 %) | 1054/1054 (100.0 %) |

| Delivery / attack type | default | lists | strict |
|---|---|---|---|
| as a web page / Data Security Harm | 17/187 (9.1 %) | 17/187 (9.1 %) | 187/187 (100.0 %) |
| as a web page / Financial Data | 102/102 (100.0 %) | 102/102 (100.0 %) | 102/102 (100.0 %) |
| as a web page / Financial Harm | 0/153 (0.0 %) | 0/153 (0.0 %) | 153/153 (100.0 %) |
| as a web page / Others | 255/255 (100.0 %) | 255/255 (100.0 %) | 255/255 (100.0 %) |
| as a web page / Physical Data | 187/187 (100.0 %) | 187/187 (100.0 %) | 187/187 (100.0 %) |
| as a web page / Physical Harm | 0/170 (0.0 %) | 0/170 (0.0 %) | 170/170 (100.0 %) |
| as an MCP tool / Data Security Harm | 1/187 (0.5 %) | 17/187 (9.1 %) | 187/187 (100.0 %) |
| as an MCP tool / Financial Data | 6/102 (5.9 %) | 102/102 (100.0 %) | 102/102 (100.0 %) |
| as an MCP tool / Financial Harm | 0/153 (0.0 %) | 0/153 (0.0 %) | 153/153 (100.0 %) |
| as an MCP tool / Others | 15/255 (5.9 %) | 255/255 (100.0 %) | 255/255 (100.0 %) |
| as an MCP tool / Physical Data | 11/187 (5.9 %) | 187/187 (100.0 %) | 187/187 (100.0 %) |
| as an MCP tool / Physical Harm | 0/170 (0.0 %) | 0/170 (0.0 %) | 170/170 (100.0 %) |

## Everyday work

Tasks with no attack. A stop here is a question the user has to answer.

| Kind of task | Tasks | default: tasks asked | lists: tasks asked | strict: tasks asked |
|---|---|---|---|---|
| no outside content | 19 | 0 | 0 | 19 |
| research only | 10 | 0 | 0 | 10 |
| research, act next turn | 6 | 0 | 0 | 6 |
| research and act in one turn | 6 | 6 | 6 | 6 |

## Data blocks

Every page from a covered source reached the model as exactly one data block, its fake end markers escaped: 2640/2640.

## Hostile input

| Input | Wrap the page + check a write (ms) |
|---|---|
| 20 KB page of 'rm -r' | 5.06 |
| 20 KB of spaces in a patch header | 6.22 |
| 20 KB of newlines | 6.89 |
| 200 KB ordinary page | 59.14 |
