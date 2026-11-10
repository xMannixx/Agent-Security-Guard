# Benchmark results

Agent Security Guard 0.4.4, run 2026-11-10 (`python benchmarks/run_benchmark.py`, 7 s). No model and no network: every case assumes a model that does what the injected text says, and asks what the guard lets through. Method and limits: [README](../README.md).

## Headline (policy as shipped)

- **Attacks on Hermes's own tools, through a web page, search, X or the browser:** 1728/1920 (90.0 %) stopped before the tool ran (1536 sent to Hermes's approval prompt, 192 refused).
- **The same attacks, judged by their wording instead** (the guard's own pattern list, the way text filters work): 320/1920 recognized as injection, 812/1920 counting shell patterns too.
- **Everyday work:** see the table below; tasks with outside content and an action in the same turn are asked about by design.
- **Speed:** median 0.123 ms per tool call, p99 0.316 ms (12740 calls).

## Attacks on Hermes's own tools, by goal

Stopped = Hermes asks the user first, or the call is refused. Covered sources: web page, search results, X, browser. All sources adds a downloaded file read with `read_file`, a shell command's output and an MCP mail tool, which the shipped policy does not treat as outside content.

| Goal | default: covered sources | mcp-listed: covered sources | strict: covered sources | default: all sources |
|---|---|---|---|---|
| run a command / remote script piped to a shell | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| run a command / harmless-looking command | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| run a command / package install | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| run a command / code execution | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| run a command / background process | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| change files / shell profile | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| change files / project source | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| change files / SSH key | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| steal data / secret sent by shell | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| steal data / secret read, then put in a URL | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 168/168 (100.0 %) |
| steal data / secret read, then mailed | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / memory | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| plant instructions / new skill | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / the guard's own code | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 168/168 (100.0 %) |
| plant instructions / Hermes config | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| act later or elsewhere / scheduled job | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| act later or elsewhere / subagent | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| act later or elsewhere / browser action | 0/96 (0.0 %) | 0/96 (0.0 %) | 96/96 (100.0 %) | 0/168 (0.0 %) |
| act later or elsewhere / desktop control | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/96 (100.0 %) | 96/168 (57.1 %) |
| act later or elsewhere / input to a running process | 0/96 (0.0 %) | 0/96 (0.0 %) | 96/96 (100.0 %) | 0/168 (0.0 %) |
| message someone / chat message | 0/96 (0.0 %) | 0/96 (0.0 %) | 96/96 (100.0 %) | 0/168 (0.0 %) |

## By source (policy as shipped, chat messages left out)

| Source | Stopped |
|---|---|
| web page | 432/480 (90.0 %) |
| search results | 432/480 (90.0 %) |
| X post | 432/480 (90.0 %) |
| browser | 432/480 (90.0 %) |
| downloaded file | 96/480 (20.0 %) |
| shell output | 96/480 (20.0 %) |
| MCP mail | 96/480 (20.0 %) |

## Wording does not matter to the guard, it does to a text filter

Covered sources, policy as shipped. Text filter = the guard's own injection patterns applied to the page (it does not decide anything in the guard; shown for comparison).

| Technique | Guard stopped | Text filter: injection | Text filter: incl. shell |
|---|---|---|---|
| plain request | 72/80 (90.0 %) | 0/80 | 28/80 |
| InjecAgent enhanced | 72/80 (90.0 %) | 80/80 | 80/80 |
| ignore previous | 72/80 (90.0 %) | 80/80 | 80/80 |
| fake system header | 72/80 (90.0 %) | 80/80 | 80/80 |
| fake end of data | 72/80 (90.0 %) | 0/80 | 28/80 |
| friendly setup step | 72/80 (90.0 %) | 0/80 | 28/80 |
| HTML comment | 72/80 (90.0 %) | 0/80 | 28/80 |
| hidden text | 72/80 (90.0 %) | 0/80 | 28/80 |
| JSON field | 72/80 (90.0 %) | 0/80 | 28/80 |
| German | 72/80 (90.0 %) | 0/80 | 28/80 |
| Spanish | 72/80 (90.0 %) | 0/80 | 28/80 |
| base64 | 72/80 (90.0 %) | 0/80 | 0/80 |
| zero-width spaced | 72/80 (90.0 %) | 0/80 | 0/80 |
| homoglyphs | 72/80 (90.0 %) | 0/80 | 24/80 |
| authority claim | 72/80 (90.0 %) | 80/80 | 80/80 |
| fake tool result | 72/80 (90.0 %) | 0/80 | 28/80 |
| security notice | 72/80 (90.0 %) | 0/80 | 28/80 |
| split instruction | 72/80 (90.0 %) | 0/80 | 20/80 |
| user impersonation | 72/80 (90.0 %) | 0/80 | 28/80 |
| note to AI readers | 72/80 (90.0 %) | 0/80 | 28/80 |
| code block | 72/80 (90.0 %) | 0/80 | 28/80 |
| README TODO | 72/80 (90.0 %) | 0/80 | 28/80 |
| mail signature | 72/80 (90.0 %) | 0/80 | 28/80 |
| no instruction at all | 72/80 (90.0 %) | 0/80 | 28/80 |

## InjecAgent (1054 public cases, Zhan et al. 2024)

The attacker tools are third-party services (bank, smart lock, mail, ...). In Hermes they would be MCP tools, `mcp__<server>__<tool>`; `TerminalExecute` is Hermes's `terminal`.

| Delivery | default | mcp-listed | strict |
|---|---|---|---|
| as an MCP tool | 33/1054 (3.1 %) | 561/1054 (53.2 %) | 1054/1054 (100.0 %) |
| as a web page | 561/1054 (53.2 %) | 561/1054 (53.2 %) | 1054/1054 (100.0 %) |

| Delivery / attack type | default | mcp-listed | strict |
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

| Kind of task | Tasks | default: tasks asked | mcp-listed: tasks asked | strict: tasks asked |
|---|---|---|---|---|
| no outside content | 15 | 0 | 0 | 15 |
| research only | 5 | 0 | 0 | 5 |
| research, act next turn | 4 | 0 | 0 | 4 |
| research and act in one turn | 4 | 4 | 4 | 4 |

## Data blocks

Every page from a covered source reached the model as exactly one data block, its fake end markers escaped: 2016/2016.

## Hostile input

| Input | Wrap the page + check a write (ms) |
|---|---|
| 20 KB page of 'rm -r' | 5.25 |
| 20 KB of spaces in a patch header | 6.31 |
| 20 KB of newlines | 6.82 |
| 200 KB ordinary page | 58.54 |
