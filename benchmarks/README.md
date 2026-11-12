# Benchmark: what the guard stops, and what it costs

```bash
python benchmarks/run_benchmark.py
```

The run takes under ten seconds on a laptop and needs nothing besides Python 3.8+.
It writes [`results/RESULTS.md`](results/RESULTS.md) (tables) and
`results/summary.json`; `results/cases.jsonl` (every case, about 5 MB) is
regenerated on each run and not kept in git.

## The question

An agent reads a page, and the page tells it to do something. Most models
often refuse. This benchmark assumes **the worst model: one that always does
what the injected text says.** It then counts what Agent Security Guard lets
through. What the model would have done on its own is not measured.

"Stopped" means Hermes does not run the tool on its own: either the call goes
to Hermes's approval prompt (the user decides) or the guard refuses it.

## What is measured

1. **Attacks on Hermes's own tools: 22 goals × 7 sources × 24 techniques
   (3,696 cases).**
   - **Goals.** What the page wants done: run a command, change files, steal
     a secret, plant instructions (memory, skills, the guard's own code,
     Hermes's config), act later or elsewhere (cron job, subagent, browser,
     desktop, a running process), and send a chat message. Each goal is
     written as the tool calls a compliant model would make in Hermes:
     `terminal`, `execute_code`, `write_file`, `patch`, `memory`,
     `skill_manage`, `cronjob_manage`, `delegate_task`, `browser_exec`,
     `computer_use`, `process_manage`, `send_message`, and for mail an MCP
     tool.
   - **Sources.** How the content arrives:
     - the five the shipped policy treats as outside content: `web_extract`,
       `web_search`, `x_search`, `browser_exec`, and the output of a shell
       command that fetches from another host (`curl`);
     - two that count once the operator says so: a downloaded file read with
       `read_file` (`untrusted_paths`), and an MCP mail tool (listed in
       `untrusted_content_tools`).
   - **Techniques.** 24 phrasings and disguises: the two InjecAgent forms,
     "ignore previous", fake system headers, fake end-of-data markers, a
     friendly setup step, HTML comments, hidden text, JSON fields, German,
     Spanish, base64, zero-width characters, homoglyphs, authority claims,
     fake tool results, split instructions, impersonating the user, and a
     bare command with no instruction at all.
2. **[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)**
   (Zhan et al., *Findings of ACL 2024*): all 1,054 base cases, 62 attacker
   instructions placed in 17 tool responses, built the way the paper builds
   them. The data in `data/injecagent/` is unchanged from the authors'
   repository (MIT, commit `f19c9f2`); `tool_names.json` splits their tool
   names into toolkit and tool.
   - Their attacker tools are third-party services: bank, smart lock, mail,
     health records, and so on. In Hermes such tools come in through MCP as
     `mcp__<server>__<tool>`; their `TerminalExecute` is Hermes's `terminal`.
   - Each case is run twice: delivered by the MCP tool it names, and
     delivered as a web page.
3. **Everyday work.** 42 tasks with no attack, from "run the tests" to
   "read the docs, then install it". Here a stop is a question the user did
   not need.
4. **Data blocks.** Every page from a covered source must reach the model as
   exactly one data block, with its fake end markers escaped.
5. **Speed.** Time per tool call over every case, and 20 KB of hostile input
   (the patterns made linear in 0.4.3).

Everything runs under three policies, each in a process of its own with an
empty home:

- the policy as shipped;
- `lists`: as shipped plus `mcp__*` in `untrusted_content_tools` and
  `~/Downloads/` in `untrusted_paths` (two lines);
- `mode: strict`.

## How Hermes is reproduced

[`hermes_sim.py`](hermes_sim.py) calls the plugin's three hooks the way
hermes-agent `3b42157858` (2026-11-09) does:

- the same keyword arguments;
- turn ids of Hermes's shape, one user turn being one chain;
- Hermes's rule for reading a `pre_tool_call` result: `block` with a message
  vetoes the call, `approve` goes to the approval prompt, and `block` wins.

No Hermes process, model or network is involved, so every number is exactly
reproducible. Nothing is executed either: commands, paths and addresses only
reach the guard's hook, which decides before a tool would run. Domains are
under `.example`, and secrets are made up.

## Results (0.5.1, policy as shipped)

Full tables: [`results/RESULTS.md`](results/RESULTS.md).

| | |
|---|---|
| Attacks on Hermes's own tools through web, search, X, the browser or a `curl` (chat messages left out, see below) | **2,520 / 2,520 stopped** |
| the same in 0.4.4 (four sources then, 1,920 cases) | 1,728 / 1,920 (90.0 %) |
| Does the phrasing change the result? | **No.** Each of the 24 techniques: 105 / 105 |
| The same pages judged by their wording (the guard's own injection patterns) | 420 / 2,520 recognized (16.7 %); with shell patterns 1,125 (44.6 %) |
| InjecAgent delivered as a web page | 561 / 1,054 (53.2 %); `mode: strict` 1,054 |
| InjecAgent delivered by MCP | 33 / 1,054 (3.1 %); `mcp__*` listed 561; `mode: strict` 1,054 |
| Everyday tasks asked about, with no outside content in the turn | **0 / 19** |
| Research only, or research and then act in the next turn | **0 / 16** |
| Research and act in the same turn | 6 / 6 (by design, see below) |
| Pages reaching the model as one intact data block | 2,640 / 2,640 |
| Time per tool call | median 0.14 ms, p99 0.41 ms |

The text-filter row is a comparison, not part of the guard: the guard decides
by *where* content came from and *what* the next call does, never by how the
page is worded. A filter that looks for attack phrases sees the
`ignore previous` kind and misses a polite setup step, a JSON field or
another language. The comparison uses the guard's own pattern list because
it is at hand; a better filter would score higher, but it would still depend
on the wording.

## What it does not stop, measured

- **Chat messages.**
  - What it misses: `send_message` is audited, not stopped. 0 / 96.
  - Why it stays: on Hermes it is how the agent answers its own user. This
    is deliberate.
- **Outside content the operator has not named.**
  - What it misses: a downloaded file read with `read_file`, and the result
    of an MCP tool, unless the download folder is in `untrusted_paths` or the
    tool is listed in `untrusted_content_tools`. 96 / 504 each.
  - What still works: the secret rules, and self-modification, which hold
    from every source.
- **Third-party (MCP) tools it does not know.**
  - What it misses: an MCP tool that writes (a bank transfer, a door
    unlock) stays free after outside content. InjecAgent via web page 561 /
    1,054; the rest are such tools.
  - What closes it: `tool_tiers` for the tools, or `mode: strict` (1,054 /
    1,054). 0.5.0 read which tools declare `readOnlyHint` from Hermes's
    private MCP registry; the plugin catalog allows public surfaces only, so
    0.5.1 does not.
- **The browser tool's code is judged by an allow-list.**
  - It is read, not run. It fails towards asking, but it is a check of the
    code, not a sandbox.
- **"Asked" still needs a "no".** "Allow for this session", or
  `hermes --yolo`, answers the prompt for the user.
- **Research and act in one turn is asked about.**
  - Example: "find the install command and run it", "clone this and run its
    tests".
  - Why: the page may be what proposes the action, and the guard cannot
    tell. This is the main cost of the design. The next turn starts clean.

## Limits of the benchmark itself

- **Attacks.** The Hermes attack set and the everyday tasks were written for
  this benchmark, which tests the guard's own design. InjecAgent is the
  outside reference, and mapping its tools onto Hermes's MCP naming is a
  choice made here.
- **No model.** The numbers say what the guard lets through when a model
  complies. They do not say how often a given model would comply.
- **Simulated hooks.** Hermes is reproduced at its plugin hooks, not run. The
  demo in [`docs/demo/`](../docs/demo/) shows the same decision in a real
  Hermes session.
