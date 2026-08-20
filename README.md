# ARGUS - Automated Response & Guided Unified Security

CLI-based automated Incident Response analysis pipeline.

Named after Argus Panoptes, the all-seeing giant of Greek mythology with 100 eyes.

## Features

- Multi-format evidence ingestion (EVTX, Excel, IIS logs, PCAP, memory dumps, etc.)
- LLM-powered triage and deep analysis agents
- Forensic Validation Engine (FVE) - no hallucinations in final output
- Automated IOC extraction and enrichment
- MITRE ATT&CK mapping
- Sigma rule generation
- Professional PDF report output

## Installation

```bash
# Clone the repository
git clone https://github.com/Howard1x5/argus.git
cd argus

# Install in development mode
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## Quick Start

```bash
# First-time setup
argus setup

# Initialize a new case
argus init ./case-001

# Copy evidence to ./case-001/evidence/

# Run full analysis
argus analyze ./case-001

# Review report_draft.md, fill in analyst notes, then finalize
argus finalize ./case-001
```

## Commands

| Command | Description |
|---------|-------------|
| `argus init <path>` | Initialize new case directory |
| `argus analyze <path>` | Run full pipeline |
| `argus triage <path>` | Run triage phases only (0-2.5) |
| `argus report <path>` | Regenerate report from analysis |
| `argus finalize <path>` | Convert draft to PDF |
| `argus status <path>` | Show pipeline progress |
| `argus run-phase N <path>` | Re-run specific phase |
| `argus resume <path>` | Resume from last checkpoint |
| `argus enrich <path>` | Run IOC enrichment |
| `argus debrief <path>` | Post-case lessons learned |
| `argus list` | List tracked cases |
| `argus setup` | First-run configuration |

## Pipeline Phases

0. **INIT** - Case setup, evidence hashing
1. **INGEST** - Parse and normalize evidence
2. **TRIAGE** - Programmatic scan + LLM agents
3. **DEEP ANALYSIS** - 9 domain agents + synthesizer
4. **VALIDATION** - Forensic Validation Engine (pure programmatic)
5. **IOC EXTRACTION** - Extract and enrich indicators
6. **DETECTION** - MITRE mapping, Sigma rules
7. **REPORT** - Generate draft with analyst note placeholders
8. **PACKAGE** - Final deliverables

## Configuration

Configuration stored in `~/.argus/`:

- `config.yaml` - API keys (env var references), preferences
- `cases.log` - Case registry
- `pattern_library/` - Custom patterns and false positives

## LLM Backends

ARGUS routes every LLM call through `argus.llm_backend`, which supports two paths:

| Backend | How it runs | Cost |
|---------|-------------|------|
| `subscription` (default) | Shells out to the `claude` CLI (Claude Code) | No metered API charges |
| `api` | Anthropic Python SDK | Billed per token against `ANTHROPIC_API_KEY` |

Select a backend with the `ARGUS_LLM_BACKEND` environment variable, or the
`llm.backend` key in `~/.argus/config.yaml`. The environment variable wins.

```bash
# Default — no API key needed, uses your Claude subscription
argus analyze mycase

# Explicitly use the metered API instead
ARGUS_LLM_BACKEND=api argus analyze mycase
```

### Notes and limitations

- The subscription backend passes prompts on **stdin**, not argv, so large
  forensic context (tens of KB) is not subject to `ARG_MAX` limits.
- It strips `ANTHROPIC_API_KEY` from the subprocess environment before invoking
  the CLI. Without this the CLI could authenticate against the metered API and
  silently defeat the point of the backend.
- Agent tools (`Bash`, `Read`, `Write`, …) are disabled for CLI calls. ARGUS
  wants a text completion, not an agent acting on the filesystem.
- Model pins are reduced to a family alias (`sonnet`, `opus`, `haiku`) because
  the CLI resolves aliases to current versions, whereas a pinned dated model id
  can be retired.
- `max_tokens` is honoured by the API backend but **not** by the subscription
  backend — the CLI does not expose an output-token cap. Long responses are
  possible; parsing already tolerates this.
- Rate-limit retry with backoff exists only on the API path. The CLI handles its
  own throttling.
- The `usage.reported_cost_usd` field returned by the CLI is informational.
  Subscription usage is not billed against API credits.
- Default CLI timeout is 900s, override with `ARGUS_LLM_TIMEOUT`.

## Requirements

- Python 3.8+
- One of:
  - [Claude Code](https://claude.com/claude-code) installed and signed in (default, no API key required), or
  - An Anthropic Claude API key for `ARGUS_LLM_BACKEND=api`
- REMnux (recommended) or Ubuntu/Debian

## SOC Pipeline Integration -- Implemented

**Status: this stage receives escalations from a real, tested pipeline (stages 1->2 tested against real triage-localLLM code; the ARGUS handoff itself is wired and documented, not yet executed end-to-end -- no real evidence sample committed to this repo to run it against).** [Pipeline code](https://github.com/Howard1x5/triage-localLLM/tree/main/pipeline).

Positioned as the deep-investigation stage of a larger pipeline: cases escalated from [triage-localLLM](https://github.com/Howard1x5/triage-localLLM) (itself fed by [detection-as-code](https://github.com/Howard1x5/detection-as-code)'s detections) land here for full evidence analysis, IOC extraction, and MITRE mapping. See detection-as-code's README for the full pipeline picture.

## License

MIT
