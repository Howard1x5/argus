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

## Requirements

- Python 3.8+
- Anthropic Claude API key
- REMnux (recommended) or Ubuntu/Debian

## License

MIT
