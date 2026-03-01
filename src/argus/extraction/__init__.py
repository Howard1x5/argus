"""
ForensicExtractor: Programmatic evidence extraction for IR analysis.

Per SPEC v1.1: ForensicExtractor does DISCOVERY, LLM Agents do INTERPRETATION.

7 Stages:
- Stage 1: Field Extraction (make data queryable)
- Stage 2: Decoding (make hidden content visible)
- Stage 3: Relationship Building (connect events)
- Stage 4: Pattern Detection (find known-bad)
- Stage 5: Anomaly Detection (find unknown-bad)
- Stage 6: Context Enrichment (make findings richer)
- Stage 7: Assembly (package for agents)
"""

from .orchestrator import ExtractionOrchestrator

__all__ = ['ExtractionOrchestrator']
