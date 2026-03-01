"""ARGUS pipeline phases.

Each phase handles a specific step in the IR analysis workflow.
"""

from argus.phases.phase0_init import run_init
from argus.phases.phase1_ingest import run_ingest
from argus.phases.phase2_triage import run_triage
from argus.phases.phase3_analysis import run_analysis
from argus.phases.phase4_validation import run_validation
from argus.phases.phase5_ioc import run_ioc_extraction
from argus.phases.phase6_detection import run_detection_engineering
from argus.phases.phase7_report import run_report_generation
from argus.phases.phase8_package import run_output_packaging

__all__ = [
    "run_init",
    "run_ingest",
    "run_triage",
    "run_analysis",
    "run_validation",
    "run_ioc_extraction",
    "run_detection_engineering",
    "run_report_generation",
    "run_output_packaging",
]
