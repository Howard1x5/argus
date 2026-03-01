"""
Extraction Orchestrator: Runs all 7 stages in order.

Each stage operates on the output of previous stages.
All outputs are saved to the extractions/ directory for agent consumption.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import json

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class ExtractionContext:
    """Shared context passed through all extraction stages."""

    # Input paths
    parquet_dir: Path
    output_dir: Path

    # Stage 1 outputs
    unified_df: Optional[pd.DataFrame] = None
    column_inventory: Dict[str, Dict] = field(default_factory=dict)
    ip_classifications: Dict[str, str] = field(default_factory=dict)
    username_classifications: Dict[str, str] = field(default_factory=dict)
    process_classifications: Dict[str, str] = field(default_factory=dict)

    # Stage 2 outputs
    decoded_base64: list = field(default_factory=list)
    decoded_urls: list = field(default_factory=list)
    decoded_powershell: list = field(default_factory=list)
    decoded_content_index: list = field(default_factory=list)

    # Stage 3 outputs
    process_trees: list = field(default_factory=list)
    classified_edges: list = field(default_factory=list)
    sessions: list = field(default_factory=list)
    cross_system_correlations: list = field(default_factory=list)
    attack_path: list = field(default_factory=list)
    file_process_links: list = field(default_factory=list)

    # Stage 4 outputs
    pattern_matches: list = field(default_factory=list)
    event_id_analysis: Dict = field(default_factory=dict)
    mitre_detections: list = field(default_factory=list)
    iocs: list = field(default_factory=list)

    # Stage 5 outputs
    rare_values: list = field(default_factory=list)
    high_entropy_strings: list = field(default_factory=list)
    first_seen_entities: Dict = field(default_factory=dict)
    hot_clusters: list = field(default_factory=list)
    suspicious_chains: list = field(default_factory=list)
    network_profiles: list = field(default_factory=list)

    # Stage 6 outputs
    enriched_findings: list = field(default_factory=list)

    # Stage 7 outputs
    agent_files: Dict[str, Path] = field(default_factory=dict)
    extraction_summary: Dict = field(default_factory=dict)

    # Metadata
    warnings: list = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class ExtractionOrchestrator:
    """
    Orchestrates the 7-stage extraction pipeline.

    Usage:
        orchestrator = ExtractionOrchestrator(parquet_dir, output_dir)
        results = orchestrator.run()
    """

    def __init__(self, parquet_dir: Path, output_dir: Path):
        self.parquet_dir = Path(parquet_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.context = ExtractionContext(
            parquet_dir=self.parquet_dir,
            output_dir=self.output_dir
        )

        # Import stage modules
        from . import stage1_fields
        from . import stage2_decoding
        from . import stage3_relationships
        from . import stage4_patterns
        from . import stage5_anomalies
        from . import stage6_context
        from . import stage7_assembly

        self.stages = [
            ("Stage 1: Field Extraction", stage1_fields.run),
            ("Stage 2: Decoding", stage2_decoding.run),
            ("Stage 3: Relationship Building", stage3_relationships.run),
            ("Stage 4: Pattern Detection", stage4_patterns.run),
            ("Stage 5: Anomaly Detection", stage5_anomalies.run),
            ("Stage 6: Context Enrichment", stage6_context.run),
            ("Stage 7: Assembly", stage7_assembly.run),
        ]

    def run(self) -> ExtractionContext:
        """Run all extraction stages and return the context with all results."""
        logger.info("Starting ForensicExtractor pipeline")

        for stage_name, stage_func in self.stages:
            logger.info(f"Running {stage_name}...")
            try:
                stage_func(self.context)
                logger.info(f"{stage_name} completed")
            except Exception as e:
                logger.error(f"{stage_name} failed: {e}")
                self.context.warnings.append(f"{stage_name} failed: {e}")
                raise

        logger.info("ForensicExtractor pipeline completed")
        return self.context

    def run_stage(self, stage_number: int) -> ExtractionContext:
        """Run a specific stage (1-7). Previous stages must have been run."""
        if stage_number < 1 or stage_number > 7:
            raise ValueError("Stage number must be 1-7")

        stage_name, stage_func = self.stages[stage_number - 1]
        logger.info(f"Running {stage_name}...")
        stage_func(self.context)
        logger.info(f"{stage_name} completed")

        return self.context

    def save_context(self, filepath: Optional[Path] = None) -> Path:
        """Save the extraction context to JSON for debugging/inspection."""
        if filepath is None:
            filepath = self.output_dir / "extraction_context.json"

        # Convert context to serializable dict
        data = {
            'parquet_dir': str(self.context.parquet_dir),
            'output_dir': str(self.context.output_dir),
            'statistics': self.context.statistics,
            'warnings': self.context.warnings,
            'ip_classifications': self.context.ip_classifications,
            'username_classifications': self.context.username_classifications,
            'process_classifications': self.context.process_classifications,
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return filepath
