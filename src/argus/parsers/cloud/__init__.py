"""Cloud log parsers for ARGUS."""

from argus.parsers.cloud.cloudtrail import CloudTrailParser
from argus.parsers.cloud.azure_ad import AzureADParser
from argus.parsers.cloud.gcp import GCPAuditParser

__all__ = ["CloudTrailParser", "AzureADParser", "GCPAuditParser"]
