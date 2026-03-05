"""USN Journal Parser for ARGUS.

Parses NTFS $UsnJrnl:$J to extract file system change events:
- File creations, deletions, modifications
- Rename operations (old name → new name)
- Security/permission changes
- Rapid operation detection (malware deployment)

This parser is critical for building comprehensive file activity timelines
and detecting anti-forensic file deletion patterns.
"""

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# USN Reason flags
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_CLOSE = 0x80000000

# Reason flag names for decoding
USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}

# Suspicious patterns
SUSPICIOUS_EXTENSIONS = {'.ps1', '.bat', '.cmd', '.vbs', '.js', '.exe', '.dll', '.rar', '.zip', '.jpg'}
SUSPICIOUS_NAMES = {
    'mimikatz', 'psexec', 'certutil', 'bitsadmin', 'winrar', 'telegram',
    'amanwhogetsnorest', 'whoisthebaba', 'eventlog', 'normal.zip',
}

# LOLBin to MITRE ATT&CK technique mapping
# Format: 'lolbin_name': ('primary_technique', 'technique_name', ['additional_techniques'])
LOLBIN_MITRE_MAP = {
    'schtasks': ('T1053.005', 'Scheduled Task/Job: Scheduled Task'),
    'bitsadmin': ('T1105', 'Ingress Tool Transfer'),  # Primary is T1105 for downloads
    'certutil': ('T1140', 'Deobfuscate/Decode Files or Information'),
    'powershell': ('T1059.001', 'Command and Scripting Interpreter: PowerShell'),
    'cmd': ('T1059.003', 'Command and Scripting Interpreter: Windows Command Shell'),
    'mshta': ('T1218.005', 'Signed Binary Proxy Execution: Mshta'),
    'rundll32': ('T1218.011', 'Signed Binary Proxy Execution: Rundll32'),
    'regsvr32': ('T1218.010', 'Signed Binary Proxy Execution: Regsvr32'),
    'wmic': ('T1047', 'Windows Management Instrumentation'),
    'cscript': ('T1059.005', 'Command and Scripting Interpreter: Visual Basic'),
    'wscript': ('T1059.005', 'Command and Scripting Interpreter: Visual Basic'),
}


@dataclass
class USNRecord:
    """Parsed USN Journal record."""
    record_length: int
    major_version: int
    minor_version: int
    file_reference: int
    parent_reference: int
    usn: int
    timestamp: datetime
    reason: int
    source_info: int
    security_id: int
    file_attributes: int
    filename: str
    reason_flags: List[str] = field(default_factory=list)


class USNJournalParser(BaseParser):
    """Parser for NTFS USN Journal ($UsnJrnl:$J)."""

    name = "usn"
    description = "NTFS USN Journal ($UsnJrnl)"
    supported_extensions = [""]  # $J has no extension

    # Known USN Journal file names
    USN_NAMES = {"$usnjrnl", "$j", "usnjrnl", "usnjournal"}

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a USN Journal file."""
        name_lower = file_path.name.lower()

        # Check known names
        for usn_name in cls.USN_NAMES:
            if usn_name in name_lower:
                return True

        # Check for USN record structure at non-zero offset
        try:
            with open(file_path, "rb") as f:
                # USN journal is sparse - skip zeros to find first record
                chunk_size = 4096
                for _ in range(100):  # Check first 400KB
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Find non-zero bytes
                    for i in range(0, len(chunk) - 8, 8):
                        if chunk[i:i + 8] != b'\x00' * 8:
                            # Try to parse as USN record
                            if len(chunk) >= i + 8:
                                record_len = struct.unpack("<I", chunk[i:i + 4])[0]
                                version = struct.unpack("<H", chunk[i + 4:i + 6])[0]
                                # Valid USN record: length > 60, version 2 or 3
                                if 60 <= record_len <= 4096 and version in (2, 3):
                                    return True
                            break

        except Exception:
            pass

        return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse USN Journal file and extract file system events."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Parse all records
            records = self._parse_journal(data)
            result.metadata["total_records"] = len(records)

            # Group records by file reference for rename tracking
            file_records: Dict[int, List[USNRecord]] = defaultdict(list)
            for record in records:
                file_records[record.file_reference].append(record)

            # Match rename pairs
            renames = self._match_renames(records)
            result.metadata["rename_operations"] = len(renames)

            # Detect rapid file operations (malware deployment)
            rapid_ops = self._detect_rapid_operations(records)

            # Generate events
            line_num = 0
            seen_events: Set[Tuple[datetime, str, str]] = set()

            for record in records:
                line_num += 1
                events = self._create_events(record, line_num, file_path.name, renames)

                for event in events:
                    # Deduplicate events
                    event_key = (event.timestamp_utc, event.event_type, event.file_path or "")
                    if event_key not in seen_events:
                        seen_events.add(event_key)
                        result.add_event(event)

            # Add rapid operation events
            for rapid_event in rapid_ops:
                result.add_event(rapid_event)

            # Detect staged deletion pattern (create then delete)
            deletion_events = self._detect_staged_deletions(records, file_path.name)
            for event in deletion_events:
                result.add_event(event)

        except Exception as e:
            result.add_error(f"Failed to parse USN Journal: {str(e)}")

        return result

    def _parse_journal(self, data: bytes) -> List[USNRecord]:
        """Parse all USN records from journal data."""
        records = []
        offset = 0
        data_len = len(data)

        # Skip to first non-zero cluster
        offset = self._find_first_record(data)

        while offset + 60 < data_len:
            try:
                # Check for zero padding
                if data[offset:offset + 8] == b'\x00' * 8:
                    # Skip zero clusters
                    offset += 8
                    while offset + 8 < data_len and data[offset:offset + 8] == b'\x00' * 8:
                        offset += 8
                    continue

                # Read record length
                record_len = struct.unpack("<I", data[offset:offset + 4])[0]

                # Validate record length
                if record_len < 60 or record_len > 4096:
                    offset += 8
                    continue

                # Read version
                version = struct.unpack("<H", data[offset + 4:offset + 6])[0]

                if version == 2:
                    record = self._parse_record_v2(data[offset:offset + record_len])
                elif version == 3:
                    record = self._parse_record_v3(data[offset:offset + record_len])
                else:
                    offset += 8
                    continue

                if record:
                    records.append(record)
                    offset += record_len
                else:
                    offset += 8

            except Exception:
                offset += 8
                continue

            # Safety limit
            if len(records) >= 500000:
                break

        return records

    def _find_first_record(self, data: bytes) -> int:
        """Find offset of first valid USN record."""
        chunk_size = 4096

        for chunk_offset in range(0, min(len(data), 10 * 1024 * 1024), chunk_size):
            chunk = data[chunk_offset:chunk_offset + chunk_size]

            # Find first non-zero byte
            for i in range(0, len(chunk) - 60, 8):
                if chunk[i:i + 8] != b'\x00' * 8:
                    # Validate as USN record
                    if len(chunk) >= i + 6:
                        record_len = struct.unpack("<I", chunk[i:i + 4])[0]
                        version = struct.unpack("<H", chunk[i + 4:i + 6])[0]
                        if 60 <= record_len <= 4096 and version in (2, 3):
                            return chunk_offset + i
                    break

        return 0

    def _parse_record_v2(self, data: bytes) -> Optional[USNRecord]:
        """Parse USN_RECORD_V2 structure."""
        if len(data) < 60:
            return None

        try:
            record_len = struct.unpack("<I", data[0:4])[0]
            major_version = struct.unpack("<H", data[4:6])[0]
            minor_version = struct.unpack("<H", data[6:8])[0]

            if major_version != 2:
                return None

            # File reference (6 bytes number + 2 bytes sequence)
            file_ref = struct.unpack("<Q", data[8:16])[0] & 0x0000FFFFFFFFFFFF
            parent_ref = struct.unpack("<Q", data[16:24])[0] & 0x0000FFFFFFFFFFFF

            usn = struct.unpack("<Q", data[24:32])[0]
            timestamp = self._filetime_to_datetime(struct.unpack("<Q", data[32:40])[0])
            reason = struct.unpack("<I", data[40:44])[0]
            source_info = struct.unpack("<I", data[44:48])[0]
            security_id = struct.unpack("<I", data[48:52])[0]
            file_attrs = struct.unpack("<I", data[52:56])[0]
            filename_len = struct.unpack("<H", data[56:58])[0]
            filename_offset = struct.unpack("<H", data[58:60])[0]

            # Extract filename
            if filename_offset + filename_len <= len(data):
                filename_bytes = data[filename_offset:filename_offset + filename_len]
                filename = filename_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
            else:
                filename = ""

            # Decode reason flags
            reason_flags = self._decode_reason(reason)

            return USNRecord(
                record_length=record_len,
                major_version=major_version,
                minor_version=minor_version,
                file_reference=file_ref,
                parent_reference=parent_ref,
                usn=usn,
                timestamp=timestamp,
                reason=reason,
                source_info=source_info,
                security_id=security_id,
                file_attributes=file_attrs,
                filename=filename,
                reason_flags=reason_flags,
            )

        except Exception:
            return None

    def _parse_record_v3(self, data: bytes) -> Optional[USNRecord]:
        """Parse USN_RECORD_V3 structure (128-bit file references)."""
        if len(data) < 76:
            return None

        try:
            record_len = struct.unpack("<I", data[0:4])[0]
            major_version = struct.unpack("<H", data[4:6])[0]
            minor_version = struct.unpack("<H", data[6:8])[0]

            if major_version != 3:
                return None

            # 128-bit file references (use first 8 bytes for compatibility)
            file_ref = struct.unpack("<Q", data[8:16])[0] & 0x0000FFFFFFFFFFFF
            parent_ref = struct.unpack("<Q", data[24:32])[0] & 0x0000FFFFFFFFFFFF

            usn = struct.unpack("<Q", data[40:48])[0]
            timestamp = self._filetime_to_datetime(struct.unpack("<Q", data[48:56])[0])
            reason = struct.unpack("<I", data[56:60])[0]
            source_info = struct.unpack("<I", data[60:64])[0]
            security_id = struct.unpack("<I", data[64:68])[0]
            file_attrs = struct.unpack("<I", data[68:72])[0]
            filename_len = struct.unpack("<H", data[72:74])[0]
            filename_offset = struct.unpack("<H", data[74:76])[0]

            # Extract filename
            if filename_offset + filename_len <= len(data):
                filename_bytes = data[filename_offset:filename_offset + filename_len]
                filename = filename_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
            else:
                filename = ""

            reason_flags = self._decode_reason(reason)

            return USNRecord(
                record_length=record_len,
                major_version=major_version,
                minor_version=minor_version,
                file_reference=file_ref,
                parent_reference=parent_ref,
                usn=usn,
                timestamp=timestamp,
                reason=reason,
                source_info=source_info,
                security_id=security_id,
                file_attributes=file_attrs,
                filename=filename,
                reason_flags=reason_flags,
            )

        except Exception:
            return None

    def _decode_reason(self, reason: int) -> List[str]:
        """Decode reason flags to human-readable names."""
        flags = []
        for flag_value, flag_name in USN_REASON_FLAGS.items():
            if reason & flag_value:
                flags.append(flag_name)
        return flags

    def _match_renames(self, records: List[USNRecord]) -> Dict[int, Tuple[str, str, datetime]]:
        """Match RENAME_OLD_NAME and RENAME_NEW_NAME pairs."""
        renames: Dict[int, Tuple[str, str, datetime]] = {}

        # Group by file reference
        file_records: Dict[int, List[USNRecord]] = defaultdict(list)
        for record in records:
            if record.reason & (USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME):
                file_records[record.file_reference].append(record)

        # Find pairs
        for file_ref, file_recs in file_records.items():
            old_name = None
            old_time = None

            for rec in sorted(file_recs, key=lambda r: r.usn):
                if rec.reason & USN_REASON_RENAME_OLD_NAME:
                    old_name = rec.filename
                    old_time = rec.timestamp
                elif rec.reason & USN_REASON_RENAME_NEW_NAME and old_name:
                    renames[file_ref] = (old_name, rec.filename, rec.timestamp)
                    old_name = None

        return renames

    def _detect_rapid_operations(self, records: List[USNRecord]) -> List[UnifiedEvent]:
        """Detect clusters of rapid file operations (malware deployment)."""
        events = []

        if not records:
            return events

        # Group records by timestamp (1-second windows)
        time_groups: Dict[str, List[USNRecord]] = defaultdict(list)
        for record in records:
            time_key = record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            time_groups[time_key].append(record)

        # Flag groups with > 10 operations involving suspicious files
        for time_key, group in time_groups.items():
            suspicious_count = 0
            filenames = set()

            for rec in group:
                filenames.add(rec.filename)
                name_lower = rec.filename.lower()

                # Check for suspicious patterns
                for sus in SUSPICIOUS_NAMES:
                    if sus in name_lower:
                        suspicious_count += 1
                        break
                else:
                    for ext in SUSPICIOUS_EXTENSIONS:
                        if name_lower.endswith(ext):
                            suspicious_count += 1
                            break

            if len(group) >= 5 and suspicious_count >= 2:
                event = UnifiedEvent(
                    timestamp_utc=group[0].timestamp,
                    source_file="usn_journal",
                    source_line=0,
                    event_type="USN_RapidOperations",
                    severity=EventSeverity.HIGH,
                    parser_name=self.name,
                    description=f"Rapid file operations: {len(group)} changes to {len(filenames)} files in 1 second",
                    raw_payload=", ".join(sorted(filenames)[:10]),
                    mitre_technique="T1105",
                )
                events.append(event)

        return events

    def _detect_staged_deletions(self, records: List[USNRecord], source_file: str) -> List[UnifiedEvent]:
        """Detect files that were created and then quickly deleted."""
        events = []

        # Group by filename
        file_history: Dict[str, List[USNRecord]] = defaultdict(list)
        for record in records:
            if record.reason & (USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE):
                file_history[record.filename.lower()].append(record)

        for filename, history in file_history.items():
            creates = [r for r in history if r.reason & USN_REASON_FILE_CREATE]
            deletes = [r for r in history if r.reason & USN_REASON_FILE_DELETE]

            for create in creates:
                for delete in deletes:
                    if delete.timestamp > create.timestamp:
                        lifespan = (delete.timestamp - create.timestamp).total_seconds()

                        # Flag if lifespan < 1 hour and suspicious name/extension
                        if lifespan < 3600:
                            name_lower = filename.lower()
                            is_suspicious = False

                            for sus in SUSPICIOUS_NAMES:
                                if sus in name_lower:
                                    is_suspicious = True
                                    break

                            if not is_suspicious:
                                for ext in SUSPICIOUS_EXTENSIONS:
                                    if name_lower.endswith(ext):
                                        is_suspicious = True
                                        break

                            if is_suspicious:
                                event = UnifiedEvent(
                                    timestamp_utc=delete.timestamp,
                                    source_file=source_file,
                                    source_line=0,
                                    event_type="USN_StagedDeletion",
                                    severity=EventSeverity.HIGH,
                                    parser_name=self.name,
                                    file_path=filename,
                                    description=f"Staged deletion: {filename} created and deleted within {lifespan:.0f}s [MITRE T1070.004]",
                                    mitre_technique="T1070.004",
                                )
                                events.append(event)
                        break

        return events

    def _create_events(
        self, record: USNRecord, line_num: int, source_file: str,
        renames: Dict[int, Tuple[str, str, datetime]]
    ) -> List[UnifiedEvent]:
        """Create forensic events from USN record."""
        events = []
        filename = record.filename
        severity = self._assess_severity(filename)

        # File Creation
        if record.reason & USN_REASON_FILE_CREATE:
            event = UnifiedEvent(
                timestamp_utc=record.timestamp,
                source_file=source_file,
                source_line=line_num,
                event_type="USN_FileCreated",
                severity=severity,
                parser_name=self.name,
                file_path=filename,
                description=f"File created: {filename}",
                raw_payload=", ".join(record.reason_flags),
            )
            events.append(event)

        # File Deletion
        if record.reason & USN_REASON_FILE_DELETE:
            event = UnifiedEvent(
                timestamp_utc=record.timestamp,
                source_file=source_file,
                source_line=line_num,
                event_type="USN_FileDeleted",
                severity=EventSeverity.HIGH,  # Deletions are always significant
                parser_name=self.name,
                file_path=filename,
                description=f"File deleted: {filename} [MITRE T1070.004]",
                mitre_technique="T1070.004",
                raw_payload=", ".join(record.reason_flags),
            )
            events.append(event)

        # File Rename
        if record.reason & USN_REASON_RENAME_NEW_NAME:
            if record.file_reference in renames:
                old_name, new_name, _ = renames[record.file_reference]
                event = UnifiedEvent(
                    timestamp_utc=record.timestamp,
                    source_file=source_file,
                    source_line=line_num,
                    event_type="USN_FileRenamed",
                    severity=EventSeverity.MEDIUM,
                    parser_name=self.name,
                    file_path=new_name,
                    description=f"File renamed: {old_name} → {new_name}",
                    raw_payload=f"Old: {old_name}, New: {new_name}",
                )
                events.append(event)

        # Security Change
        if record.reason & USN_REASON_SECURITY_CHANGE:
            event = UnifiedEvent(
                timestamp_utc=record.timestamp,
                source_file=source_file,
                source_line=line_num,
                event_type="USN_SecurityChanged",
                severity=EventSeverity.MEDIUM,
                parser_name=self.name,
                file_path=filename,
                description=f"Security changed: {filename}",
                mitre_technique="T1222",
            )
            events.append(event)

        # Data Modification (if significant)
        if record.reason & (USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND):
            if severity in (EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL):
                event = UnifiedEvent(
                    timestamp_utc=record.timestamp,
                    source_file=source_file,
                    source_line=line_num,
                    event_type="USN_FileModified",
                    severity=severity,
                    parser_name=self.name,
                    file_path=filename,
                    description=f"File modified: {filename}",
                    raw_payload=", ".join(record.reason_flags),
                )
                events.append(event)

        # LOLBin/Technique Detection - check for LOLBin prefetch files or executables
        name_lower = filename.lower()
        for lolbin, (mitre_id, mitre_name) in LOLBIN_MITRE_MAP.items():
            if lolbin in name_lower:
                # Create MITRE technique event
                event = UnifiedEvent(
                    timestamp_utc=record.timestamp,
                    source_file=source_file,
                    source_line=line_num,
                    event_type="USN_LOLBin_Detected",
                    severity=EventSeverity.HIGH,
                    parser_name=self.name,
                    file_path=filename,
                    process_name=lolbin,
                    description=f"LOLBin activity: {lolbin} [{mitre_id}: {mitre_name}]",
                    mitre_technique=mitre_id,
                )
                events.append(event)
                break  # Only one LOLBin match per file

        return events

    def _assess_severity(self, filename: str) -> EventSeverity:
        """Assess severity based on filename."""
        name_lower = filename.lower()

        # Check suspicious names
        for sus in SUSPICIOUS_NAMES:
            if sus in name_lower:
                return EventSeverity.HIGH

        # Check suspicious extensions
        for ext in SUSPICIOUS_EXTENSIONS:
            if name_lower.endswith(ext):
                return EventSeverity.MEDIUM

        return EventSeverity.INFO

    def _filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        EPOCH_DIFF = 116444736000000000
        try:
            if filetime < EPOCH_DIFF or filetime > EPOCH_DIFF + (200 * 365 * 24 * 60 * 60 * 10000000):
                return datetime.now(timezone.utc)
            unix_time = (filetime - EPOCH_DIFF) / 10000000
            return datetime.fromtimestamp(unix_time, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return datetime.now(timezone.utc)
