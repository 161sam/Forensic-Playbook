#!/usr/bin/env python3
"""
Filesystem Analysis Module
Comprehensive filesystem analysis using Sleuthkit (TSK)

Features:
- Filesystem type detection
- Partition table analysis
- File listing and metadata extraction
- Deleted file detection
- File carving
- Inode analysis
- String extraction
- Hash computation
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat

from ...tools import sleuthkit as sleuthkit_wrapper


class FilesystemAnalysisModule(AnalysisModule):
    TOOL_WRAPPERS = {"Sleuthkit": sleuthkit_wrapper}

    """
    Filesystem analysis module using Sleuthkit

    Performs comprehensive filesystem analysis on:
    - Raw disk images
    - Forensic image formats (E01, AFF)
    - Individual partitions
    - Mounted filesystems
    """

    @property
    def name(self) -> str:
        return "filesystem_analysis"

    @property
    def description(self) -> str:
        return "Filesystem analysis using Sleuthkit"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if "image" not in params:
            self.logger.error("Missing required parameter: image")
            return False

        image = Path(params["image"])
        if not image.exists():
            self.logger.error(f"Image file does not exist: {image}")
            return False

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute filesystem analysis"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()

        image = Path(params["image"])
        partition = params.get("partition")  # Optional partition number

        # Analysis options
        include_deleted = params.get("include_deleted", "true").lower() == "true"
        extract_strings = params.get("extract_strings", "false").lower() == "true"
        compute_hashes = params.get("compute_hashes", "false").lower() == "true"
        max_depth = int(params.get("max_depth", 0))  # 0 = unlimited

        findings = []
        errors = []
        metadata = {
            "image": str(image),
            "partition": partition,
            "analysis_start": timestamp,
        }

        self.logger.info(f"Analyzing filesystem: {image}")

        # Check Sleuthkit availability
        if not self._verify_tool("fls"):
            guidance = "Install sleuthkit (fls) to analyze disk images."
            return self._missing_tool_result(
                result_id,
                "fls",
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
            )

        try:
            # 1. Get image info
            self.logger.info("Extracting image information...")
            image_info = self._get_image_info(image)
            metadata["image_info"] = image_info

            findings.append(
                {
                    "type": "image_info",
                    "description": "Disk image information",
                    **image_info,
                }
            )

            # 2. Analyze partition table
            self.logger.info("Analyzing partition table...")
            partitions = self._analyze_partitions(image)
            metadata["partitions"] = len(partitions)

            findings.append(
                {
                    "type": "partitions",
                    "description": f"Found {len(partitions)} partitions",
                    "partitions": partitions,
                }
            )

            # 3. Determine target partition
            if partition:
                target_partition = int(partition)
            elif len(partitions) == 1:
                target_partition = 0
            elif partitions:
                # Find first data partition
                target_partition = next(
                    (
                        i
                        for i, p in enumerate(partitions)
                        if p.get("type") not in ["Extended", "Unused"]
                    ),
                    0,
                )
            else:
                target_partition = None

            metadata["target_partition"] = target_partition

            # 4. Filesystem detection
            if target_partition is not None:
                self.logger.info(f"Analyzing partition {target_partition}...")
                fs_info = self._detect_filesystem(image, target_partition)
                metadata["filesystem"] = fs_info

                findings.append(
                    {
                        "type": "filesystem_info",
                        "description": "Filesystem information",
                        **fs_info,
                    }
                )

            # 5. File listing
            self.logger.info("Extracting file listing...")
            file_list = self._list_files(
                image, target_partition, include_deleted, max_depth
            )

            metadata["total_files"] = len(file_list)
            metadata["deleted_files"] = sum(1 for f in file_list if f.get("deleted"))

            # Save file list
            file_list_file = self.output_dir / "file_list.json"
            with open(file_list_file, "w") as f:
                json.dump(file_list, f, indent=2, sort_keys=True)

            findings.append(
                {
                    "type": "file_listing",
                    "description": f'Extracted {len(file_list)} files ({metadata["deleted_files"]} deleted)',
                    "output_file": str(file_list_file),
                }
            )

            # 6. Deleted file analysis
            if include_deleted and metadata["deleted_files"] > 0:
                self.logger.info("Analyzing deleted files...")
                deleted_files = [f for f in file_list if f.get("deleted")]

                # Categorize by type
                deleted_by_ext = {}
                for f in deleted_files:
                    ext = Path(f["name"]).suffix.lower() or "no_extension"
                    deleted_by_ext[ext] = deleted_by_ext.get(ext, 0) + 1

                findings.append(
                    {
                        "type": "deleted_files",
                        "description": "Deleted file analysis",
                        "total": len(deleted_files),
                        "by_extension": deleted_by_ext,
                    }
                )

            # 7. String extraction (if requested)
            if extract_strings:
                self.logger.info("Extracting strings...")
                strings_file = self._extract_strings(image, target_partition)

                if strings_file:
                    findings.append(
                        {
                            "type": "strings",
                            "description": "Strings extracted from filesystem",
                            "output_file": str(strings_file),
                        }
                    )

            # 8. File hashing (if requested)
            if compute_hashes:
                self.logger.info("Computing file hashes...")
                hash_results = self._compute_file_hashes(
                    image, target_partition, file_list[:100]  # Limit to first 100 files
                )

                hash_file = self.output_dir / "file_hashes.json"
                with open(hash_file, "w") as f:
                    json.dump(hash_results, f, indent=2, sort_keys=True)

                findings.append(
                    {
                        "type": "file_hashes",
                        "description": f"Computed hashes for {len(hash_results)} files",
                        "output_file": str(hash_file),
                    }
                )

        except Exception as e:
            self.logger.error(f"Filesystem analysis failed: {e}")
            errors.append(f"Analysis failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors,
            )

        metadata["analysis_end"] = utc_isoformat()

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=file_list_file if "file_list_file" in locals() else None,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _get_image_info(self, image: Path) -> Dict:
        """Get disk image information using img_stat"""
        info = {}

        try:
            stdout, stderr, rc = self._run_command(["img_stat", str(image)])

            # Parse output
            for line in stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    value = value.strip()
                    info[key] = value
        except Exception as e:
            self.logger.warning(f"img_stat failed: {e}")

        return info

    def _analyze_partitions(self, image: Path) -> List[Dict]:
        """Analyze partition table using mmls"""
        partitions = []

        try:
            stdout, stderr, rc = self._run_command(["mmls", str(image)])

            # Parse mmls output
            # Format: Slot Start End Length Description
            lines = stdout.splitlines()

            for line in lines:
                # Skip headers
                if line.startswith("Units") or line.startswith("Slot"):
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    try:
                        partitions.append(
                            {
                                "slot": parts[0],
                                "start": int(parts[1]),
                                "end": int(parts[2]),
                                "length": int(parts[3]),
                                "type": " ".join(parts[4:]),
                            }
                        )
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            self.logger.warning(f"mmls failed: {e}")
            # Might not have partition table - try single filesystem

        return partitions

    def _detect_filesystem(self, image: Path, partition: Optional[int]) -> Dict:
        """Detect filesystem type using fsstat"""
        info = {}

        cmd = ["fsstat"]

        if partition is not None:
            # Calculate offset for partition
            partitions = self._analyze_partitions(image)
            if partition < len(partitions):
                offset = (
                    partitions[partition]["start"] * 512
                )  # Assuming 512-byte sectors
                cmd.extend(["-o", str(offset)])

        cmd.append(str(image))

        try:
            stdout, stderr, rc = self._run_command(cmd)

            # Parse fsstat output
            for line in stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    value = value.strip()
                    info[key] = value
        except Exception as e:
            self.logger.warning(f"fsstat failed: {e}")

        return info

    def _list_files(
        self,
        image: Path,
        partition: Optional[int],
        include_deleted: bool,
        max_depth: int,
    ) -> List[Dict]:
        """List files using fls"""
        files = []

        cmd = ["fls", "-r", "-l", "-p"]  # Recursive, long format, display full path

        if include_deleted:
            cmd.append("-d")  # Include deleted

        if partition is not None:
            partitions = self._analyze_partitions(image)
            if partition < len(partitions):
                offset = partitions[partition]["start"] * 512
                cmd.extend(["-o", str(offset)])

        cmd.append(str(image))

        try:
            stdout, stderr, rc = self._run_command(cmd, timeout=600)

            # Parse fls output
            # Format: r/r <inode> <deleted>: <name>
            for line in stdout.splitlines():
                if not line.strip():
                    continue

                # Parse line
                match = re.match(r"([rd])/([rd])\s+(\d+)(?:\(realloc\))?:\s+(.+)", line)
                if match:
                    dir_type = match.group(2)
                    inode = match.group(3)
                    name = match.group(4)

                    # Check if deleted
                    deleted = "*" in line

                    files.append(
                        {
                            "inode": int(inode),
                            "name": name.strip("*"),
                            "type": "directory" if dir_type == "d" else "file",
                            "deleted": deleted,
                        }
                    )
        except Exception as e:
            self.logger.warning(f"fls failed: {e}")

        return sorted(
            files,
            key=lambda item: (
                item.get("name") or "",
                item.get("inode", 0),
            ),
        )

    def _extract_strings(self, image: Path, partition: Optional[int]) -> Optional[Path]:
        """Extract strings from filesystem"""
        strings_file = self.output_dir / "strings.txt"

        cmd = ["strings", "-a", "-t", "d"]  # All bytes, decimal offset

        # For partition, use blkcat to extract partition data
        if partition is not None:
            partitions = self._analyze_partitions(image)
            if partition < len(partitions):
                offset = partitions[partition]["start"]
                length = partitions[partition]["length"]

                # Use blkcat to extract partition
                blkcat_cmd = ["blkcat", str(image), str(offset), str(length)]

                try:
                    # Pipe blkcat to strings
                    with open(strings_file, "w") as f:
                        # TODO: use forensic.tools.sleuthkit wrapper for blkcat/strings integration
                        blkcat_proc = subprocess.Popen(
                            blkcat_cmd, stdout=subprocess.PIPE
                        )
                        strings_proc = subprocess.Popen(
                            ["strings", "-a"],
                            stdin=blkcat_proc.stdout,
                            stdout=f,
                            stderr=subprocess.PIPE,
                        )
                        blkcat_proc.stdout.close()
                        strings_proc.communicate(timeout=600)

                    return strings_file
                except Exception as e:
                    self.logger.warning(f"String extraction failed: {e}")
        else:
            cmd.append(str(image))

            try:
                with open(strings_file, "w") as f:
                    # TODO: use forensic.tools.sleuthkit wrapper for string extraction
                    subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=600)

                return strings_file
            except Exception as e:
                self.logger.warning(f"String extraction failed: {e}")

        return None

    def _compute_file_hashes(
        self, image: Path, partition: Optional[int], file_list: List[Dict]
    ) -> List[Dict]:
        """Compute hashes for files using icat"""
        hash_results = []

        for file_info in file_list:
            if file_info["type"] != "file":
                continue

            inode = file_info["inode"]

            # Extract file content using icat
            cmd = ["icat"]

            if partition is not None:
                partitions = self._analyze_partitions(image)
                if partition < len(partitions):
                    offset = partitions[partition]["start"] * 512
                    cmd.extend(["-o", str(offset)])

            cmd.extend([str(image), str(inode)])

            try:
                # TODO: use forensic.tools.sleuthkit wrapper for icat access
                result = subprocess.run(cmd, capture_output=True, timeout=60)

                if result.returncode == 0:
                    # Compute hash
                    import hashlib

                    h = hashlib.sha256(result.stdout)

                    hash_results.append(
                        {
                            "inode": inode,
                            "name": file_info["name"],
                            "sha256": h.hexdigest(),
                            "size": len(result.stdout),
                        }
                    )
            except Exception as e:
                self.logger.debug(f"Hash computation failed for inode {inode}: {e}")
                continue

        return sorted(
            hash_results,
            key=lambda item: (
                item.get("name") or "",
                item.get("inode", 0),
            ),
        )
