#!/usr/bin/env python3
"""
Disk Imaging Module
Forensic disk imaging with multiple tools and verification
"""

import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...core.time_utils import utc_isoformat


class DiskImagingModule(AcquisitionModule):
    """
    Forensic disk imaging module
    
    Supports:
    - dd (basic imaging)
    - ddrescue (damaged disk recovery)
    - ewfacquire (Expert Witness Format)
    - Automatic hash verification
    - Bad sector logging
    - Chain of custody integration
    """
    
    @property
    def name(self) -> str:
        return "disk_imaging"
    
    @property
    def description(self) -> str:
        return "Forensic disk imaging with verification"
    
    @property
    def requires_root(self) -> bool:
        return True
    
    @property
    def supported_evidence_types(self) -> List[str]:
        return ["disk", "partition"]
    
    def validate_params(self, params: Dict) -> bool:
        """
        Validate parameters
        
        Required params:
        - source: Source device (e.g., /dev/sdb)
        - output: Output path
        
        Optional params:
        - tool: Imaging tool (dd|ddrescue|ewfacquire, default: ddrescue)
        - hash_algorithm: Hash algorithm (sha256|sha1|md5, default: sha256)
        - block_size: Block size (default: 4M)
        - skip_verify: Skip hash verification (default: False)
        """
        required = ['source', 'output']
        for param in required:
            if param not in params:
                self.logger.error(f"Missing required parameter: {param}")
                return False
        
        # Check source exists
        source = Path(params['source'])
        if not source.exists():
            self.logger.error(f"Source device not found: {source}")
            return False
        
        # Check if block device
        if not os.path.isblk(source):
            self.logger.error(f"Source is not a block device: {source}")
            return False
        
        return True
    
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute disk imaging"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        
        source = Path(params['source'])
        output = Path(params.get('output', self.output_dir / f"disk_image_{timestamp}.img"))
        tool = params.get('tool', 'ddrescue')
        hash_algo = params.get('hash_algorithm', 'sha256')
        block_size = params.get('block_size', '4M')
        skip_verify = params.get('skip_verify', 'false').lower() == 'true'
        
        findings = []
        errors = []
        metadata = {
            'source': str(source),
            'output': str(output),
            'tool': tool,
            'hash_algorithm': hash_algo,
            'imaging_start': timestamp
        }

        required = {
            'dd': ['dd'],
            'ddrescue': ['ddrescue'],
            'ewfacquire': ['ewfacquire'],
        }
        missing = [name for name in required.get(tool, []) if not self._verify_tool(name)]
        if missing:
            guidance = (
                "Install the requested imaging tool(s) before running the module."
            )
            return self._missing_tool_result(
                result_id,
                missing,
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
                status="skipped",
            )
        
        # Ensure output directory exists
        output.parent.mkdir(parents=True, exist_ok=True)
        
        # Get source device info
        metadata.update(self._get_device_info(source))
        
        # Pre-imaging hash of source (if requested)
        if not skip_verify:
            self.logger.info(f"Computing source hash...")
            try:
                source_hash = self._hash_device(source, hash_algo)
                metadata['source_hash'] = source_hash
                findings.append({
                    'type': 'hash',
                    'description': 'Source device hash',
                    'hash': source_hash,
                    'algorithm': hash_algo
                })
            except Exception as e:
                errors.append(f"Failed to hash source: {e}")
        
        # Perform imaging
        self.logger.info(f"Starting disk imaging: {source} -> {output}")
        
        try:
            if tool == 'dd':
                success, image_metadata = self._image_with_dd(source, output, block_size)
            elif tool == 'ddrescue':
                success, image_metadata = self._image_with_ddrescue(source, output)
            elif tool == 'ewfacquire':
                success, image_metadata = self._image_with_ewfacquire(source, output)
            else:
                errors.append(f"Unknown imaging tool: {tool}")
                success = False
                image_metadata = {}
            
            metadata.update(image_metadata)
            metadata['imaging_end'] = utc_isoformat()
            
            if not success:
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    output_path=output if output.exists() else None,
                    findings=findings,
                    metadata=metadata,
                    errors=errors
                )
            
            findings.append({
                'type': 'imaging',
                'description': 'Disk image created successfully',
                'tool': tool,
                'size': output.stat().st_size if output.exists() else 0
            })
            
        except Exception as e:
            self.logger.error(f"Imaging failed: {e}")
            errors.append(f"Imaging failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                output_path=None,
                findings=findings,
                metadata=metadata,
                errors=errors
            )
        
        # Post-imaging hash verification
        if not skip_verify and output.exists():
            self.logger.info("Verifying image hash...")
            try:
                image_hash = self._compute_hash(output, hash_algo)
                metadata['image_hash'] = image_hash
                
                if 'source_hash' in metadata:
                    if metadata['source_hash'] == image_hash:
                        findings.append({
                            'type': 'verification',
                            'description': 'Hash verification successful',
                            'status': 'match'
                        })
                    else:
                        errors.append("Hash mismatch: source and image hashes differ")
                        findings.append({
                            'type': 'verification',
                            'description': 'Hash verification failed',
                            'status': 'mismatch',
                            'source_hash': metadata['source_hash'],
                            'image_hash': image_hash
                        })
            except Exception as e:
                errors.append(f"Hash verification failed: {e}")
        
        # Generate hash file
        if output.exists():
            hash_file = output.with_suffix(f'.{hash_algo}')
            with open(hash_file, 'w') as f:
                f.write(f"{metadata.get('image_hash', 'N/A')}  {output.name}\n")
        
        status = "success" if not errors else "partial"
        
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=output,
            findings=findings,
            metadata=metadata,
            errors=errors
        )
    
    def _get_device_info(self, device: Path) -> Dict:
        """Get device information"""
        info = {}
        
        try:
            # Get device size
            stdout, _, _ = self._run_command(['blockdev', '--getsize64', str(device)])
            info['device_size_bytes'] = int(stdout.strip())
            
            # Get device model/serial
            stdout, _, _ = self._run_command(['lsblk', '-ndo', 'MODEL,SERIAL', str(device)])
            if stdout.strip():
                parts = stdout.strip().split()
                if len(parts) >= 1:
                    info['device_model'] = parts[0]
                if len(parts) >= 2:
                    info['device_serial'] = parts[1]
            
            # Get partition info
            stdout, _, _ = self._run_command(['fdisk', '-l', str(device)])
            info['partition_table'] = stdout
            
        except Exception as e:
            self.logger.warning(f"Could not get full device info: {e}")
        
        return info
    
    def _hash_device(self, device: Path, algorithm: str) -> str:
        """Compute hash of device"""
        import hashlib
        
        h = getattr(hashlib, algorithm)()
        
        with open(device, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                h.update(chunk)
        
        return h.hexdigest()
    
    def _image_with_dd(self, source: Path, output: Path, block_size: str) -> tuple:
        """Image with dd"""
        log_file = output.with_suffix('.dd.log')
        
        cmd = [
            'dd',
            f'if={source}',
            f'of={output}',
            f'bs={block_size}',
            'conv=sync,noerror',
            'status=progress'
        ]
        
        stdout, stderr, returncode = self._run_command(cmd)
        
        # Save log
        with open(log_file, 'w') as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            f.write("STDOUT:\n")
            f.write(stdout)
            f.write("\n\nSTDERR:\n")
            f.write(stderr)
        
        metadata = {
            'dd_log': str(log_file),
            'dd_returncode': returncode
        }
        
        return returncode == 0, metadata
    
    def _image_with_ddrescue(self, source: Path, output: Path) -> tuple:
        """Image with ddrescue"""
        log_file = output.with_suffix('.ddrescue.log')
        
        # Phase 1: Fast copy
        self.logger.info("Phase 1: Fast copy...")
        cmd = [
            'ddrescue',
            '-f',  # Force overwrite
            '-n',  # Skip scraping phase
            str(source),
            str(output),
            str(log_file)
        ]
        
        stdout1, stderr1, rc1 = self._run_command(cmd)
        
        # Phase 2: Retry bad sectors
        self.logger.info("Phase 2: Retry bad sectors...")
        cmd = [
            'ddrescue',
            '-f',
            '-r', '3',  # 3 retry attempts
            str(source),
            str(output),
            str(log_file)
        ]
        
        stdout2, stderr2, rc2 = self._run_command(cmd)
        
        # Parse log for bad sectors
        bad_sectors = 0
        if log_file.exists():
            with open(log_file) as f:
                for line in f:
                    if 'non-tried' in line or 'non-trimmed' in line or 'bad-sector' in line:
                        bad_sectors += 1
        
        metadata = {
            'ddrescue_log': str(log_file),
            'bad_sectors_count': bad_sectors,
            'phase1_returncode': rc1,
            'phase2_returncode': rc2
        }
        
        return rc2 == 0, metadata
    
    def _image_with_ewfacquire(self, source: Path, output: Path) -> tuple:
        """Image with ewfacquire (Expert Witness Format)"""
        # ewfacquire creates .E01 files
        output_base = output.with_suffix('')
        
        cmd = [
            'ewfacquire',
            '-t', str(output_base),
            '-u',  # Unattended mode
            '-f', 'encase6',  # EnCase 6 format
            str(source)
        ]
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=3600)
        
        metadata = {
            'ewfacquire_returncode': returncode,
            'format': 'encase6'
        }
        
        return returncode == 0, metadata
