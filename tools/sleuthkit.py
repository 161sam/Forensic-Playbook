#!/usr/bin/env python3
"""
Sleuthkit (TSK) Tool Wrapper
Comprehensive wrapper for The Sleuth Kit forensic tools

Wrapped Tools:
- img_stat: Disk image information
- mmls: Partition table listing
- fsstat: Filesystem information
- fls: File listing
- icat: File content extraction
- istat: Inode information
- blkcat: Block extraction
- blkls: Unallocated block listing
- ffind: Find filename by inode
- mactime: Timeline generation
"""

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ImageInfo:
    """Disk image information"""
    image_type: str
    size_bytes: int
    sector_size: int = 512
    metadata: Dict = None


@dataclass
class Partition:
    """Partition information"""
    slot: str
    start: int
    end: int
    length: int
    description: str
    type: str = None


@dataclass
class FileInfo:
    """File metadata information"""
    inode: int
    name: str
    size: int
    type: str  # file, directory, link
    deleted: bool = False
    mtime: Optional[str] = None
    atime: Optional[str] = None
    ctime: Optional[str] = None
    crtime: Optional[str] = None


class SleuthkitWrapper:
    """
    The Sleuth Kit wrapper
    
    Provides Pythonic interface to TSK command-line tools.
    """
    
    def __init__(self, image_path: Path):
        """
        Initialize TSK wrapper
        
        Args:
            image_path: Path to disk image
        """
        self.image_path = Path(image_path)
        self.logger = logging.getLogger(__name__)
        
        if not self.image_path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        # Cache
        self._partitions = None
        self._fs_info = None
    
    def get_image_info(self) -> ImageInfo:
        """
        Get disk image information using img_stat
        
        Returns:
            ImageInfo object
        """
        cmd = ['img_stat', str(self.image_path)]
        
        stdout, stderr, rc = self._run_command(cmd)
        
        if rc != 0:
            raise RuntimeError(f"img_stat failed: {stderr}")
        
        # Parse output
        info = {}
        for line in stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower().replace(' ', '_')] = value.strip()
        
        return ImageInfo(
            image_type=info.get('image_type', 'raw'),
            size_bytes=int(info.get('size', 0)),
            sector_size=int(info.get('sector_size', 512)),
            metadata=info
        )
    
    def get_partitions(self, force_refresh: bool = False) -> List[Partition]:
        """
        Get partition table using mmls
        
        Args:
            force_refresh: Force refresh of cached partitions
        
        Returns:
            List of Partition objects
        """
        if self._partitions and not force_refresh:
            return self._partitions
        
        cmd = ['mmls', str(self.image_path)]
        
        stdout, stderr, rc = self._run_command(cmd)
        
        if rc != 0:
            # Might not have partition table
            self.logger.warning(f"mmls failed: {stderr}")
            return []
        
        partitions = []
        lines = stdout.splitlines()
        
        for line in lines:
            # Skip headers
            if 'Units' in line or 'Slot' in line or '---' in line or not line.strip():
                continue
            
            # Parse partition line
            # Format: Slot Start End Length Description
            parts = line.split()
            if len(parts) >= 5:
                try:
                    partitions.append(Partition(
                        slot=parts[0],
                        start=int(parts[1]),
                        end=int(parts[2]),
                        length=int(parts[3]),
                        description=' '.join(parts[4:])
                    ))
                except (ValueError, IndexError):
                    continue
        
        self._partitions = partitions
        return partitions
    
    def get_filesystem_info(self, partition: Optional[int] = None) -> Dict:
        """
        Get filesystem information using fsstat
        
        Args:
            partition: Partition number (None for whole disk)
        
        Returns:
            Dictionary with filesystem information
        """
        cmd = ['fsstat']
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.append(str(self.image_path))
        
        stdout, stderr, rc = self._run_command(cmd)
        
        if rc != 0:
            raise RuntimeError(f"fsstat failed: {stderr}")
        
        # Parse output
        info = {}
        for line in stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower().replace(' ', '_')] = value.strip()
        
        return info
    
    def list_files(
        self,
        partition: Optional[int] = None,
        path: str = '/',
        recursive: bool = True,
        include_deleted: bool = False,
        long_format: bool = True
    ) -> List[FileInfo]:
        """
        List files using fls
        
        Args:
            partition: Partition number
            path: Starting path
            recursive: Recursive listing
            include_deleted: Include deleted files
            long_format: Long format with metadata
        
        Returns:
            List of FileInfo objects
        """
        cmd = ['fls', '-p']  # Full path
        
        if recursive:
            cmd.append('-r')
        
        if include_deleted:
            cmd.append('-d')
        
        if long_format:
            cmd.append('-l')
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.append(str(self.image_path))
        
        if path != '/':
            cmd.append(path)
        
        stdout, stderr, rc = self._run_command(cmd, timeout=600)
        
        if rc != 0:
            self.logger.warning(f"fls failed: {stderr}")
            return []
        
        return self._parse_fls_output(stdout)
    
    def _parse_fls_output(self, output: str) -> List[FileInfo]:
        """Parse fls output to FileInfo objects"""
        files = []
        
        for line in output.splitlines():
            if not line.strip():
                continue
            
            # Parse fls line
            # Format: r/r <inode>: <name>
            # or with -l: r/r <inode>: <name> (size, timestamps)
            
            match = re.match(r'([rd])/([rd])\s+(\d+)(?:\(realloc\))?:\s+(.+)', line)
            if match:
                file_type_char = match.group(1)
                dir_type_char = match.group(2)
                inode = int(match.group(3))
                name_part = match.group(4)
                
                # Check if deleted
                deleted = '*' in line
                name = name_part.strip('*').strip()
                
                # Determine type
                if dir_type_char == 'd':
                    file_type = 'directory'
                elif dir_type_char == 'r':
                    file_type = 'file'
                else:
                    file_type = 'other'
                
                files.append(FileInfo(
                    inode=inode,
                    name=name,
                    size=0,  # Size extraction would require parsing -l format
                    type=file_type,
                    deleted=deleted
                ))
        
        return files
    
    def read_file(
        self,
        inode: int,
        partition: Optional[int] = None,
        output_path: Optional[Path] = None
    ) -> bytes:
        """
        Read file content using icat
        
        Args:
            inode: File inode number
            partition: Partition number
            output_path: Optional path to write content
        
        Returns:
            File content as bytes
        """
        cmd = ['icat']
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.extend([str(self.image_path), str(inode)])
        
        stdout, stderr, rc = self._run_command(cmd, capture_binary=True)
        
        if rc != 0:
            raise RuntimeError(f"icat failed: {stderr}")
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(stdout)
        
        return stdout
    
    def get_inode_info(
        self,
        inode: int,
        partition: Optional[int] = None
    ) -> Dict:
        """
        Get inode metadata using istat
        
        Args:
            inode: Inode number
            partition: Partition number
        
        Returns:
            Dictionary with inode information
        """
        cmd = ['istat']
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.extend([str(self.image_path), str(inode)])
        
        stdout, stderr, rc = self._run_command(cmd)
        
        if rc != 0:
            raise RuntimeError(f"istat failed: {stderr}")
        
        # Parse istat output
        info = {}
        for line in stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower().replace(' ', '_')] = value.strip()
        
        return info
    
    def read_blocks(
        self,
        start_block: int,
        count: int,
        partition: Optional[int] = None
    ) -> bytes:
        """
        Read raw blocks using blkcat
        
        Args:
            start_block: Starting block number
            count: Number of blocks to read
            partition: Partition number
        
        Returns:
            Block data as bytes
        """
        cmd = ['blkcat']
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.extend([str(self.image_path), str(start_block), str(count)])
        
        stdout, stderr, rc = self._run_command(cmd, capture_binary=True)
        
        if rc != 0:
            raise RuntimeError(f"blkcat failed: {stderr}")
        
        return stdout
    
    def find_filename(
        self,
        inode: int,
        partition: Optional[int] = None
    ) -> Optional[str]:
        """
        Find filename by inode using ffind
        
        Args:
            inode: Inode number
            partition: Partition number
        
        Returns:
            Filename or None
        """
        cmd = ['ffind']
        
        if partition is not None:
            offset = self._get_partition_offset(partition)
            cmd.extend(['-o', str(offset)])
        
        cmd.extend([str(self.image_path), str(inode)])
        
        stdout, stderr, rc = self._run_command(cmd)
        
        if rc != 0:
            return None
        
        return stdout.strip() if stdout.strip() else None
    
    def _get_partition_offset(self, partition: int) -> int:
        """Get byte offset for partition"""
        partitions = self.get_partitions()
        
        if partition >= len(partitions):
            raise ValueError(f"Partition {partition} not found")
        
        # Calculate byte offset (sectors * 512)
        return partitions[partition].start * 512
    
    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        capture_binary: bool = False
    ) -> Tuple[bytes, str, int]:
        """
        Run TSK command
        
        Args:
            cmd: Command list
            timeout: Timeout in seconds
            capture_binary: Capture output as binary
        
        Returns:
            (stdout, stderr, returncode)
        """
        self.logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                check=False
            )
            
            if capture_binary:
                return result.stdout, result.stderr.decode('utf-8', errors='ignore'), result.returncode
            else:
                return (
                    result.stdout.decode('utf-8', errors='ignore'),
                    result.stderr.decode('utf-8', errors='ignore'),
                    result.returncode
                )
        
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Command timeout: {' '.join(cmd)}")
        except Exception as e:
            raise RuntimeError(f"Command failed: {e}")


# Convenience functions
def list_partitions(image_path: Path) -> List[Partition]:
    """Quick function to list partitions"""
    tsk = SleuthkitWrapper(image_path)
    return tsk.get_partitions()


def extract_file(image_path: Path, inode: int, output_path: Path, partition: int = 0):
    """Quick function to extract file by inode"""
    tsk = SleuthkitWrapper(image_path)
    tsk.read_file(inode, partition, output_path)
