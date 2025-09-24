import os
import re
import json
import math
import uuid
import struct
from datetime import datetime

from pathlib import Path
from fastmcp import FastMCP
from hexdump import hexdump
from collections import Counter
from magika import Magika, PredictionMode
from tempfile import NamedTemporaryFile, gettempdir
from subprocess import check_output, CalledProcessError



mcp = FastMCP(
    name="Binwalk MCP Server",
    instructions="""
        This server provides firmware analysis tools.
        # Steps to analyze a firmware:
        1. Call get_file_type_from_file() to get the file type of the firmware;
        2. Call get_hexdump() to get the hexdump of the firmware header, offset pointers may be inside the header or after the header;
        3. If the hexdump is not helpful, call extract() to extract the firmware;
        4. Analyze **all** extracted partitions and files with available codes. 
        4.0. List all files under a certain partition;
        4.1. Use rizin to analyze extracted ELF files, find useful information, such as strings, symbols, etc;
        4.2. Use strings to extract strings from extracted files;
        4.3. Use binwalk recursively to analyze extracted files whose type is unknown;
        # Hints:
        1. dtb file always contains useful information, such as partition table, partition name, partition size, partition offset, etc;
        2. the entropy of encrypted data is always high;
    """
)

# TODO: support something like old `binwalk -A`

@mcp.tool
def get_file_type_from_file(fw_path: str) -> dict:
    """
    Identify the file type of a firmware or extracted partition.
    
    Uses Magika AI-based file type detection to accurately determine 
    the format of firmware images and extracted components.
    
    Args:
        fw_path: Absolute path to the firmware file or extracted component
        
    Returns:
        dict: Contains 'file_type' key with detected file format label,
              or 'error' key if file doesn't exist
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    m = Magika(prediction_mode=PredictionMode.BEST_GUESS)
    result = m.identify_path(Path(fw_path))
    return {"file_type": result.output.label}

@mcp.tool
def get_file_type_from_bytes(fw_chunk: str) -> dict:
    """
    Identify file type from a binary data chunk.
    
    Useful for analyzing extracted data chunks without writing to disk.
    Supports various binary formats including firmware headers.
    
    Args:
        fw_chunk: Binary data as string (will be encoded to bytes)
        
    Returns:
        dict: Contains 'file_type' key with detected format label
    """
    m = Magika(prediction_mode=PredictionMode.BEST_GUESS)
    result = m.identify_bytes(fw_chunk.encode('latin-1'))
    return {"file_type": result.output.label}

@mcp.tool
def get_mapping(fw_path: str) -> dict:
    """
    Generate partition map of firmware image using binwalk signature scanning.
    
    Scans the firmware for known file signatures, filesystem markers, and 
    partition boundaries to create a comprehensive map of embedded components.
    
    Args:
        fw_path: Path to firmware image file
        
    Returns:
        dict: Partition mapping with offset, size, and type information,
              or error dict if file doesn't exist or scan fails
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    with NamedTemporaryFile(delete_on_close=False, suffix=".json") as fp:
        try:
            _ = check_output(["binwalk",
                              f"--log", fp.name,
                              fw_path])
        except CalledProcessError as e:
            _ = e.output
        fp.seek(0)
        data = json.load(fp)
        return data[0] if data else dict(error=f"No data found: {fw_path}")

@mcp.tool
def get_chunk(fw_path: str, head_offset: int, tail_offset: int) -> dict:
    """
    Extract a specific data chunk from firmware image.
    
    Enables targeted analysis of specific regions like bootloaders, 
    filesystem headers, or embedded certificates.
    
    Args:
        fw_path: Path to firmware file
        head_offset: Starting byte offset (inclusive)
        tail_offset: Ending byte offset (exclusive)
        
    Returns:
        dict: Contains 'chunk' key with extracted data as string,
              or error dict if file/range is invalid
              
    Raises:
        ValueError: If offset range is invalid
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    with open(fw_path, "rb") as fp:
        data = fp.read()
        return {"chunk": data[head_offset:tail_offset].decode('latin-1')}

@mcp.tool
def get_hexdump(fw_path: str, head_offset: int, tail_offset: int) -> dict:
    """
    Generate formatted hexadecimal dump of firmware region.
    
    Provides both raw hex and formatted hexdump views for analyzing 
    firmware headers, magic numbers, and data structures.
    
    Args:
        fw_path: Firmware file path
        head_offset: Starting byte offset for dump
        tail_offset: Ending byte offset for dump
        
    Returns:
        dict: Contains both formatted hexdump and raw hex data:
            - readable_hexdump: Formatted hexdump with addresses
            - readable_hex: Raw hex data as string
            
    Use Cases:
        - Analyzing firmware headers
        - Identifying magic numbers/Signatures
        - Inspecting filesystem metadata
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    with open(fw_path, "rb") as fp:
        data = fp.read()
        data_selected_hex = data[head_offset:tail_offset]
        data_selected_hexdump = hexdump(data[head_offset:tail_offset], result="return")
        return {
            "readable_hex": data_selected_hex.decode('latin-1'),
            "readable_hexdump": data_selected_hexdump
        }

@mcp.tool
def extract(fw_path: str, recursive: bool = False) -> dict:
    """
    Extract firmware contents using binwalk automated extraction.
    
    Performs signature-based extraction of embedded filesystems, 
    kernels, bootloaders, and other components into a temporary directory.
    
    Args:
        fw_path: Path to firmware image file
        recursive: Enable recursive extraction of found components
        
    Returns:
        dict: Extraction results including output directory and extracted files,
              or error dict if extraction fails
              
    Output Structure:
        {
            "extracted_to": "/tmp/extracted_12345/",
            "files": [...],
            "logs": [...]
        }
        
    Note:
        Extracted files are placed in a unique temp directory to avoid conflicts
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    with NamedTemporaryFile(delete_on_close=False, suffix=".json") as fp:
        recursive_option = "-e" if not recursive else "-e"
        output_directory = os.path.join(gettempdir(), str(uuid.uuid4()))
        try:
            _ = check_output(["binwalk",
                              f"--log", fp.name,
                              recursive_option,
                              "--directory", output_directory,
                              fw_path])
        except CalledProcessError as e:
            _ = e.output
        fp.seek(0)
        data = json.load(fp)
        return data[0] if data else dict(error=f"No data extracted: {fw_path}")

@mcp.tool
def list_all_files(fw_extracted_directory: str) -> dict:
    """
    Catalog all files from extracted firmware with type identification.
    
    Recursively scans extraction directory and identifies file types 
    for all discovered components using AI-based detection.
    
    Args:
        fw_extracted_directory: Path to binwalk extraction directory
        
    Returns:
        dict: Contains 'file_maps' with path-to-type mapping:
            {
                "file_maps": {
                    "/tmp/extract_123/kernel": "linux-kernel",
                    "/tmp/extract_123/rootfs/etc/passwd": "text/plain"
                }
            }
            
    Skips:
        - Symbolic links (to prevent cycles)
        - Non-existent files
    """
    if not os.path.exists(fw_extracted_directory):
        return {"error": f"Directory not exists: {fw_extracted_directory}"}
    m = Magika(prediction_mode=PredictionMode.BEST_GUESS)
    file_maps = dict()
    for root, dirs, files in os.walk(fw_extracted_directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path):
                continue
            file_maps[file_path] = m.identify_path(Path(file_path)).output.label
    return {"file_maps": file_maps}

@mcp.tool
def calculate_entropy(fw_chunk: str) -> float:
    """
    Calculate Shannon entropy of binary data chunk.
    
    Measures randomness/uncertainty in data, useful for:
    - Detecting encrypted/compressed regions
    - Identifying packed code sections
    - Finding high-entropy keys/certificates
    
    Args:
        fw_chunk: Binary data string to analyze
        
    Returns:
        float: Normalized entropy value (0.0 = low entropy, 1.0 = high entropy)
        
    Interpretation:
        Higher entropy means more randomness/uncertainty in data, which is common in encrypted/compressed regions
    """
    if not fw_chunk:
        return 0.0
    byte_counts = Counter(fw_chunk)
    total_bytes = len(fw_chunk)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy / 8.0

@mcp.tool
def extract_strings(file_path: str, min_length: int = 4, encoding: str = "s") -> dict:
    """
    Extract human-readable strings from binary firmware components.
    
    Uses system 'strings' utility to find printable ASCII/Unicode sequences,
    revealing configuration data, URLs, version strings, and debug info.
    
    Args:
        file_path: Target file path for string extraction
        min_length: Minimum consecutive printable characters (default: 4)
        encoding: String encoding type:
            - 's': 7-bit ASCII (default)
            - 'S': 8-bit extended ASCII
            - 'b': 16-bit big-endian Unicode
            - 'l': 16-bit little-endian Unicode
            
    Returns:
        dict: Contains extracted strings and analysis metadata:
            {
                "strings": ["Linux version 4.9", "admin:password123"],
                "count": 42,
                "min_length": 4,
                "encoding": "s"
            }
            
    Common Use Cases:
        - Finding hardcoded credentials
        - Extracting version/build info
        - Discovering configuration URLs
        - Identifying debug symbols
    """
    if not os.path.exists(file_path):
        return {"error": f"File not exists: {file_path}"}
    try:
        output = check_output([
            "strings",
            f"-{encoding}",
            f"-n{min_length}",
            file_path
        ], text=True)

        strings = [line.strip() for line in output.split('\n') if line.strip()]
        
        return {
            "strings": strings,
            "count": len(strings),
            "min_length": min_length,
            "encoding": encoding,
            "file_path": file_path
        }

    except CalledProcessError as e:
        return {"error": f"Failed to extract strings: {str(e)}"}
    except FileNotFoundError:
        return {"error": "strings command not found. Please install binutils"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


if __name__ == "__main__":
    print("Starting Rizin MCP server...")
    mcp.run()