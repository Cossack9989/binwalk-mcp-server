import os
import json
import math
import uuid

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
        get the file type of a local firmware, or a part extracted from a firmware.
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    m = Magika(prediction_mode=PredictionMode.BEST_GUESS)
    result = m.identify_path(Path(fw_path))
    return {"file_type": result.output.label}

@mcp.tool
def get_file_type_from_bytes(fw_chunk: str) -> dict:
    """get the file type of a chunk of firmware."""
    m = Magika(prediction_mode=PredictionMode.BEST_GUESS)
    result = m.identify_bytes(fw_chunk.encode('latin-1'))
    return {"file_type": result.output.label}

@mcp.tool
def get_mapping(fw_path: str) -> dict:
    """
        get the mapping of all possible partitions inside a local firmware.
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
    get a chunk of firmware from a local firmware.
    """
    if not os.path.exists(fw_path):
        return {"error": f"File not exists: {fw_path}"}
    with open(fw_path, "rb") as fp:
        data = fp.read()
        return {"chunk": data[head_offset:tail_offset].decode('latin-1')}

@mcp.tool
def get_hexdump(fw_path: str, head_offset: int, tail_offset: int) -> dict:
    """
        get the hexdump of specified region of a local firmware.
        usually be used for figuring out the header structure of a firmware whose type is unknown.
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
def extract(fw_path: str, recursive: bool = False):
    """
        extract a local firmware.
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
        list all files extracted by binwalk.
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
def calculate_entropy(fw_chunk: str):
    """Calculate the entropy of a chunk of firmware, 0.0 is the lowest, 1.0 is the highest"""
    if not fw_chunk:
        return 0.0
    byte_counts = Counter(fw_chunk)
    total_bytes = len(fw_chunk)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy / 8.0