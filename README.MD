# Binwalk MCP Server
A powerful Model Context Protocol (MCP) server that provides advanced firmware analysis capabilities using binwalk and related tools. This server enables AI assistants to analyze, extract, and inspect firmware images with comprehensive tooling support.

## Features
- **Firmware Analysis**: Identify file types and analyze firmware structures
- **Hexdump Generation**: Generate readable hex dumps of firmware regions
- **Partition Mapping**: Discover and map all partitions within firmware images
- **Extraction**: Extract firmware contents with optional recursive analysis
- **File Type Detection**: Identify file types of extracted components using Magika
- **Entropy Analysis**: Calculate data entropy to detect encryption/compression
- **Comprehensive Tooling**: Integrated support for multiple firmware analysis tools
## Installation
### Prerequisites
```bash
chmod +x setup.sh
./setup.sh
```
## Usage
```bash=
fastmcp run server.py:mcp --transport sse --host 0.0.0.0 --port 8000
```

## Available Tools
The server provides the following tools for firmware analysis:

1. File Type Identification
- `get_file_type_from_file`: Identify file type from a local file path
- `get_file_type_from_bytes`: Identify file type from binary data
2. Firmware Mapping
- `get_mapping`: Get partition mapping of firmware using binwalk
3. Hexdump Analysis
- `get_hexdump`: Generate hexdump of specific firmware regions
4. Extraction
- `extract`: Extract firmware contents with optional recursive analysis
5. File Enumeration
- `list_all_files`: List all files extracted by binwalk with their types
6. Entropy Analysis
- `calculate_entropy`: Calculate entropy of binary data (0.0-1.0 scale)


