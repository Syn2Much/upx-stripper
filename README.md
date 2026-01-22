# NoMoreUPX! 

A Python script to detect and/or remove UPX strings from packed binary executables with comprehensive logging and error handling.

## Features

- **Detection:** 28+ UPX strings/artifacts (magic bytes, section names, URLs, metadata, version strings)
- **Smart Binary Detection:** Automatically identifies binary files and skips text files to prevent corruption
- **Obfuscation:** Mixed padding strategies (valid x86-looking bytes, structured noise, true randomness)
- **Backups:** Auto backup folder, hashed filenames, comprehensive `operation.log`, rollback-friendly
- **Logging:** Optional file logging with debug information for better troubleshooting
- **CLI:** File/dir support, `--dry-run`, `--verbose`, `--log`, built-in help

## Installation

```bash
chmod +x noMoreUPX.py
sudo cp noMoreUPX.py /usr/local/bin/nomoreupx  # optional
```

**Requirements:** Python 3.6+ (stdlib only)

## Usage

```bash
# Single file
python3 noMoreUPX.py suspicious.exe

# Directory (recursive)
python3 noMoreUPX.py ./samples/

# Scan only (dry run)
python3 noMoreUPX.py target.bin --dry-run

# Verbose output
python3 noMoreUPX.py ./samples/ --verbose

# With debug logging
python3 noMoreUPX.py target.bin --log debug.log

# Combined options
python3 noMoreUPX.py ./samples/ --dry-run --verbose --log scan.log
```

## Command-Line Options

```
positional arguments:
  target                File or directory to process

optional arguments:
  -h, --help            Show help message and exit
  -d, --dry-run         Scan for UPX patterns without modifying files
  -v, --verbose         Show detailed information during processing
  -l, --log FILE        Write debug log to specified file
```

## What it does (High Level)

1. **Detects** common UPX markers (strings/sections/URLs/etc.)
2. **Creates backups** in a timestamped folder (with hashed names + comprehensive log)
3. **Replaces** detected markers with realistic, high-entropy padding (unique per hit)
4. **Logs** all operations with detailed information for debugging

## Advanced Features

### Binary File Detection
The tool automatically detects binary files by:
- Sampling the first 8KB of each file
- Checking for null bytes and binary indicators
- Analyzing ASCII printability ratios
- Preventing accidental modification of text files

### Comprehensive Logging
Enable debug logging with the `--log` option:
```bash
python3 noMoreUPX.py ./samples/ --log operation_debug.log
```

This creates a detailed log file with:
- Timestamp information
- All operations performed
- Errors and warnings
- Debug messages for troubleshooting

### Error Recovery
The tool includes robust error handling for:
- Permission denied scenarios
- Out of memory conditions
- Corrupted files
- Interrupted operations

## Output Example

```
==============================================================
                     PROCESSING SUMMARY
==============================================================
  Files processed:       15
  Files modified:        3
  UPX patterns found:    5
  Total replacements:    8
  Backup location:       /path/to/backup_samples_20260122_143022
  Operation log:         /path/to/backup_samples_20260122_143022/operation.log
==============================================================
```

## Operation Log

The `operation.log` file in the backup directory contains:
- Date and time of operation
- Target path processed
- Summary statistics
- Per-file details including patterns found and replacements made
- Error information for failed files

## Notes

- Always run **`--dry-run` first** and test on copies
- Check `operation.log` inside the backup directory for detailed results
- Use `--log` option for debugging in case of issues
- Large files (>100MB) are automatically skipped
- Backups are automatically created before modification

## Version History

- **v2.0** (Current) - Added logging, type hints, binary detection, enhanced error handling
- **v1.0** - Initial release with core functionality

## License / Disclaimer

**Educational use only.** Use responsibly and only with proper authorization.

**Author:** Syn • **Version:** 2.0 (Improved) • **Build:** 2026-01-09
