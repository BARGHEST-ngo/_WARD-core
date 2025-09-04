# WARD Core v2.0.0-beta.1.2 - Standalone Engine Release

This is the first standalone release of the WARD Core engine, this is the backend engine of the main WARD project. The main project is here: https://github.com/BARGHEST-ngo/_WARD-UI

WARD is a modular, open-source and decentralised tool for behavioral mobile forensics and acquisition using Android ADB–accessible data. It's developed by [BARGHEST](https://barghest.asia), a non-profit organization aiming to support the democratization of threat intelligence in the majority world.
It grabs and analyses a wide range of live-state system artifacts — crash logs, process and thread listings, diagnostic outputs, Wi-Fi manager logs, installed apps — to preserve forensic evidence and surface patterns that might indicate spyware or other unwanted activity.
Instead of relying on vendor telemetry, malware signatures, or preloaded IOCs, WARD uses heuristics to spot anomalies like:

    abnormal wakelock usage
    unexplained battery drain
    location misuse
    persistent background processes
    memory crashes

This lets civil society, journalists, and investigators run self-service device triage — making spyware identification more readily available to the many.

It should be noted that this is a beta test release, since heuristics require further tuning across various different OEMs. 

## v2.0.0-beta.1

- **WARD Core**:  is now a Python package (`ward-core`) that can be installed and used independently
- **Self-Contained Binaries**: Pre-built executables for Windows, macOS, and Linux - no Python installation required
- **Preserved CLI Interface**: All existing command-line functionality maintained for backward compatibility
- **Enhanced Metadata**: Analysis results include engine version and schema version for better integration

## Downloads

Choose the appropriate binary for your platform:

- **Windows x64**: `ward-core-v2.0.0-windows-x64.zip`
- **Linux x64**: `ward-core-v2.0.0-linux-x64.zip` 
- **macOS Intel**: `ward-core-v2.0.0-macos-x64.zip`
- **macOS Apple Silicon**: `ward-core-v2.0.0-macos-arm64.zip`

Each download includes SHA256 checksums for verification.

##  Usage

### Prerequisites: USB Debugging enabled on the device (Developer options)
### Prerequisites: Android Debug Bridge (ADB)

Required for live device collection. Not needed when analyzing existing logs.
Install “Android SDK Platform‑Tools” and ensure adb is on your PATH.


Install instructions

Windows
-Download: https://developer.android.com/tools/releases/platform-tools
-Extract to C:\Android\platform-tools (or any folder)
-Add that folder to PATH (System Properties → Environment Variables → Path → New)
-Optional: install your device’s OEM USB driver if the device doesn’t appear

macOS
-Homebrew: brew install android-platform-tools
-Or download from Google (link above) and add platform-tools to PATH

Linux (Debian/Ubuntu)
-sudo apt-get install android-tools-adb
-Or download from Google (link above) and add platform-tools to PATH

Verify ADB

-adb version → shows the installed version
-adb devices → should list your phone as device (authorize the USB debugging prompt on the device)

### Binary Usage
```bash
# Extract the ZIP and run the executable
./ward-core --version
./ward-core --config config.yaml --device DEVICE_SERIAL --output OUTPUT_DIR
./ward-core --config config.yaml --logs LOG_DIR --output OUTPUT_DIR

### Python Package Usage
pip install ward-core
ward-core --version
python -m ward_core --version

#### CLI reference
--version: Print engine version
--config <path>: Specify configuration file (optional, uses bundled default)
--device <serial>: Live collection from specific ADB device
--logs <dir>: Analyze existing log directory
--output <dir>: Output directory for results
--profile <name>: Collection profile (standard, etc.)

#### JSON Output Schema

{
  "metadata": {
    "engineVersion": "2.0.0",
    "schemaVersion": 1
  },
  "heuristic_results": { ... },
  "overall_score": 0.0,
  "risk_level": "low"
}

#### Forensics artifacts output

Default (no --output): ./collections\YYYY\MM\<timestamp_model_serial>\ relative to the current working directory
With --output OUTPUT_DIR: OUTPUT_DIR\YYYY\MM\<timestamp_model_serial>\

**Full Changelog**: https://github.com/BARGHEST-ngo/_WARD-core/commits/v2.0.0-beta.1

## Important notes

-Unsigned Binaries: macOS users may see Gatekeeper warnings - this is expected for unsigned binaries
-Python 3.11+: Source installation requires Python 3.11 or later
-Backward Compatibility: All existing WARD workflows and integrations should continue working
-ADB install is required
-First-run on macOS may require right-click → Open to bypass Gatekeeper
