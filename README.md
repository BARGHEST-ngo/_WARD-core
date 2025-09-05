# WARD Core v2.0.0-beta.1.2 — Standalone Engine

This is the standalone release of the WARD core engine — the backend engine of the main WARD software. The primary desktop application lives here: **[BARGHEST-ngo/_WARD-UI](https://github.com/BARGHEST-ngo/_WARD-UI)**.

Note: This engine is designed specifically for the [WARD app]((https://github.com/BARGHEST-ngo/_WARD-UI)) and thus, functionality exists purely on the basis of that _right now_. Usability of the core engine may be difficult for non-technical and heurstic results may be difficult to interpret when using the core engine.
This is because it's designed to be technical under the hood. If you are a non-technical user and wish to abstract away the technical aspects, you should usee the app first. For technical users, we will release development guides in the coming months. 

What is WARD? 

WARD is a modular, open-source, decentralised tool for **behavioural mobile forensics** and artifact acquisition using Android ADB–accessible data. It’s developed by **[BARGHEST](https://barghest.asia)**, a non-profit supporting the democratisation of threat intelligence in the majority world.
Heavily inspired by the legendary work that is [AndroidQF](https://github.com/botherder/androidqf) we wanted to take this further by enhancing coverage to forensics logs and building a heurstics behavioural pattern engine ontop for self-service forensics analysis providing a programmatic triaging mechanism. WARD collects and analyses a wide range of live-state system artifacts — crash logs, process/thread listings, diagnostic outputs, Wi-Fi manager logs, installed apps — to preserve forensic evidence and surface patterns that might indicate spyware or other unwanted activity.

Rather than vendor telemetry, malware signatures, or preloaded IOCs, WARD uses behavioral based heuristics to spot patterns of malicious behavior. Our current heurstics cover:

- *Memory analysis:* Signals against suspicious in-memory DEX loading, secondary DEX files from external storage, and shell-initiated code compilation that may indicate fileless malware or dynamic code injection.
- *System security:* Signals against persistence mechanisms, suspicious app behaviors, unusual service patterns, and malware-like activity patterns across system logs
- *Permission analysis:* Identifies dangerous permission abuse, privilege escalation attempts, and apps requesting excessive or suspicious permission combinations
- *Crash analysis:* Detects crash patterns that may indicate exploitation attempts, buffer/heap overflows, or targeted attacks against system components
- *Memory exploitation:* Attempts to identifies memory exploitation attempts synonymous with zero-click and one-click activity. It performs episode-based temporal analysis to identify memory corruption and exploitation attempts. Monitoring native crashes (SIGSEGV, SIGABRT, SIGBUS), heap exploitation (overflows, UAF, double-free), kernel driver abuse (Binder, GPU, futex, perf events), and high-value zero-click targets like media parsers, WebView, and system services. Related events are grouped within 15-second windows, applying scoring boosts for background zero-click exploits and dampening for user-triggered one-click crashes, while detecting repeated exploitation attempts and post-exploitation artifacts like HPROF dumps, OOM states, and log tampering.
- *User analysis:* Detects anomalous user interaction patterns and suspicious user behavior that may indicate compromise
- *System anomalies (disabled by default):* Catches general system irregularities and anomalous behaviors that don't fit other specific categories
- *Process anomalies (disabbled by default):* Monitors process creation patterns, suspicious process behaviors, and process-level indicators of compromise

This enables civil society, journalists, and investigators to run **self-service device triage**, making spyware identification more accessible to many.

> **Beta notice:** heuristics still require tuning across different OEMs; this is a beta test release.

---

## v2.0.0-beta.1.2

- **WARD Core as a package:** now a Python package (`ward-core`) that can be installed and used independently.  
- **Self-contained binaries:** pre-built executables for Windows, macOS, and Linux (no Python required).  
- **Preserved CLI:** existing command-line functionality maintained for backward compatibility.  
- **Enhanced metadata:** analysis results include engine and schema versions for better integration.

---

## Downloads

Choose the binary for your platform:

- **Windows x64:** `ward-core-v2.0.0-windows-x64.zip`  
- **Linux x64:** `ward-core-v2.0.0-linux-x64.zip`  
- **macOS Intel:** `ward-core-v2.0.0-macos-x64.zip`  
- **macOS Apple Silicon:** `ward-core-v2.0.0-macos-arm64.zip`

Each download includes **SHA-256 checksums** for verification.

---

## Usage

### Prerequisites

- **USB debugging** enabled on the device (Developer options).  
- **Android Debug Bridge (ADB)** installed and on your `PATH`. Required for live device collection; not needed when analysing existing logs.

Install “Android SDK Platform-Tools” and ensure `adb` is available on your system `PATH`.

---

## ADB Install Instructions

### Windows
1. Download: **[Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools)**  
2. Extract to `C:\Android\platform-tools` (or any folder).  
3. Add that folder to **PATH** (System Properties → Environment Variables → *Path* → **New**).  
4. Optional: install your device’s OEM USB driver if the device doesn’t appear.

### macOS
- With Homebrew:
  ```bash
  brew install android-platform-tools
  ```
- Or download from Google (link above) and add `platform-tools` to your `PATH`.

### Linux (Debian/Ubuntu)
```bash
sudo apt-get install android-tools-adb
```
Or download from Google (link above) and add `platform-tools` to your `PATH`.

### Verify ADB
```bash
adb version   # shows the installed version
adb devices   # should list your phone as "device" (authorise the USB debugging prompt)
```

---

## Binary Usage

Extract the ZIP and run the executable with a device connected to ADB:

```bash
# Windows (PowerShell/CMD)
.\ward-core.exe

# macOS/Linux
./ward-core
```

### CLI Options

```
--version                 Print engine version
--config <path>           Path to configuration file (optional; uses bundled default)
--device <serial>         Live collection from a specific ADB device
--logs <dir>              Analyse an existing log directory
--output <dir>            Output directory for results
--profile <name>          Collection profile (e.g., standard)
```

We **recommend reviewing** the default **[configuration file](https://github.com/BARGHEST-ngo/_WARD-core/blob/main/ward_core/config.yaml)** to understand available options.  
If you want features like **APK acquisition**, supply a **custom config** with `--config`.

---

## Forensic Artifacts Output

On completion, a full forensic snapshot is written under the collections root:

- **Default (no `--output`):**
  ```
  ./collections/YYYY/MM/<timestamp_model_serial>/
  ```
- **With `--output OUTPUT_DIR`:**
  ```
  OUTPUT_DIR/YYYY/MM/<timestamp_model_serial>/
  ```

Inside each scan folder you’ll find, among other files:

- **`Risk_assessment.json`** — a full breakdown of the device’s current security state based on the heuristics run.  
  Example indicating a behavioural detection for **[NoviSpy](https://www.amnesty.org/en/wp-content/uploads/2024/12/EUR7088132024ENGLISH.pdf)**:

  <img width="1282" height="1102" alt="Risk assessment example" src="https://github.com/user-attachments/assets/08966f7f-9001-405d-97f2-017c843838eb" />

---

## Python Package Usage

```bash
pip install ward-core

ward-core --version
python -m ward_core --version
```

### JSON Output Schema

```json
{
  "metadata": {
    "engineVersion": "2.0.0",
    "schemaVersion": 1
  },
  "heuristic_results": {},
  "overall_score": 0.0,
  "risk_level": "low"
}
```

**Full changelog:** https://github.com/BARGHEST-ngo/_WARD-core/commits/v2.0.0-beta.1

---

## Important Notes

- **Unsigned binaries:** macOS users may see Gatekeeper warnings — expected for unsigned binaries.  
- **Python 3.11+:** source installation requires Python 3.11 or later.  
- **Backward compatibility:** existing WARD workflows and integrations should continue working.  
- **ADB required:** for live device collection.  
- **First run on macOS:** may require *Right-click → Open* to bypass Gatekeeper.
