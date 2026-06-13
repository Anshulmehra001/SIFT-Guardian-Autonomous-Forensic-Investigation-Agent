# SIFT Guardian - Autonomous Forensic Investigation Agent

Self-correcting AI agent for digital forensics and incident response. Analyzes evidence using real forensic techniques combined with AI reasoning to produce validated, evidence-based findings.

## What It Does

SIFT Guardian autonomously investigates forensic evidence by:

1. **Real Forensic Analysis** - Calculates hashes, analyzes entropy, extracts strings, parses PE files
2. **Malware Detection** - Scans for 50+ threat indicators across 8 categories
3. **Self-Correction** - Validates findings, detects contradictions, re-investigates when needed
4. **Report Generation** - Produces professional incident response reports with MITRE ATT&CK mappings

## Key Features

- **Evidence-Based Findings**: All conclusions backed by verifiable forensic data (SHA-256 hashes, entropy scores, pattern matches)
- **Self-Correction System**: Agent checks its own findings for contradictions and low confidence, automatically re-investigating when needed
- **Security Guardrails**: Command whitelisting, path sanitization, input validation prevent unsafe operations
- **Audit Trail**: Complete SHA-256 chain-of-custody logs all operations
- **SIFT Integration**: Ready to orchestrate SIFT Workstation tools via WSL/Ubuntu
- **Multi-Provider AI**: Works with Google Gemini (FREE), Groq, Claude, or Ollama

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure API key (get free key from https://ai.google.dev/)
python setup.py

# 3. Run demonstration
python demo.py

# 4. Analyze evidence
python investigate.py evidence/suspicious_sample.py
```

## Installation

See [INSTALL.md](INSTALL.md) for detailed setup instructions.

## Usage

### Basic Investigation

```bash
python investigate.py path/to/evidence.dd
```

### With Options

```bash
# Specify AI provider
python investigate.py --provider groq evidence.dd

# Custom case ID
python investigate.py --case-id CASE-2024-001 evidence.dd

# Verbose mode
python investigate.py -v evidence.dd

# Check system status
python investigate.py status
```

## How It Works

### Investigation Workflow

```
1. Evidence Validation
   ├─ File integrity check (SHA-256)
   ├─ Path validation
   └─ Security guardrails

2. Real Forensic Analysis
   ├─ Hash calculation (MD5, SHA1, SHA256)
   ├─ Entropy analysis (detect packing/encryption)
   ├─ String extraction (URLs, IPs, commands)
   ├─ PE file parsing (Windows executables)
   └─ YARA-style pattern matching (50+ rules)

3. Finding Generation
   ├─ Malware indicators (trojan, ransomware, etc.)
   ├─ Suspicious characteristics (high entropy, etc.)
   ├─ Confidence scoring (0.0 - 1.0)
   └─ Severity assessment (critical/high/medium/low)

4. Self-Correction Loop
   ├─ Check confidence threshold (< 0.75)
   ├─ Detect contradictions
   ├─ Validate evidence cross-references
   └─ Re-investigate low-confidence findings

5. Report Generation
   ├─ Executive summary
   ├─ Detailed findings with evidence
   ├─ MITRE ATT&CK mappings
   └─ Recommendations
```

### Self-Correction System

The agent validates its own findings by checking for:

- **Low Confidence** (< 0.75 threshold) → Re-investigate
- **Logical Contradictions** → Compare with existing findings
- **Temporal Impossibility** → Verify timeline consistency
- **Severity Mismatch** → Check same evidence rated differently
- **Insufficient Evidence** → Require multiple corroborating artifacts

When issues detected, the agent generates a re-investigation prompt and produces corrected findings with higher confidence.

## Architecture

```
┌──────────────────────────────────────────────────┐
│           Investigator (Main Agent)              │
│  • Evidence validation & integrity               │
│  • Investigation planning                        │
│  • Finding coordination                          │
│  • Self-correction orchestration                 │
└────────────────────┬─────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
┌────────▼───────────▼───────────▼─────────────────┐
│         Forensic Analysis Layer                  │
│  • FileAnalyzer: Hash, entropy, strings, PE      │
│  • YARAScanner: 50+ malware patterns             │
│  • SIFTToolExecutor: External tool integration   │
└────────┬─────────────────────────────────────────┘
         │
┌────────▼─────────────────────────────────────────┐
│       Self-Correction System                     │
│  • Contradiction detection                       │
│  • Confidence validation                         │
│  • Re-investigation trigger                      │
│  • Finding correction                            │
└──────────────────────────────────────────────────┘
         │
┌────────▼─────────────────────────────────────────┐
│       Security & Audit Layer                     │
│  • Command whitelist                             │
│  • Path sanitization                             │
│  • SHA-256 audit chain                           │
│  • Evidence chain-of-custody                     │
└──────────────────────────────────────────────────┘
```

## What's Real vs AI?

### 100% Real Forensic Analysis

✅ **File hashing** (MD5, SHA1, SHA256) - Verifiable against external tools  
✅ **Entropy calculation** - Mathematical analysis for detecting packing/encryption  
✅ **String extraction** - Byte-level parsing of binary files  
✅ **PE file parsing** - Windows executable structure analysis  
✅ **YARA-style patterns** - 50+ malware indicators across 8 categories  
✅ **Risk scoring** - Algorithm-based threat assessment  

### AI Enhancement (Not Replacement)

📊 **Investigation planning** - Strategy for evidence analysis  
📊 **Finding summarization** - Natural language report generation  
📊 **Re-investigation prompts** - Self-correction guidance  
📊 **Contextual analysis** - Human-readable conclusions  

**All findings are evidence-based. AI provides reasoning and context, not the underlying forensic analysis.**

## Malware Detection

YARA-style pattern matching across 8 threat categories:

| Category | Patterns | Severity |
|----------|----------|----------|
| Ransomware | WannaCry, Ryuk, encryption markers | Critical |
| Trojan | RAT, C2_SERVER, backdoor | High |
| Credential Theft | mimikatz, keylogger, LSASS | High |
| Persistence | Registry Run keys, schtasks | High |
| PowerShell Abuse | -enc, Invoke-Expression, DownloadString | Medium |
| Obfuscation | base64, xor, encoding | Medium |
| Lateral Movement | PsExec, WMI, admin$ | High |
| Data Exfiltration | FTP, compression, upload | High |

## Output

### Investigation Reports

Saved to `reports/CASE-ID_report.markdown`:
- Executive summary
- Evidence analysis
- Detailed findings with confidence scores
- Self-correction history
- MITRE ATT&CK mappings
- Recommendations

### Audit Logs

Saved to `audit_logs/CASE-ID_audit.json`:
- Tool execution trace
- Finding generation events
- Self-correction decisions
- SHA-256 integrity chain
- Complete chain-of-custody

## Example Output

```
📊 Investigation Results

Case ID: CASE-20240614-123456
Status: complete
Duration: 12.3 seconds
Findings: 3

┌──────────────┬──────────┬────────────┬─────────────────────────────┬───────────┐
│ ID           │ Severity │ Confidence │ Description                 │ Corrected │
├──────────────┼──────────┼────────────┼─────────────────────────────┼───────────┤
│ FIND-001     │ HIGH     │ 0.90       │ Malware indicators detected │           │
│ FIND-002     │ MEDIUM   │ 0.75       │ High entropy detected       │           │
│ FIND-003     │ MEDIUM   │ 0.82       │ Suspicious strings found    │ ✓         │
└──────────────┴──────────┴────────────┴─────────────────────────────┴───────────┘
```

## Technical Stack

- **Language**: Python 3.8+
- **AI Providers**: Google Gemini, Groq, Anthropic Claude, Ollama
- **Forensics**: Custom file analysis, YARA-style pattern matching
- **Security**: Command whitelisting, input validation, audit logging
- **Integration**: WSL/Ubuntu for SIFT Workstation tools

## Project Structure

```
sift-guardian/
├── config/              # Configuration files
├── src/
│   ├── agent/           # Investigation agent, self-corrector
│   ├── ai/              # AI provider integrations
│   ├── forensics/       # File analysis, malware detection
│   ├── security/        # Guardrails, validation
│   ├── audit/           # Audit logging
│   └── tools/           # SIFT tool integration
├── docs/                # Architecture and testing docs
├── evidence/            # Sample files
├── demo.py              # Quick demonstration
├── investigate.py       # Main CLI
└── setup.py             # Configuration helper
```

## Documentation

- **INSTALL.md** - Detailed installation and setup
- **docs/ARCHITECTURE.md** - System design and implementation
- **docs/ACCURACY_REPORT.md** - Testing methodology and results
- **docs/DEMO_SCRIPT.md** - Demo video guide

## Requirements

- Python 3.8 or higher
- Internet connection (for AI API)
- 100MB disk space
- Optional: WSL/Ubuntu for SIFT tools

## Security

Built-in security controls:

- **Command Whitelist**: Only approved forensic tools can execute
- **Path Sanitization**: Prevents directory traversal attacks
- **Input Validation**: Blocks command injection attempts
- **Audit Logging**: SHA-256 chain tracks all operations
- **Read-Only Analysis**: Never modifies evidence files

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

Built for SANS Find Evil! Hackathon 2026. Uses Google Gemini AI for reasoning while maintaining real forensic analysis at the core.

---

**Note**: This is a demonstration of autonomous investigation with self-correction. For production use, consider expanding YARA rules, adding memory analysis capabilities, and integrating additional forensic tools from the SIFT Workstation.
