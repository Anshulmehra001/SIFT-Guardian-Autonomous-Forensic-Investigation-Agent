# Installation Guide

## Quick Start (3 minutes)

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Key

Get a FREE API key from Google Gemini: https://ai.google.dev/

Edit `config/config.yaml`:
```yaml
ai:
  provider: "gemini"
  model: "gemini-2.0-flash-exp"
  api_key: "YOUR-API-KEY-HERE"  # Replace this
```

### 3. Test Setup

```bash
python setup.py
```

### 4. Run Demo

```bash
python demo.py
```

## Done!

Now you can analyze files:
```bash
python investigate.py evidence/your_file.exe
```

---

## Optional: SIFT Tools (Advanced)

For full SIFT Workstation integration:

### Windows (WSL)
```bash
wsl --install Ubuntu
wsl
sudo apt update
sudo apt install strings file binwalk exiftool volatility3
```

### Linux
```bash
sudo apt install sift-cli
```

---

## Troubleshooting

**API Error?**
- Check your API key in `config/config.yaml`
- Get free key: https://ai.google.dev/

**Import Error?**
- Run: `pip install -r requirements.txt`

**Permission Error?**
- Windows: Run as Administrator
- Linux: Use `sudo` for SIFT tools

---

Need help? Check README.md
