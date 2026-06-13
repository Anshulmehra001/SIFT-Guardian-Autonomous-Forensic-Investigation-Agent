#!/usr/bin/env python3
"""
SIFT Guardian - Setup
Run this first to check configuration
"""

import sys
import yaml
from pathlib import Path


def main():
    print("\n" + "="*70)
    print("SIFT GUARDIAN - SETUP")
    print("="*70)
    
    # Check config exists
    config_file = Path("config/config.yaml")
    if not config_file.exists():
        print("\n✗ Configuration file missing!")
        print(f"   Expected: {config_file}")
        sys.exit(1)
    
    # Load config
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    
    print("\n✓ Configuration loaded")
    
    # Show settings
    provider = config['ai']['provider']
    model = config['ai']['model']
    api_key = config['ai'].get('api_key', '')
    
    print(f"\nAI Provider: {provider}")
    print(f"Model: {model}")
    
    if api_key and api_key != 'your-api-key-here':
        print(f"API Key: {api_key[:20]}..." if len(api_key) > 20 else "API Key: configured")
        
        # Test connection
        print("\nTesting API connection...")
        try:
            sys.path.insert(0, str(Path(__file__).parent / "src"))
            from src.ai import get_provider
            ai = get_provider(config)
            if ai.is_available():
                print("✓ API working!")
            else:
                print("✗ API not responding")
        except Exception as e:
            print(f"✗ Error: {e}")
    else:
        print("API Key: NOT SET")
        print("\nTo set your API key:")
        print(f"  1. Open: {config_file}")
        print(f"  2. Find: api_key: your-api-key-here")
        print(f"  3. Replace with your key")
        print(f"\nGet FREE key: https://ai.google.dev/ (Google Gemini)")
    
    # Check directories
    print("\nChecking directories...")
    for name in ["audit_logs", "reports", "evidence"]:
        path = Path(name)
        if path.exists():
            print(f"  ✓ {name}/")
        else:
            path.mkdir(exist_ok=True)
            print(f"  ✓ Created {name}/")
    
    print("\n" + "="*70)
    print("✓ SETUP COMPLETE")
    print("="*70)
    print("\nQuick start:")
    print("  python demo.py              # Run quick demo")
    print("  python investigate.py --help  # See all options")
    print("\n")


if __name__ == "__main__":
    main()
