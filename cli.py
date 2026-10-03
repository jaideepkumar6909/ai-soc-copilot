import argparse
import json
from pathlib import Path
from core import load_events, investigate, baseline_report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Offline SSH triage; no API key required.')
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    events, skipped = load_events(args.input.read_text())
    print(json.dumps({'skipped': skipped, 'cases': [{'case': c, 'report': baseline_report(c)} for c in investigate(events)]}, indent=2))
