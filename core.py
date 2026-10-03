"""Deterministic SSH triage. No model output executes actions."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parent


def timestamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamps must include a timezone.')
    return dt.astimezone(timezone.utc)


def load_events(text):
    if len(text.encode()) > 2_000_000:
        raise ValueError('Maximum input size is 2 MB.')
    try:
        rows = json.loads(text) if text.lstrip().startswith('[') else [json.loads(x) for x in text.splitlines() if x.strip()]
    except json.JSONDecodeError as exc:
        raise ValueError('Expected a JSON array or JSONL events.') from exc
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError('Provide 1–10,000 events.')
    events, seen, skipped = [], {}, 0
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f'Row {index}: expected an object.')
        # Deliberately narrow Wazuh adapter: per-event sshd authentication records.
        if 'rule' in row:
            rule = row['rule']
            if not isinstance(rule, dict) or not isinstance(rule.get('groups', []), list) or any(not isinstance(g, str) for g in rule.get('groups', [])):
                raise ValueError(f'Row {index}: malformed Wazuh rule groups.')
            groups = rule.get('groups', [])
            data = row.get('data', {})
            if 'sshd' not in groups or not ({'authentication_failed', 'authentication_success'} & set(groups)):
                skipped += 1
                continue
            if not isinstance(data, dict) or not isinstance(row.get('agent'), dict):
                raise ValueError(f'Row {index}: malformed Wazuh data or agent.')
            row = {'id': row.get('id'), 'timestamp': row.get('timestamp'),
                   'host': row.get('agent', {}).get('name'), 'user': data.get('dstuser'),
                   'src_ip': data.get('srcip'),
                   'event_type': 'ssh_success' if 'authentication_success' in groups else 'ssh_failure'}
        required = ('id', 'timestamp', 'host', 'user', 'src_ip', 'event_type')
        if any(not isinstance(row.get(k), str) or not row[k] or len(row[k]) > 256 for k in required):
            raise ValueError(f'Row {index}: all required fields must be nonempty strings of at most 256 characters.')
        if row['event_type'] not in ('ssh_success', 'ssh_failure'):
            raise ValueError(f'Row {index}: unsupported event_type.')
        try:
            dt = timestamp(row['timestamp'])
            ipaddress.ip_address(row['src_ip'])
        except (ValueError, TypeError) as exc:
            raise ValueError(f'Row {index}: invalid timezone-aware timestamp or IP address.') from exc
        event = {k: row[k] for k in required}
        event['timestamp'] = dt.isoformat()
        event['src_ip'] = str(ipaddress.ip_address(event['src_ip']))
        if event['id'] in seen:
            if seen[event['id']] != event:
                raise ValueError(f'Row {index}: conflicting duplicate event ID.')
            continue
        seen[event['id']] = event
        events.append(event)
    if not events:
        raise ValueError('No supported SSH authentication events found.')
    return sorted(events, key=lambda e: (e['timestamp'], e['id'])), skipped


def investigate(events, window_minutes=10, threshold=5):
    grouped = defaultdict(list)
    for e in events:
        grouped[(e['host'], e['user'], e['src_ip'])].append(e)
    cases = []
    for key, group in sorted(grouped.items()):
        # Gap-based sessions group the timeline. Detection uses a rolling window,
        # so many slow failures across a long session do not trigger a burst.
        group.sort(key=lambda e: e['timestamp'])
        sessions, current = [], []
        for e in group:
            if current and timestamp(e['timestamp']) - timestamp(current[-1]['timestamp']) > timedelta(minutes=window_minutes):
                sessions.append(current)
                current = []
            current.append(e)
        if current:
            sessions.append(current)
        for timeline in sessions:
            peak, preceding, success_after = 0, 0, False
            failures = deque()
            for e in timeline:
                now = timestamp(e['timestamp'])
                while failures and now - failures[0] > timedelta(minutes=window_minutes):
                    failures.popleft()
                if e['event_type'] == 'ssh_failure':
                    failures.append(now)
                    peak = max(peak, len(failures))
                else:
                    preceding = max(preceding, len(failures))
                    success_after |= len(failures) >= threshold
            priority = 'high' if success_after else 'medium' if peak >= threshold else 'low'
            signal = 'failure_burst_then_success' if success_after else 'failure_burst' if peak >= threshold else 'below_threshold'
            ids = [e['id'] for e in timeline]
            case_id = hashlib.sha256(json.dumps(timeline, sort_keys=True).encode()).hexdigest()[:12]
            cases.append({'case_id': case_id, 'host': key[0], 'user': key[1], 'src_ip': key[2],
                          'priority': priority, 'signal': signal, 'verdict': 'needs_review' if priority != 'low' else 'insufficient_evidence',
                          'failure_count': sum(e['event_type'] == 'ssh_failure' for e in timeline),
                          'success_count': sum(e['event_type'] == 'ssh_success' for e in timeline),
                          'peak_failures_in_window': peak, 'max_failures_before_success': preceding,
                          'window_minutes': window_minutes, 'threshold': threshold,
                          'ip_scope': 'globally_routable' if ipaddress.ip_address(key[2]).is_global else 'non_global',
                          'evidence_ids': ids, 'timeline': timeline})
    return sorted(cases, key=lambda c: ({'high': 0, 'medium': 1, 'low': 2}[c['priority']], c['case_id']))


def retrieve_playbook(case):
    # Deterministic retrieval by detected signal; not vector search.
    filename = 'ssh_burst.md' if case['signal'] != 'below_threshold' else 'ssh_review.md'
    return {'source': filename, 'text': (ROOT / 'playbooks' / filename).read_text()}


def baseline_report(case):
    return {'mode': 'rules_only', 'case_id': case['case_id'], 'priority': case['priority'],
            'verdict': case['verdict'],
            'findings': [{'statement': f"Observed {case['failure_count']} failed and {case['success_count']} successful SSH authentication events; signal: {case['signal']}.", 'evidence_ids': case['evidence_ids']}],
            'hypotheses': ['Possible password guessing or user error; authentication records alone do not establish compromise.'],
            'missing_evidence': ['Account-owner confirmation', 'Post-login process activity', 'Expected source IP and change records'],
            'next_steps': ['Review the cited timeline.', 'Confirm whether the account owner recognizes the activity.', 'Collect endpoint activity before deciding containment.'],
            'playbook': retrieve_playbook(case)}


def save_review(case, report, decision, note, db_path=None):
    if decision not in ('Escalate', 'Request evidence', 'Close as benign') or not note.strip():
        raise ValueError('Choose a review decision and provide a rationale.')
    path = Path(db_path) if db_path else ROOT / 'local' / 'reviews.db'
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY, created_at TEXT, case_id TEXT, decision TEXT, note TEXT, snapshot TEXT)')
        db.execute('INSERT INTO reviews(created_at,case_id,decision,note,snapshot) VALUES(?,?,?,?,?)',
                   (datetime.now(timezone.utc).isoformat(), case['case_id'], decision, note, json.dumps({'case': case, 'report': report})))
    return path
