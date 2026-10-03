import hashlib
import json
from pathlib import Path
import streamlit as st
from core import load_events, investigate, baseline_report, save_review
from llm import analyze

st.set_page_config(page_title='SOC Copilot', page_icon='🛡️', layout='wide')
st.title('SOC Copilot')
st.caption('SSH alert investigation • Evidence first • Analyst reviewed')
with st.sidebar:
    st.header('Investigation input')
    demo = st.selectbox('Sample scenario', ['suspicious', 'benign_lookalike', 'injection'])
    upload = st.file_uploader('Or upload JSON / JSONL (2 MB maximum)', type=['json', 'jsonl'])
    st.caption('Supported: normalized SSH events or per-event Wazuh sshd authentication records.')
    st.info('Demo data stays local unless you explicitly request LLM analysis.')
try:
    if upload is not None and upload.size > 2_000_000:
        raise ValueError('Maximum input size is 2 MB.')
    content = upload.getvalue().decode('utf-8') if upload is not None else (Path(__file__).parent / 'data' / f'{demo}.jsonl').read_text()
    events, skipped = load_events(content)
    cases = investigate(events)
except (ValueError, UnicodeError) as exc:
    st.error(str(exc))
    st.stop()
source = hashlib.sha256(content.encode()).hexdigest()
if st.session_state.get('source') != source:
    st.session_state['source'] = source
    st.session_state['reports'] = {}
if skipped:
    st.warning(f'{skipped} unsupported Wazuh records skipped; this is not a full SIEM ingestion adapter.')
a, b, c = st.columns(3)
a.metric('Authentication events', len(events))
b.metric('Investigation cases', len(cases))
c.metric('High-priority cases', sum(x['priority'] == 'high' for x in cases))
selected = st.selectbox('Select case', range(len(cases)), format_func=lambda i: f"{cases[i]['priority'].upper()} · {cases[i]['host']} · {cases[i]['user']} · {cases[i]['src_ip']}")
case = cases[selected]
st.subheader('Evidence and rule result')
st.write({'priority': case['priority'], 'signal': case['signal'], 'IP scope': case['ip_scope'], 'peak failures / 10 min': case['peak_failures_in_window']})
st.caption('Priority is a rule-based review order, not a probability of compromise. Non-global IP includes private and documentation addresses.')
st.dataframe(case['timeline'], width='stretch', hide_index=True)
report = st.session_state['reports'].get(case['case_id'], baseline_report(case))
with st.expander('Optional LLM analysis'):
    st.write('Sends this case’s normalized events (including account, IP, and host) and the playbook to Anthropic. Raw log messages and API keys are not included in the prompt.')
    consent = st.checkbox('I have reviewed the data and want to send this case to the LLM provider.', key='consent_' + case['case_id'])
    if st.button('Generate AI investigation', disabled=not consent):
        try:
            with st.spinner('Reviewing evidence…'):
                report = analyze(case)
            st.session_state['reports'][case['case_id']] = report
        except ValueError as exc:
            st.error(str(exc))
st.subheader('Investigation report')
st.caption('Mode: ' + report['mode'] + ' • Citation IDs are checked; whether each claim is supported still requires analyst review.')
st.write('Assessment: ' + report['verdict'])
for finding in report['findings']:
    st.text(finding['statement'])
    st.caption('Evidence: ' + ', '.join(finding['evidence_ids']))
for field in ('hypotheses', 'missing_evidence', 'next_steps'):
    with st.expander(field.replace('_', ' ').capitalize(), expanded=field == 'next_steps'):
        for item in report[field]:
            st.text('• ' + item)
with st.expander('Retrieved playbook'):
    st.text(report['playbook']['source'])
    st.text(report['playbook']['text'])
st.download_button('Download investigation JSON', json.dumps({'case': case, 'report': report}, indent=2), file_name=f"case-{case['case_id']}.json", mime='application/json')
st.subheader('Analyst decision')
st.caption('Records a local review only. No emails, tickets, account changes, or blocking actions are performed.')
with st.form('review_' + case['case_id']):
    decision = st.selectbox('Decision', ['Request evidence', 'Escalate', 'Close as benign'])
    note = st.text_area('Rationale and supporting context')
    if st.form_submit_button('Save review'):
        try:
            save_review(case, report, decision, note)
            st.success('Review saved to local/reviews.db.')
        except ValueError as exc:
            st.error(str(exc))
