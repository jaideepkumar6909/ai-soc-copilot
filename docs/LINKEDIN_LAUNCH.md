# LinkedIn launch kit

## What to upload

Publish the repository first. Use the actual repository URL in the draft below.
Create one LinkedIn post with that URL and three fresh screenshots:

1. **Dashboard overview:** suspicious demo, 21 events, one high-priority case,
   rule result and event timeline visible.
2. **AI report:** mode `llm_assisted`, findings with event IDs, and missing-evidence
   or next-step content visible. Select a report you can explain and acknowledge
   remaining limitations. Do not present raw model output as verified truth.
3. **Evaluation:** terminal showing `live_llm: 7/8 automated checks passed`, together
   with the README evaluation table if space allows. Preserve the observed result.

Capture only the app/terminal region. Exclude browser tabs, bookmarks, desktop
files, personal email, API pages, and any credential entry. Your earlier screenshots
include unrelated personal screen content, so take fresh captures for publication.
On a Mac, Shift+Command+4 lets you select just the region you want to capture.
Suggested filenames: `01-dashboard.png`, `02-ai-report.png`, `03-evaluation.png`.

Do not upload the source ZIP, API key, review database, or raw JSON as LinkedIn
attachments. Link to GitHub, where the source and synthetic evaluation belong.
No screenshot files are included in this package; capture them from the running app.

## Full post — replace the bracketed URL before publishing

I've been building AI SOC Copilot, a Python project that helps investigate SSH authentication alerts using detection rules and Claude-assisted reporting.

It groups authentication events into cases, identifies failure bursts followed by successful logins, and drafts findings linked to event IDs. An analyst can review the evidence, document a decision, and export the investigation. The application does not execute containment actions.

The most useful part of building it has been evaluating where the AI gets things wrong. In one live run across eight synthetic scenarios, seven matched the automated checks. Both tested prompt-injection examples were treated as data, but one report recommended excessive escalation and another misexplained why a case was high priority.

Those findings reinforced an important lesson: valid JSON and real citation IDs do not guarantee that an AI-generated security report is accurate.

The repository includes the code, synthetic samples, tests, the recorded evaluation, and known limitations. It's a portfolio prototype, and my next goal is to validate it with authorized logs from my own lab.

I used AI coding assistance during development and focused on testing the workflow, reviewing its outputs, and documenting the limitations honestly.

GitHub: [PASTE YOUR REPOSITORY URL]

I'd welcome feedback from SOC analysts and security engineers on the investigation workflow and evaluation approach.

#Cybersecurity #SOC #Python #SecurityAutomation #AI

## Featured project entry

Title: AI SOC Copilot — SSH Alert Investigation

Description: Python/Streamlit prototype combining SSH event correlation, Claude-assisted reports with evidence references, and local analyst review. Includes synthetic scenarios, automated tests, and a documented live evaluation with known limitations.

Add the published GitHub repository as a Featured link on your profile. If using
the Projects section, use the same title and description. Do not claim production
deployment, measured accuracy, prevented attacks, or a time-saving percentage.

## Optional 60–90 second demonstration

- Show suspicious events and explain the high-priority rule.
- Show the distinction between rule priority and unconfirmed compromise.
- Open an existing AI report and follow its event IDs back to the timeline.
- Show the injection sample's literal field and the recorded evaluation result.
- Finish with the known limitations and your next lab-validation goal.

Use synthetic data. Avoid recording key setup, personal tabs, or the entire desktop.
An existing report avoids making another paid call just for the recording.
