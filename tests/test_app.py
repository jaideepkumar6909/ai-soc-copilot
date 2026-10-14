import unittest
from pathlib import Path
try:
    from streamlit.testing.v1 import AppTest
except ImportError:
    AppTest = None

@unittest.skipIf(AppTest is None, 'Streamlit not installed')
class DashboardTests(unittest.TestCase):
    def test_demo_and_switch(self):
        app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py')).run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[2].value,'1')
        app.sidebar.selectbox[0].select('benign_lookalike').run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[2].value,'0')
        app.sidebar.selectbox[0].select('injection').run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[2].value,'1')

    def test_rule_model_category_comparison(self):
        from unittest.mock import patch
        from core import baseline_report

        # Cover both rule categories against every accepted model category.
        for demo, rule in (('suspicious', 'needs_review'),
                           ('benign_lookalike', 'insufficient_evidence')):
            for model in ('needs_review', 'likely_benign', 'insufficient_evidence'):
                with self.subTest(demo=demo, model=model):
                    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run()
                    app.sidebar.selectbox[0].select(demo).run()
                    self.assertFalse(app.exception)
                    self.assertFalse(app.warning)
                    self.assertTrue(app.button[0].disabled)

                    def mocked_analysis(case):
                        return {**baseline_report(case), 'mode': 'llm_assisted',
                                'verdict': model}

                    with patch('llm.analyze', side_effect=mocked_analysis) as analyze:
                        app.checkbox[0].check().run()
                        analyze.assert_not_called()
                        app.button[0].click().run()
                        analyze.assert_called_once()
                        self.assertFalse(app.exception)
                        rendered = '\n'.join(item.value for item in app.markdown)
                        self.assertIn('Rule review category: ' + rule, rendered)
                        self.assertIn('Model review category: ' + model, rendered)
                        self.assertIn('Model interpretation', [x.value for x in app.subheader])
                        self.assertEqual(len(app.warning), int(rule != model))
                        if rule != model:
                            self.assertIn('Rule/model disagreement', app.warning[0].value)
                            self.assertIn(rule, app.warning[0].value)
                            self.assertIn(model, app.warning[0].value)
                        self.assertIn('matching categories do not validate',
                                      ' '.join(x.value for x in app.caption))
                        # Cached reports retain the comparison on ordinary reruns.
                        app.run()
                        self.assertEqual(len(app.warning), int(rule != model))
                        self.assertEqual(analyze.call_count, 1)
                        # A new input clears the model report and its warning.
                        app.sidebar.selectbox[0].select('injection').run()
                        self.assertFalse(app.exception)
                        self.assertFalse(app.warning)
                        self.assertIn('Rules-only investigation report',
                                      [x.value for x in app.subheader])
                        self.assertEqual(analyze.call_count, 1)

    def test_failed_analysis_does_not_create_disagreement(self):
        from unittest.mock import patch
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run()
        with patch('llm.analyze', side_effect=ValueError('Report rejected')):
            app.checkbox[0].check().run()
            app.button[0].click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.error[0].value, 'Report rejected')
        self.assertFalse(app.warning)
        self.assertIn('Rules-only investigation report', [x.value for x in app.subheader])
