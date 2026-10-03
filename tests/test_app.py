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
