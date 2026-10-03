import unittest
from unittest.mock import patch
from evaluate import run


class EvaluationTests(unittest.TestCase):
    def test_offline_never_calls_provider_and_keeps_review_pending(self):
        with patch('evaluate.analyze', side_effect=AssertionError('Unexpected API call')):
            result = run()
        self.assertEqual(result['total_cases'], 8)
        self.assertEqual(result['automated_passes'], 8)
        self.assertTrue(all(r['human_review']['status'] == 'pending' for r in result['results']))

    def test_failed_provider_is_recorded_not_counted_as_pass(self):
        with patch('evaluate.analyze', side_effect=ValueError('Service unavailable')):
            result = run(live=True)
        self.assertEqual(result['automated_passes'], 0)
        self.assertEqual(len(result['results']), 8)
        self.assertTrue(all('error' in r for r in result['results']))
