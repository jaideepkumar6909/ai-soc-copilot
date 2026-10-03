import json
import unittest
from unittest.mock import patch
from core import investigate
from llm import parse_response, analyze
from test_core import events, valid_report

class FormatTests(unittest.TestCase):
    def setUp(self):
        self.case=investigate(events())[0]

    def envelope(self, text, reason='end_turn'):
        return {'stop_reason':reason,'content':[{'type':'text','text':text}]}

    def test_plain_json(self):
        self.assertEqual(parse_response(self.envelope(json.dumps(valid_report())),self.case),valid_report())

    def test_markdown_wrapper(self):
        self.assertEqual(parse_response(self.envelope('```json\n'+json.dumps(valid_report())+'\n```'),self.case),valid_report())

    def test_prose_not_silently_discarded(self):
        with self.assertRaisesRegex(ValueError,'complete JSON'):
            parse_response(self.envelope('Here is the report: '+json.dumps(valid_report())),self.case)

    def test_truncation_rejected_even_if_parseable(self):
        with self.assertRaisesRegex(ValueError,'token limit'):
            parse_response(self.envelope(json.dumps(valid_report()),'max_tokens'),self.case)

    def test_refusal(self):
        with self.assertRaisesRegex(ValueError,'declined'):
            parse_response(self.envelope('No','refusal'),self.case)

    def test_unknown_citation_still_rejected(self):
        report=valid_report(); report['findings'][0]['evidence_ids']=['invented']
        with self.assertRaisesRegex(ValueError,'nonexistent'):
            parse_response(self.envelope('```json\n'+json.dumps(report)+'\n```'),self.case)

    def test_broken_envelopes(self):
        for body in [[],{}, {'stop_reason':'end_turn','content':None}, {'stop_reason':'end_turn','content':[1]}, self.envelope(None)]:
            with self.subTest(body=body), self.assertRaises(ValueError): parse_response(body,self.case)

    def test_duplicate_json_fields(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):
            parse_response(self.envelope('{"verdict":"needs_review","verdict":"likely_benign"}'),self.case)

    def test_payload_requests_structured_output(self):
        test=self
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self): return json.dumps(test.envelope(json.dumps(valid_report()))).encode()
        class Opener:
            def open(self,request,timeout):
                payload=json.loads(request.data)
                fmt=payload['output_config']['format']
                test.assertEqual(fmt['type'],'json_schema')
                test.assertFalse(fmt['schema']['additionalProperties'])
                test.assertEqual(payload['max_tokens'],3000)
                test.assertNotIn('tools',payload)
                return Response()
        with patch.dict('os.environ',{'ANTHROPIC_API_KEY':'test','ANTHROPIC_MODEL':'test'}),patch('urllib.request.build_opener',return_value=Opener()):
            self.assertEqual(analyze(self.case)['mode'],'llm_assisted')
