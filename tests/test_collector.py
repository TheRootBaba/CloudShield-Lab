import json
import sys
import types
import unittest
from unittest.mock import patch
from cloudshield.collector import collect_cloudtrail

class FakeTrail:
    def __init__(self, responses): self.responses = list(responses); self.calls=[]
    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, Exception): raise response
        return response

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.config = types.ModuleType("botocore.config")
        self.config.Config = lambda **kwargs: kwargs
        self.botocore = types.ModuleType("botocore")
        self.botocore.config = self.config
    def call_with(self, client, *args):
        boto3 = types.ModuleType("boto3")
        boto3.client = lambda *a, **kw: client
        with patch.dict(sys.modules, {"boto3":boto3,"botocore":self.botocore,"botocore.config":self.config}):
            return collect_cloudtrail(*args)
    def test_pagination_is_bounded_and_repeated_token_reported(self):
        event = {"CloudTrailEvent":json.dumps({"eventID":"one","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey"})}
        client = FakeTrail([{"Events":[event],"NextToken":"repeat"},{"Events":[],"NextToken":"repeat"}])
        result = self.call_with(client,"us-east-1",60,5)
        self.assertEqual(1,len(result["events"]))
        self.assertFalse(result["complete"])
        self.assertTrue(any(x["type"] == "RepeatedContinuationToken" for x in result["partial_failures"]))
    def test_later_page_failure_keeps_first_page(self):
        event = {"CloudTrailEvent":json.dumps({"eventID":"one"})}
        client = FakeTrail([{"Events":[event],"NextToken":"next"},RuntimeError("throttled")])
        result = self.call_with(client,"us-east-1",60,5)
        self.assertEqual(1,len(result["events"]))
        self.assertFalse(result["complete"])
        self.assertEqual("RuntimeError",result["partial_failures"][0]["type"])
    def test_invalid_region_rejected_before_sdk(self):
        with self.assertRaises(ValueError): collect_cloudtrail("bad-region")

if __name__ == "__main__": unittest.main()
