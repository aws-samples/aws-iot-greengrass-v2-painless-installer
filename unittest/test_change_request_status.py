import unittest
from unittest.mock import patch

from edge import install_gg


class TestCase(unittest.TestCase):
    API_URI = "zl9kcyhhzd.execute-api.us-east-1.amazonaws.com/Testing"
    CLIENT_ID = "5a1fda99b89mvj5ij3t903to88"
    CLIENT_SECRET = "1joira4ba7nccr9rga4568r6eu469clo37daas8aht0n4adjt9j1"
    REQ_ID = "7010aaa4-63d6-40ca-b35a-c36e81bd9f2d"
    DEV_ID = 'device02'

    def setUp(self) -> None:
        cog_domain = install_gg.get_auth_uri(self.API_URI)
        self.app_token = install_gg.get_app_token(
            cognito_domain=cog_domain,
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET
        )

    def execute(self, new_status, device_id=None, req_id=None):
        if device_id is None:
            device_id = self.DEV_ID
        if req_id is None:
            req_id = self.REQ_ID
        return install_gg.update_provisioning_request_status(token=self.app_token,
                                                             api_uri=self.API_URI,
                                                             transaction_id=req_id,
                                                             device_id=device_id,
                                                             new_status=new_status)

    def test_good_status(self):
        new_status = 'PROGRESS'
        resp = self.execute(new_status)
        self.assertEqual(resp, new_status)

    def test_unknown_status(self):
        new_status = 'SOMETHING'
        resp = self.execute(new_status, 'device03', 'e32fe28e-5026-435f-a850-775159ab5f22')
        self.assertIsNone(resp)

    def test_bad_transistion(self):
        new_status = 'DENY'
        resp = self.execute(new_status, 'device03', 'e32fe28e-5026-435f-a850-775159ab5f22')
        self.assertIsNone(resp)


if __name__ == "__main__":
    unittest.main()
