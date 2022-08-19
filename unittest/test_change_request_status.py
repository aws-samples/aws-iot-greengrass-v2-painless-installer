import unittest
from base64 import b64encode

from edge import install_gg


def get_auth_uri(api_uri):
    url = "https://{}/auth-uri".format(api_uri)
    method = "GET"
    response = install_gg.request(
        url=url,
        method=method
    )

    if response.status == 200:
        return response.json().get('auth-uri')
    else:
        return None


def get_app_token(cognito_domain: str, client_id: str, client_secret: str) -> str:

    url = "https://{}/oauth2/token".format(cognito_domain)
    method = "POST"
    b64_auth = 'Basic {}'.format(b64encode(bytes("{}:{}".format(client_id, client_secret), "ascii")).decode("ascii"))
    headers = {'Content-Type': "application/x-www-form-urlencoded", 'Authorization': b64_auth}
    params = None
    data_as_json = False
    data = {
        'grant_type': 'client_credentials',
        'scope': 'ggInstallerRS/request'
    }

    response = install_gg.request(
        url=url,
        data=data,
        params=params,
        headers=headers,
        method=method,
        data_as_json=data_as_json
    )

    if response.status == 200:
        return response.json().get('access_token')
    else:
        return ""


class TestCase(unittest.TestCase):
    API_URI = "zl9kcyhhzd.execute-api.us-east-1.amazonaws.com/Testing"
    CLIENT_ID = "5a1fda99b89mvj5ij3t903to88"
    CLIENT_SECRET = "1joira4ba7nccr9rga4568r6eu469clo37daas8aht0n4adjt9j1"
    REQ_ID = "7010aaa4-63d6-40ca-b35a-c36e81bd9f2d"
    DEV_ID = 'device02'

    def setUp(self) -> None:
        cog_domain = get_auth_uri(self.API_URI)
        self.app_token = get_app_token(
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
