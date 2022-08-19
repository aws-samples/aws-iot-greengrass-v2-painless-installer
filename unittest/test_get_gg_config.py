import unittest
from base64 import b64encode

from unittest.mock import patch
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

    @patch("edge.install_gg.get_greengrass_version", return_value="2.5.6")
    def test01(self, ggver):
        DEVICE_SERIAL = "device04"
        THING_NAME = "thing04"
        GG_SECRETS_DIR = "../garbage/secrets-{}".format(THING_NAME)
        request_id = "baa796f6-fc86-44f1-91f1-188b93ccf043"
        CLIENT_ID = ""
        CLIENT_SECRET = ""

        cognito_domain = get_auth_uri(install_gg.API_URI)
        app_token = get_app_token(
            cognito_domain=cognito_domain,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )

        raw_cfg = install_gg.get_greengrass_config(token=app_token,
                                                   api_uri=install_gg.API_URI,
                                                   transaction_id=request_id,
                                                   device_id=DEVICE_SERIAL)
        print(raw_cfg)
        creds = install_gg.SslCreds(
            dest_directory=GG_SECRETS_DIR,
            base_name="greengrassV2"
        )
        cfg = install_gg.populate_greengrass_config(ssl_creds=creds, template=raw_cfg)
        print(cfg)
        install_gg.save_greengrass_config(cfg=cfg, directory="../garbage/")


if __name__ == "__main__":
    unittest.main()
