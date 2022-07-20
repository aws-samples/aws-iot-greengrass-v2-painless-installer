import unittest

from unittest.mock import patch
from edge import install_gg


class TestCase(unittest.TestCase):

    @patch("edge.install_gg.get_greengrass_version", return_value="2.5.6")
    def test01(self, ggver):
        DEVICE_SERIAL = "device04"
        THING_NAME = "thing04"
        GG_SECRETS_DIR = "../garbage/secrets-{}".format(THING_NAME)
        request_id = "baa796f6-fc86-44f1-91f1-188b93ccf043"

        cognito_domain = install_gg.get_auth_uri(install_gg.API_URI)
        app_token = install_gg.get_app_token(
            cognito_domain=cognito_domain,
            client_id=install_gg.CLIENT_ID,
            client_secret=install_gg.CLIENT_SECRET
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