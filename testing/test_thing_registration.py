from base64 import b64encode

from edge.install_gg import *


def get_auth_uri(api_uri):
    url = "https://{}/auth-uri".format(api_uri)
    method = "GET"
    response = request(
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

    response = request(
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


if __name__ == "__main__":
    DEVICE_SERIAL = "device04"
    THING_NAME = "thing04"
    GG_SECRETS_DIR = "../garbage/secrets-{}".format(THING_NAME)
    request_id = "baa796f6-fc86-44f1-91f1-188b93ccf043"
    CLIENT_ID = ""
    CLIENT_SECRET = ""

    cognito_domain = get_auth_uri(API_URI)
    app_token = get_app_token(
        cognito_domain=cognito_domain,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )

    try:
        creds = SslCreds(
            dest_directory=GG_SECRETS_DIR,
            base_name="greengrassV2"
        )
        creds.create_private_key_and_csr()
        # creds.get_amazon_root_ca()
        csr = creds.get_csr()
    except Exception as e:
        print(e)
        raise FailProvisioning("Could not create Key and CSR. Provisioning Failed.")
    # Request Thing Provisioning from CSR
    response = provision_thing(device_id=DEVICE_SERIAL,
                               transaction_id=request_id,
                               csr=csr,
                               token=app_token,
                               api_uri=API_URI,
                               )
    if not response:
        raise FailProvisioning("Registering IoT Thing Failed.")
    crt = response.get('certificatePem')
    if crt is None or response['thingName'] != THING_NAME or response['deviceId'] != DEVICE_SERIAL:
        raise FailProvisioning("Mismatching data or missing CRT:\n{}".format(response))
    creds.save_crt(crt)
    print("IoT Data Endpoint is: {}".format(response.get('iotDataEndpoint')))
