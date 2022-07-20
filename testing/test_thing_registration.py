from edge.install_gg import *


if __name__ == "__main__":
    DEVICE_SERIAL = "device01"
    THING_NAME = "thing01"
    GG_SECRETS_DIR = "../garbage/secrets-{}".format(THING_NAME)
    request_id = "c5a2fc63-41f7-4aed-a852-5ef26f05580c"

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
        #creds.get_amazon_root_ca()
        csr = creds.get_csr()
    except Exception as e:
        raise FailProvisioning("Could not create Key and CSR. Provisioning Failed.")
        print(e)
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
