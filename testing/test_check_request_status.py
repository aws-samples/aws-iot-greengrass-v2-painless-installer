from base64 import b64encode

from edge import install_gg as igg


def get_auth_uri(api_uri):
    url = "https://{}/auth-uri".format(api_uri)
    method = "GET"
    response = igg.request(
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

    response = igg.request(
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
    DEVICE_SERIAL = "device06"
    THING_NAME = "thing06"
    TRANSACTION_ID = "c5a2fc63-41f7-4aed-a852-5ef26f05580c"
    CLIENT_ID = ""
    CLIENT_SECRET = ""

    cognito_domain = get_auth_uri(igg.API_URI)
    app_token = get_app_token(
        cognito_domain=cognito_domain,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )
    # app_token = "eyJraWQiOiJVVktZS2F1NnpIYzAzRGh6ckt2SlR5U05Oa3lsVEI5SlVENzRXQ0d0VTlvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI1YTFmZGE5OWI4OW12ajVpajN0OTAzdG84OCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiZ2dJbnN0YWxsZXJSU1wvcmVxdWVzdCIsImF1dGhfdGltZSI6MTY1NzU0NzA1NSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfWnRBYXBSVGNtIiwiZXhwIjoxNjU3NTUwNjU1LCJpYXQiOjE2NTc1NDcwNTUsInZlcnNpb24iOjIsImp0aSI6Ijg2M2ZkMTM1LTc1ZTYtNDE4Yy1hNzFkLWVlM2Q3Nzg1NWRkZSIsImNsaWVudF9pZCI6IjVhMWZkYTk5Yjg5bXZqNWlqM3Q5MDN0bzg4In0.sNVL-vnYiUpVJMm18bUgI8lTyt0L8CJDh_UXRfGJe3ucmKdN4xFPwUk3n3OX8LOtWHFPQstsGpShF2T_zNSydBuB0Z5ev6C8ozGNApr0AXhIe-GfsHm2NL6xQOUlPW4Y37M7MUFOwm0SdAusrc6jTDjBnMuN1Lb43hHZjVoTX7IpA_ctKB-tGaPfB4rvacSk8YVx8Bjt-EtRlf1ICpkQohoKCXMSjx-jsH2w-2wIn8_QWB_So0dsr9Wo7xgboNmQEjVgD8bsO_CESSJvzhCDEhGOsFtgbkKybPIXGCPsFa_oGOk6wcmNH5s2R2mMwVtzBgu01BIr7zKAt3LWJ8KhJQ"
    res = igg.is_request_allowed(transaction_id=TRANSACTION_ID, device_id=DEVICE_SERIAL,
                                 api_uri=igg.API_URI, token=app_token,
                                 poll_period=5, timeout=10)
    print(res)
