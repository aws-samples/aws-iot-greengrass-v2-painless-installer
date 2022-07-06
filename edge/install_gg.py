#!/usr/bin/env python3

# Copyright 2010-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

# This file is licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

"""
This script will install AWS IoT Greengrass Version 2 (latest) and provision a new Greengrass Core Device in your
account. It interacts with Amazon API Gateway and Amazon Cognito running in your account and expects that you have
deployed the matching AWS CloudFormaion template and created at least one Cognito User allowed to provision devices.
See the readme.md documentation for further details.
"""

import json
import typing
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from base64 import b64encode


class Response(typing.NamedTuple):
    """Container for HTTP response."""

    body: str
    headers: Message
    status: int
    error_count: int = 0

    def json(self) -> typing.Any:
        """
        Decode body's JSON.
        Returns:
            Pythonic representation of the JSON object
        """
        try:
            output = json.loads(self.body)
        except json.JSONDecodeError:
            output = str(self.body)
        return output

    def __str__(self):

        return str({
            'body': self.json(),
            'status': self.status,
            'error_count': self.error_count,
            'headers': str(self.headers),
        })



def request(
        url: str,
        data: dict = None,
        params: dict = None,
        headers: dict = None,
        method: str = "GET",
        data_as_json: bool = True,
        error_count: int = 0,
) -> Response:
    """
    Perform HTTP request.
    Args:
        url: url to fetch
        data: dict of keys/values to be encoded and submitted
        params: dict of keys/values to be encoded in URL query string
        headers: optional dict of request headers
        method: HTTP method , such as GET or POST
        data_as_json: if True, data will be JSON-encoded
        error_count: optional current count of HTTP errors, to manage recursion
    Raises:
        URLError: if url starts with anything other than "http"
    Returns:
        A dict with headers, body, status code, and, if applicable, object
        rendered from JSON
    """
    if not url.startswith("http"):
        raise urllib.error.URLError("Incorrect and possibly insecure protocol in url")
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json", **headers}

    if method == "GET":
        params = {**params, **data}
        data = None

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()

    httprequest = urllib.request.Request(
        url, data=request_data, headers=headers, method=method
    )

    # print("url: {}".format(url))
    # print("data: {}".format(data))
    # print("headers: {}".format(headers))
    # print("method: {}".format(method))

    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            response = Response(
                headers=httpresponse.headers,
                status=httpresponse.status,
                body=httpresponse.read().decode(
                    httpresponse.headers.get_content_charset('UTF-8')
                ),
            )
    except urllib.error.HTTPError as e:
        body = e.read().decode(e.headers.get_content_charset('UTF-8'))
        response = Response(
            headers=e.headers,
            status=e.code,
            error_count=error_count + 1,
            body="{}: {}".format(str(e.reason), body),
        )

    return response


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


def get_app_token(cognito_domain, client_id, client_secret):
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
        return None


def request_provisioning(api_uri, token, serial_number, thing_name, user_name):
    url = "https://{}/request".format(api_uri)
    method = "GET"
    headers = {'Authorization': token}
    params = {'deviceId': serial_number, 'thingName': thing_name, 'userName': user_name}

    response = request(
        url=url,
        params=params,
        headers=headers,
        method=method
    )

    if response.status == 200:
        return response.json()['transactionId']
    else:
        print("Error when requesting provisioning:")
        print(response)
        return None


if __name__ == "__main__":
    # TODO: Move tho constants below to command line argument or config file
    CLIENT_ID = "5a1fda99b89mvj5ij3t903to88"
    CLIENT_SECRET = "1joira4ba7nccr9rga4568r6eu469clo37daas8aht0n4adjt9j1"
    API_URI = "zl9kcyhhzd.execute-api.us-east-1.amazonaws.com/Testing"
    DEVICE_SERIAL = "device02"
    THING_NAME = "thing02"
    USER_NAME = "lautip"

    # Retrieve the Authorization endpoint URI
    cognito_domain = get_auth_uri(API_URI)
    if not cognito_domain:
        raise (RuntimeError("Cognito Domain could not be retrieved"))

    # Get a time-limited Application Token
    app_token = get_app_token(
        cognito_domain=cognito_domain,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )
    if not app_token:
        raise (RuntimeError("Application Token could not be obtained"))

    # Send a request to provision the device and store the response elements
    request_id = request_provisioning(
        api_uri=API_URI,
        token=app_token,
        serial_number=DEVICE_SERIAL,
        thing_name=THING_NAME,
        user_name=USER_NAME
    )
    if not request_id:
        raise (RuntimeError("Provisioning Request was not accepted. Aborting."))
    else:
        print("Provisioning Request accepted with ID: {}".format(request_id))

    print("Goodbye")
