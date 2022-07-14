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
deployed the matching AWS CloudFormation template and created at least one Cognito User allowed to provision devices.
See the readme.md documentation for further details.
"""

import json
import typing
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from base64 import b64encode
import time
from enum import Enum
import platform
import subprocess
import re
import os
import logging
import sys

# Constants that are not supposed to be changed for each deployment

API_RESOURCE_REQUEST_CREATE = "/request/create"
API_RESOURCE_REQUEST_STATUS = "/request/status"

LOG_LEVEL = "DEBUG"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('GrenngrassInstaller')
logger.setLevel(LOG_LEVEL)


class Status(Enum):
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    ALLOWED = 5
    PROGRESS = 6
    SUCCESS = 7
    NONE = 8


class ProvisioningException(Exception):
    pass


class AbortProvisioning(Exception):
    pass


class CancelProvisioning(Exception):
    pass


class FailProvisioning(Exception):
    pass


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


def check_requirements():
    os_type = platform.system()
    if os_type == "Linux":
        return check_requirements_linux()
    elif os_type == "Darwin":
        # MacOS not compliant to Greengrass requirements. Implemented only for test purposes.
        return check_requirements_darwin()
    else:
        raise ProvisioningException("System detected: {}. Only Linux platforms supported.".format(os_type))


def get_java_version():
    try:
        java_ver = subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT)
        match = re.search('(\d+\.\d+).*', java_ver)
        if match:
            major, minor = match.group(0).strip('"').split(".")[:2]
            return int(minor) if int(major) == 1 else int(major)
        else:
            return 0
    except Exception as e:
        logger.critical("Exception when checking JAVA version:\n {}".format(e))
        return 0


def get_glibc_version():
    try:
        glibc_ver = subprocess.check_output(['ldd', '--version'], stderr=subprocess.STDOUT)
        match = re.search('(\d+\.\d+).*', glibc_ver)
        if match:
            major, minor = match.group(0).strip('"').split(".")[:2]
            return int(major), int(minor)
        else:
            return 0, 0
    except Exception as e:
        logger.critical("Exception when checking glibc version:\n {}".format(e))
        return 0, 0


def check_sudoers(fname="/etc/sudoers"):
    try:
        with open(fname) as f:
            for line in f.readlines():
                stripped_line = re.sub("\s\s+", " ", line).strip(" ")
                if "root ALL=(ALL) ALL" in stripped_line or "root ALL=(ALL:ALL) ALL" in stripped_line:
                    return True
        return False
    except Exception as e:
        logger.critical("Exception when checking sudoers configuration:\n {}".format(e))
        return False


def check_tmp_directory():
    try:
        return os.access("/tmp", os.X_OK)
    except Exception as e:
        logger.critical("Exception when checking /tmp directory configuration:\n {}".format(e))
        return False


def check_requirements_linux():
    required = ["ps", "sudo", "sh", "kill", "cp", "chmod", "rm", "ln", "echo", "exit", "id", "uname", "grep",
                "systemctl", "useradd", "groupadd", "usermod"]
    java_min = 8
    glibc_min = (2, 25)  # major, minor
    result = {}
    for req in required:
        if subprocess.call(['which', req], stdout=subprocess.DEVNULL) == 0:
            result[req] = True
        else:
            result[req] = False

    java_ver = get_java_version()
    if java_ver < java_min:
        result['java'] = False
    else:
        result['java'] = True

    glibc_ver = get_glibc_version()
    result['glibc'] = glibc_ver[0] > glibc_min[0] or (glibc_ver[0] == glibc_min[0] and glibc_ver[1] >= glibc_min[1])

    # is user root?
    result['root'] = os.geteuid() == 0

    # Is sudoers correctly set
    result['sudoers'] = check_sudoers()

    # IS /tmp correctly configured
    result['tmp directory'] = check_tmp_directory()

    return result


def check_requirements_darwin():
    # TODO: Fix this
    return {'one': True, 'two': True}
    # raise ProvisioningException("MacOS (Darwin) is not supported.")


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

    # logger.debug("url: {}".format(url))
    # logger.debug("data: {}".format(data))
    # logger.debug("headers: {}".format(headers))
    # logger.debug("method: {}".format(method))

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
    url = "https://{}{}".format(api_uri, API_RESOURCE_REQUEST_CREATE)
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
        logger.critical("Error when requesting provisioning:")
        logger.critical(response)
        return None


def update_provisioning_request_status(request_id, thing_name, new_status):
    raise NotImplementedError("update_provisioning_request_status")


def is_request_allowed(transaction_id, device_id, api_uri, token, poll_period=60, timeout=2700):
    """
    This is a blocking function
    Periodically polls the Provisioning Request status until it is allowed or denied.
    Times out after the set parameter or if the token expires. 
    :param str transaction_id: UUID string returned when creating the request
    :param str device_id:  The deviceId
    :param str api_uri: The base URI for the API
    :param str token: The access token for contacting the API
    :param int poll_period: how frequently to check the status
    :param int timeout: Time after which the provisioning attempt is aborted
    :return: True if the request is allowed or False otherwise
    """
    timeout_time = time.time() + timeout
    while True:
        url = "https://{}{}".format(api_uri, API_RESOURCE_REQUEST_STATUS)
        method = "GET"
        headers = {'Authorization': token}
        params = {'deviceId': device_id, 'transactionId': transaction_id}

        response = request(
            url=url,
            params=params,
            headers=headers,
            method=method
        )

        if response.status == 200:
            status = response.json().get('status')
            if status == Status.ALLOWED.name:
                return True
            elif status != Status.PENDING.name:
                logger.critical("Aborting due to Request Status = {}".format(status))
                return False
            else:  # PENDING
                if time.time() > timeout_time:
                    logger.critical("Aborting due to Status not approved before timeout")
                    return False
                else:
                    logger.info("Request status is {}. Waiting for Request Status to be allowed. "
                                "Will try again in {} seconds.".format(status, poll_period))
                    time.sleep(poll_period)
        elif response.status == 401:  # Unauthorised
            logger.critical("Aborting due to Authentication issue: {}".format(response.body))
            return False
        else:
            logger.critical("Aborting due to unexpected error when requesting Request Status:")
            logger.critical(response)
            return False


# TODO: Move tho constants below to command line argument or config file
# TODO: Consider creating an API endpoint to fetch other config variables
CLIENT_ID = "5a1fda99b89mvj5ij3t903to88"
CLIENT_SECRET = "1joira4ba7nccr9rga4568r6eu469clo37daas8aht0n4adjt9j1"
API_URI = "zl9kcyhhzd.execute-api.us-east-1.amazonaws.com/Testing"
DEVICE_SERIAL = "device09"
THING_NAME = "thing09"
USER_NAME = "lautip"

if __name__ == "__main__":
    try:
        # Check if requirements are met
        try:
            reqs = check_requirements()
        except ProvisioningException as e:
            raise AbortProvisioning(e)
        good = all(x for x in reqs.values())
        if not good:
            missing = {k: v for (k, v) in reqs.items() if v is False}
            logger.critical("Some requirements are missing :\n{}".format(missing))
            raise AbortProvisioning("Hosting system requirements are not met.")

        # Retrieve the Authorization endpoint URI
        cognito_domain = get_auth_uri(API_URI)
        if not cognito_domain:
            raise AbortProvisioning("Cognito Domain could not be retrieved")

        # Get a time-limited Application Token
        app_token = get_app_token(
            cognito_domain=cognito_domain,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        if not app_token:
            raise AbortProvisioning("Application Token could not be obtained")

        # Send a request to provision the device and store the response elements
        request_id = request_provisioning(
            api_uri=API_URI,
            token=app_token,
            serial_number=DEVICE_SERIAL,
            thing_name=THING_NAME,
            user_name=USER_NAME
        )
        if not request_id:
            raise AbortProvisioning("Provisioning Request was not accepted.")
        else:
            logger.info("Provisioning Request accepted with ID: {}".format(request_id))

        # Wait until the Request changes status (human intervention)
        if not is_request_allowed(transaction_id=request_id, device_id=DEVICE_SERIAL, api_uri=API_URI, token=app_token):
            raise CancelProvisioning("Provisioning Request not allowed within allowed time window.")
        else:
            logger.info("Provisioning Request allowed - moving forward...")

        # Change status to in progress
        update_provisioning_request_status(request_id=request_id,
                                           thing_name=THING_NAME,
                                           new_status=Status.PROGRESS.name)
        # Download Greengrass package and extract it

        # Request Iot Think provisioning

        # Install Greengrass Core

        # Update Status to SUCCESS

        logger.info("Goodbye")

    except FailProvisioning as e:
        if 'request_id' in locals():
            logger.critical("Provisioning process failed. Chancing State to Failed:\n{}".format(e))
            update_provisioning_request_status(request_id=request_id,
                                               thing_name=THING_NAME,
                                               new_status=Status.FAILED.name)
        else:
            logger.critical("Process aborted due to Exception but cloud not Cancel the request\n {}".format(e))

        sys.exit(1)

    except CancelProvisioning as e:
        if 'request_id' in locals():
            logger.critical(
                "Aborting Provisioning Request due to Exception. Chancing State to Cancelled:\n{}".format(e))
            update_provisioning_request_status(request_id=request_id,
                                               thing_name=THING_NAME,
                                               new_status=Status.CANCELLED.name)
        else:
            logger.critical("Process aborted due to Exception but cloud change its state to Cancelled:\n {}".format(e))

        sys.exit(1)

    except AbortProvisioning as e:
        logger.critical("Process aborted due to Exception. State has not been updated:\n {}".format(e))
        sys.exit(1)
