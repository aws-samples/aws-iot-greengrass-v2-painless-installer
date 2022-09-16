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
deployed the matching AWS CloudFormation template, and created at least one Cognito User allowed to provision devices.
See the readme.md documentation for further details.

Version of this script: 1.0.0
"""
import json
import typing
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from base64 import b64decode
import time
from enum import Enum
import platform
import subprocess
import re
import os
import logging
import sys
from zipfile import ZipFile

# Change those constants according to your preferences

# SSL Key and CSR Distinguished Names elements
SSL_CN = "Greengrass Installer"
SSL_OU = "Amazon Web Services"
SSL_O = "Amazon.com Inc."
SSL_L = "Seattle"
SSL_ST = "Washington"
SSL_C = "US"

LOG_LEVEL = "DEBUG"

# Constants that are not supposed to be changed

API_RESOURCE_REQUEST_CREATE = "/request/create"
API_RESOURCE_REQUEST_STATUS = "/request/status"
API_RESOURCE_REQUEST_UPDATE = "/request/update"
API_RESOURCE_REGISTER_THING = "/provision/register-thing"
API_RESOURCE_GREENGRASS_CONFIG = "/provision/greengrass-config"
URL_GREENGRASS_NUCLEUS_DL = "https://d2s8p88vqu9w66.cloudfront.net/releases/greengrass-nucleus-latest.zip"
GG_ZIP_DEST_DIR = "/tmp"
GG_ZIP_DEST_FILE = "greengrass-nucleus.zip"
GG_UNZIP_DEST_DIR = "/tmp/GreengrassInstaller"
GG_SECRETS_DIR = "/greengrass-v2-certs"
GG_ROOT_PATH = "/greengrass/v2"
GG_CONFIG_FILE_NAME = "config.yaml"
AMAZON_ROOT_CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"

# Logger setup
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('GrenngrassInstaller')
logger.setLevel(LOG_LEVEL)


class Status(Enum):
    """
    Defines the possible satus of a Status Request.
    Make sure this stays in sync with the same class in the edge script
    """
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    ALLOWED = 5
    PROGRESS = 6
    REGISTERED = 7
    SUCCESS = 8
    NONE = 9


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


def check_requirements() -> dict:
    """
    Initiates checkng the requirements for installing Greengrass are met for the platform this script is running on
    :return:
    :raises: ProvisioningException
    """
    os_type = platform.system()
    if os_type == "Linux":
        return check_requirements_linux()
    elif os_type == "Darwin":
        # MacOS not compliant to Greengrass requirements. Implemented only for test purposes.
        return check_requirements_darwin()
    else:
        raise ProvisioningException("System detected: {}. Only Linux platforms supported.".format(os_type))


def get_java_version() -> int:
    """
    Retrieves the Java version if installed.
    :return: the major of the Java version or 0 if Java not installed
    """
    try:
        java_ver = subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT)
        match = re.search('(\d+\.\d+).*', str(java_ver))
        if match:
            major, minor = match.group(0).strip('"').split(".")[:2]
            return int(minor) if int(major) == 1 else int(major)
        else:
            return 0
    except Exception as e:
        logger.critical("Exception when checking JAVA version:\n {}".format(e))
        return 0


def get_glibc_version() -> typing.Tuple[int, int]:
    """
    Retrieves the version of glic
    :return: (major, minor) and (0,0) if not installed
    """
    try:
        glibc_ver = subprocess.check_output(['ldd', '--version'], stderr=subprocess.STDOUT)
        match = re.search('(\d+\.\d+)', str(glibc_ver))
        if match:
            major, minor = match.group(0).strip('"').split(".")[:2]
            return int(major), int(minor)
        else:
            return 0, 0
    except Exception as e:
        logger.critical("Exception when checking glibc version:\n {}".format(e))
        return 0, 0


def check_sudoers(fname="/etc/sudoers") -> bool:
    """
    Checks if sudoer is properly configured
    :param fname: file /absolute_path/name where sudoers are configured
    :return: True of correct or False
    """
    try:
        with open(fname) as f:
            for line in f.readlines():
                line = line.replace("\t", " ")
                line = line.rstrip("\n")
                stripped_line = re.sub("\s\s+", " ", line).strip(" ")
                if "root ALL=(ALL) ALL" in stripped_line or "root ALL=(ALL:ALL) ALL" in stripped_line:
                    return True
        return False
    except Exception as e:
        logger.critical("Exception when checking sudoers configuration:\n {}".format(e))
        return False


def check_tmp_directory() -> bool:
    """
    Checks if /tmp has execute permission
    :return: True if /tmp is correctly configured or False
    """
    try:
        return os.access("/tmp", os.X_OK)
    except Exception as e:
        logger.critical("Exception when checking /tmp directory configuration:\n {}".format(e))
        return False


def check_requirements_linux() -> dict:
    """
    Checks Greengrass requirements for the Linux OS
    :return: a dictionary with each requirement as key and True (met) or False (not met) as value
    """
    logger.info("Checking requirements for Linux platform")
    required = ["ps", "sudo", "sh", "kill", "cp", "chmod", "rm", "ln", "echo", "id", "uname", "grep",
                "systemctl", "useradd", "groupadd", "usermod", "openssl"]
    # 'exit' is a shell command and cannot be checked with which and is omitted
    java_min = 8
    glibc_min = (2, 25)  # major, minor
    result = {}
    for req in required:
        result[req] = subprocess.call(['which', req], stdout=subprocess.DEVNULL) == 0

    result['java'] = get_java_version() >= java_min

    glibc_ver = get_glibc_version()
    result['glibc'] = glibc_ver[0] > glibc_min[0] or (glibc_ver[0] == glibc_min[0] and glibc_ver[1] >= glibc_min[1])

    # is user root?
    result['root'] = os.geteuid() == 0

    # Is sudoers correctly set
    result['sudoers'] = check_sudoers()

    # Is /tmp correctly configured
    result['tmp directory'] = check_tmp_directory()

    return result


def check_requirements_darwin() -> dict:
    """
    This is a placeholder for MacOS requirements check.
    It is used mostly when developing for now.
    :return: a dictionary with each requirement as key and True (met) or False (not met) as value
    :raises: ProvisioningException until t is supported.
    """
    # TODO: Fix this
    # return {'one': True, 'two': True}
    raise ProvisioningException("MacOS (Darwin) is not supported.")


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


def request_provisioning(api_uri: str, token: str, serial_number: str, thing_name: str, user_name: str) -> str:
    """
    Calls the API to initiate a new provisioning request.
    :param api_uri: API Gateway endpoint (without https://)
    :param token: Cognito Access Token
    :param serial_number: Identifier of the Device, like a serial number
    :param thing_name: The name of the IoT Thing to create
    :param user_name: The username of the person initiating the provisioning
    :return: The Provisioning Request UUID
    """
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
        return ""


def update_provisioning_request_status(token: str, api_uri: str, transaction_id: str, device_id: str,
                                       new_status: str) -> str:
    """
    Attempts to change the status of an existing provisioning request on the backend.
    :param token: Cognito Access Token
    :param api_uri: API Gateway endpoint (without https://)
    :param transaction_id: The Provisioning Request UUID
    :param device_id: Identifier of the Device, like a serial number
    :param new_status: Name of the new status (must be member of the 'Status' class)
    :return: the new status value if success or emtpy string
    """
    url = "https://{}{}".format(api_uri, API_RESOURCE_REQUEST_UPDATE)
    method = "GET"
    headers = {'Authorization': token}
    params = {'transactionId': transaction_id, 'deviceId': device_id, 'newStatus': new_status}

    response = request(
        url=url,
        params=params,
        headers=headers,
        method=method
    )

    if response.status == 200:
        return response.json()['status']
    else:
        logger.critical("Error when requesting provisioning:")
        logger.critical(response)
        return ""


def is_request_allowed(transaction_id: str, device_id: str, api_uri: str, token: str, poll_period: int = 30,
                       timeout: int = 2700) -> bool:
    """
    WARNING: This is a blocking function until it succeeds or times-out
    Periodically polls the Provisioning Request status until it is allowed or denied.
    Times out after the set parameter or if the token expires. 
    :param str transaction_id: UUID returned when creating the request
    :param str device_id:  Identifier of the Device, like a serial number
    :param str api_uri: API Gateway endpoint (without https://)
    :param str token: Cognito Access Token
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


def get_gg_installer(url: str = URL_GREENGRASS_NUCLEUS_DL, zip_dest: str = GG_ZIP_DEST_DIR,
                     zip_filename: str = GG_ZIP_DEST_FILE, unzip_dir: str = GG_UNZIP_DEST_DIR) -> None:
    """
    Downloads the AWS Greengrass Installer archive and unzip it at specified location
    :param url: where to download the installer archive from
    :param zip_dest: where to store the archive once downloaded
    :param zip_filename: name of the zip file
    :param unzip_dir: where to unzip the archive
    :return: None
    """
    try:
        zip_dest = os.path.abspath(zip_dest)
        logger.debug("Creating directory: {}".format(zip_dest))
        os.makedirs(name=zip_dest, mode=0o700, exist_ok=True)
        dest_zip_path = os.path.join(zip_dest, zip_filename)
        urllib.request.urlretrieve(url=url, filename=dest_zip_path)
        with ZipFile(dest_zip_path, 'r') as zipf:
            zipf.extractall(unzip_dir)

    except Exception as e:
        logger.critical("Could not get greengrass installer:\n{}".format(e))
        raise


class SslCreds(object):
    """
    Faciliy Class to generate and manage SSL credentials
    """
    CN = SSL_CN
    OU = SSL_OU
    O = SSL_O
    L = SSL_L
    ST = SSL_ST
    C = SSL_C
    __SUPPORTED_OS = ['Linux', 'Darwin']
    AMZ_CA_URL = AMAZON_ROOT_CA_URL
    AMZ_CA_NAME = "AmazonRootCA1.pem"

    def __init__(self, dest_directory: str, base_name: str) -> None:
        """
        :param dest_directory: where to store the secrets
        :param base_name: a common prefix used for all the files generated.
        """
        self.os_type = platform.system()
        if self.os_type not in self.__SUPPORTED_OS:
            self._unsupported_os()
        self.dest_dir = os.path.abspath(dest_directory)
        self.base_name = base_name
        self.key_path = os.path.join(self.dest_dir, self.base_name + ".key")
        self.csr_path = os.path.join(self.dest_dir, self.base_name + ".csr")
        self.crt_path = os.path.join(self.dest_dir, self.base_name + ".crt")
        self.ca_path = os.path.join(self.dest_dir, self.AMZ_CA_NAME)

    @property
    def certificate_file_path(self) -> str:
        return self.crt_path

    @property
    def private_key_path(self) -> str:
        return self.key_path

    @property
    def root_ca_path(self) -> str:
        return self.ca_path

    def _get_dn_string(self) -> str:
        """
        Formats a string corresponding to the DN
        :return: nothing
        """
        return "/CN={}/OU={}/O={}/L={}/ST={}/C={}".format(self.CN, self.OU, self.O, self.L, self.ST, self.C)

    def create_private_key_and_csr(self) -> None:
        """
        Also downloads the Amazon Root CA
        :return: Nothing
        """
        if self.os_type not in self.__SUPPORTED_OS:
            self._unsupported_os()

        if self.os_type in ['Linux', 'Darwin']:
            self._create_private_key_and_csr_linux()
        self.download_amazon_root_ca()

    def download_amazon_root_ca(self) -> None:
        """
        Downloads and stores the Amazon Root CA
        :return: nothing
        """
        if not os.path.isfile(self.ca_path):
            urllib.request.urlretrieve(url=self.AMZ_CA_URL, filename=self.ca_path)
            os.chmod(path=self.csr_path, mode=0o400)

    def get_csr(self) -> str:
        """
        Reads the CSR from a file and returns it as a string
        :return: CSR string
        """
        if not os.path.isfile(self.csr_path):
            return ""
        with open(self.csr_path, 'r') as f:
            return f.read()

    def _create_private_key_and_csr_linux(self) -> None:
        """
        Creates the Private Key and CSR files
        :return: nothing
        """
        try:
            logger.debug("Creating directory: {}".format(self.dest_dir))
            os.makedirs(name=self.dest_dir, mode=0o700, exist_ok=True)
            # Generate the key
            subprocess.call(['openssl', 'genrsa', '-out', self.key_path, '4096'])
            os.chmod(path=self.key_path, mode=0o400)
            # Generate CSR
            subprocess.call(
                ['openssl', 'req', '-new', '-key', self.key_path, '-out', self.csr_path,
                 '-subj', self._get_dn_string()])
            os.chmod(path=self.csr_path, mode=0o400)
        except Exception as e:
            logger.critical("Error when creating the key or csr:\n {}".format(e))
            raise

    def _unsupported_os(self):
        raise ProvisioningException("System detected: {}. Only Linux platforms supported.".format(self.os_type))

    def save_crt(self, crt: str) -> None:
        '''
        Saves CRT file and position file mode accordingly.
        Removes an older CRT file if existing before storing the new one.
        If crt is None existing CRT will be deleted.
        :param crt: the CRT as a string
        :return: Nothing
        '''
        if os.path.isfile(self.crt_path):
            os.chmod(path=self.crt_path, mode=0o600)
            os.remove(self.crt_path)
        if crt is not None:
            with open(self.crt_path, "w") as f:
                f.write(crt)
            os.chmod(path=self.crt_path, mode=0o400)


def provision_thing(device_id: str, transaction_id: str, csr: str, token: str, api_uri: str,
                    prov_template: str) -> typing.Any:
    """
    Calls the API to provision a new Thing in IoT Core, providing a CSR and expecting a signed certificate in return.
    :param prov_template: Name of the Provisioning Template
    :param device_id: Identifier of the Device, like a serial number
    :param transaction_id: UUID returned when creating the request
    :param csr: the CSR as string
    :param token: Cognito Access Token
    :param api_uri: API Gateway endpoint (without https://)
    :return: Generally a dictionary containing the IoT Core provisioning response
    """
    url = "https://{}{}".format(api_uri, API_RESOURCE_REGISTER_THING)
    method = "POST"
    headers = {'Content-Type': "application/json", 'Authorization': token}
    params = None
    data_as_json = True
    data = {
        'CSR': csr,
        'deviceId': device_id,
        'transactionId': transaction_id,
        'provisioningTemplate': prov_template
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
        return response.json()
    else:
        logger.critical("Error when registering Thing:")
        logger.critical(response)
        return {}


def get_greengrass_config(token: str, api_uri: str, transaction_id: str,
                          device_id: str, gg_config_file: str):
    """
    Calls the API to get the customised Greengrass Configuration template. Expects the template to be Bse64 encoded.
    :param gg_config_file: Greengrass Configuration File name
    :param token: Cognito Access Token
    :param api_uri: API Gateway endpoint (without https://)
    :param transaction_id: UUID returned when creating the request
    :param device_id: Identifier of the Device, like a serial number
    :return: Generally a dictionary containing the IoT Core provisioning response
    """
    url = "https://{}{}".format(api_uri, API_RESOURCE_GREENGRASS_CONFIG)
    method = "GET"
    headers = {'Authorization': token, "Accept": "text/plain"}
    params = {'transactionId': transaction_id, 'deviceId': device_id, 'greengrassConfigTemplate': gg_config_file}

    response = request(
        url=url,
        params=params,
        headers=headers,
        method=method
    )

    if response.status == 200:
        return b64decode(response.body).decode('utf-8')
    else:
        logger.critical("Error when requesting provisioning:")
        logger.critical(response)
        return None


def get_greengrass_version() -> str:
    """
    Determines the version of Greengrass by atempting to run its binary
    :return: The version returned by the binary or an emtpy string
    """
    try:
        ggi_bin = "{}/lib/Greengrass.jar".format(GG_UNZIP_DEST_DIR)
        gg_ver = subprocess.check_output(['java', '-jar', ggi_bin, '--version'], stderr=subprocess.STDOUT)
        match = re.search('(\d+\.\d+.\d+)', str(gg_ver))
        if match:
            return match[0]
        else:
            return ""
    except Exception as e:
        logger.critical("Exception when checking Greengrass installer version:\n {}".format(e))
        return ""


def populate_greengrass_config(ssl_creds: SslCreds, template: str) -> str:
    """

    :param ssl_creds: The Class instance holding the SSL credentials
    :param template: The greengrass configuration template as a string
    :return: The updated template
    """
    template = template.replace("$system.certificateFilePath$", ssl_creds.certificate_file_path)
    template = template.replace("$system.privateKeyPath$", ssl_creds.private_key_path)
    template = template.replace("$system.rootCaPath$", ssl_creds.root_ca_path)
    template = template.replace("$system.rootpath$", GG_ROOT_PATH)
    gg_ver = get_greengrass_version()
    if not gg_ver:
        raise ProvisioningException("Undefined Greengrass installer version")
    template = template.replace("$services.aws.greengrass.Nucleus.version$", gg_ver)
    return template


def save_greengrass_config(cfg: str, directory: str = GG_UNZIP_DEST_DIR, file_name: str = GG_CONFIG_FILE_NAME) -> str:
    """
    Stores the Greegrass configuration template at the defined location
    :param cfg: Configuration template fully populated
    :param directory: Where to store teh configuration file
    :param file_name: How to call the configuration file
    :return: The path/name of the configuration file
    """
    gg_config_path = os.path.join(os.path.abspath(directory), file_name)
    logger.debug("Saving Greengrass config to: {}".format(gg_config_path))
    with open(gg_config_path, "w") as f:
        f.write(cfg)
    os.chmod(path=gg_config_path, mode=0o644)
    return gg_config_path


def install_greengrass(config_path: str, gg_root: str = GG_ROOT_PATH, installer_path: str = GG_UNZIP_DEST_DIR) -> int:
    """
    Runs the greengrass installer.
    WARNING: using subprocess didn't work, so folded back to os.system method!!!
    :param config_path:
    :param gg_root: Root path for Greengrass V2 application
    :param installer_path: Where to find the installer (home) folder. Generally the unzip directory.
    :return: The code returned by the OS after running the installer.
    """
    command = 'java -Droot="{}" -Dlog.store=FILE -jar {}/lib/Greengrass.jar --init-config {} ' \
              '--component-default-user ggc_user:ggc_group ' \
              '--setup-system-service true'.format(gg_root, installer_path, config_path)
    return os.system(command)


# DO NOT CHANGE THE CONSTANTS BELOW
USER_NAME = "$USER_NAME$"
THING_NAME = "$THING_NAME$"
DEVICE_SERIAL = "$DEVICE_SERIAL$"
API_URI = "$API_URI$"
TOKEN = "$TOKEN$"
GG_CFG_FILE = "$GG_CFG_FILE$"
THING_PROV_TEMPLATE = "$THING_PROV_TEMPLATE$"
# DO NOT CHANGE CONSTANTS ABOVE


if __name__ == "__main__":
    """
    Overview of the sequence of operations:
    * Check that the host meets the Greengrass V2 (software) requirements: 
      https://docs.aws.amazon.com/greengrass/v2/developerguide/setting-up.html#installation-requirements
    * Initiate a new provisioning request to the backend
    * Wait for the provisioning request to be allowed by the operator
    * Download Greengrass V2 installer archive in its latest version
    * Generate SSL credentials
    * Request provisioning to IoT Core with CSR
    * Store signed certificate
    * Get Greengrass configuration template from backend (partially filled-in)
    * Finish filling-in the configuration template and store it on disk
    * Launch the Greengrass installer
    * Be polite and say goodbye
    
    Notes:
    * The IoT Thing provisioning is defined by a provisioning template located in S3.
      The template to use can be specified in the API call with the body element 'provisioningTemplate'.  
    * The Greengrass configuration template is also located in S3. 
      The template to use can be specified in the API call with the query string parameter 'greengrassConfigTemplate'.
    """
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

        # Get a time-limited Application Token - removed when the token got embedded in the downloaded script
        app_token = TOKEN

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
        new_status = Status.PROGRESS
        resp_status = update_provisioning_request_status(token=app_token,
                                                         api_uri=API_URI,
                                                         transaction_id=request_id,
                                                         device_id=DEVICE_SERIAL,
                                                         new_status=new_status.name)
        if new_status.name != resp_status:
            raise FailProvisioning("Status could not be updated to {}.".format(new_status.name))
        # Download Greengrass archive and extract it
        try:
            get_gg_installer()
        except Exception:
            raise FailProvisioning("Could not get Greengrass Installer. Provisioning Failed.")
        # Create SLL Credentials
        try:
            creds = SslCreds(
                dest_directory=GG_SECRETS_DIR,
                base_name="greengrassV2"
            )
            creds.create_private_key_and_csr()
            csr = creds.get_csr()
            if not csr:
                raise ProvisioningException("CSR is empty.")
        except Exception:
            raise FailProvisioning("Could not create Key and CSR. Provisioning Failed.")
        # Request Thing Provisioning from CSR
        response = provision_thing(device_id=DEVICE_SERIAL,
                                   transaction_id=request_id,
                                   csr=csr,
                                   token=app_token,
                                   api_uri=API_URI,
                                   prov_template=THING_PROV_TEMPLATE
                                   )
        if not response:
            raise FailProvisioning("Registering IoT Thing Failed.")
        crt = response.get('certificatePem')
        if crt is None or response['thingName'] != THING_NAME or response['deviceId'] != DEVICE_SERIAL:
            raise FailProvisioning("Mismatching data or missing CRT:\n{}".format(response))
        creds.save_crt(crt)

        try:
            # Install Greengrass Core
            raw_cfg = get_greengrass_config(token=app_token,
                                            api_uri=API_URI,
                                            transaction_id=request_id,
                                            device_id=DEVICE_SERIAL,
                                            gg_config_file=GG_CFG_FILE)
            logger.debug("Config file received from API:\n{}".format(raw_cfg))
            cfg = populate_greengrass_config(ssl_creds=creds, template=raw_cfg)
            logger.debug("Final Greengrass configuration:\n{}".format(cfg))
            cfg_path = save_greengrass_config(cfg)
        except Exception as e:
            msg = "Exception during Greengrass config preparation:\n{}".format(e)
            logger.critical(msg)
            raise FailProvisioning(e)

        try:
            resp = install_greengrass(cfg_path)
            if resp == 0:
                logger.info("Greengrass V2 successfully installed.")
            else:
                raise FailProvisioning("Greengrass V2 installation failed.")
        except Exception as e:
            msg = "Greengrass Installation failed:\n{}".format(e)
            logger.critical(msg)
            raise FailProvisioning(e)

        # Update Status to SUCCESS
        new_status = Status.SUCCESS
        resp_status = update_provisioning_request_status(token=app_token,
                                                         api_uri=API_URI,
                                                         transaction_id=request_id,
                                                         device_id=DEVICE_SERIAL,
                                                         new_status=new_status.name)
        if new_status.name != resp_status:
            logger.error("Status could not be updated to {}.".format(new_status.name))

        # End message
        print("WARNING: Running containerized Lambda functions is not enabled. "
              "Check the documentation if you want to enable it:\n"
              "https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#set-up-device-environment")
        print("Goodbye. Enjoy Greengrass V2.")

    except FailProvisioning as e:
        if 'request_id' in locals() and 'app_token' in locals():
            logger.critical("Provisioning process failed. Changing State to Failed:\n{}".format(e))
            update_provisioning_request_status(token=app_token,
                                               api_uri=API_URI,
                                               transaction_id=request_id,
                                               device_id=DEVICE_SERIAL,
                                               new_status=Status.FAILED.name)
        else:
            logger.critical("Process aborted due to Exception but cloud not Cancel the request\n {}".format(e))

        sys.exit(1)

    except CancelProvisioning as e:
        if 'request_id' in locals() and 'app_token' in locals():
            logger.critical(
                "Aborting Provisioning Request due to Exception. Chancing State to Cancelled:\n{}".format(e))
            update_provisioning_request_status(token=app_token,
                                               api_uri=API_URI,
                                               transaction_id=request_id,
                                               device_id=DEVICE_SERIAL,
                                               new_status=Status.CANCELLED.name)
        else:
            logger.critical("Process aborted due to Exception but cloud change its state to Cancelled:\n {}".format(e))

        sys.exit(1)

    except AbortProvisioning as e:
        logger.critical("Process aborted due to Exception. State has not been updated:\n {}".format(e))
        sys.exit(1)
