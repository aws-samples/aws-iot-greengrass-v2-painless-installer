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
Processes the initialisation form received:
* Validate the user Auth
* Validates the parameters received
* Configures the script to run at the edge
* Returns an HTML page where the user can copy the link to the installation script to download
and run it on the Device

The provisioning script contains a Cognito Token.
The S3 pre-signed URL has a short validity period.
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *
from typing import List

import boto3
from urllib.parse import parse_qs

# Cognito Configuration
COG_POOL = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_POOL:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_CID = os.environ.get("COGNITO_CLIENT_ID")
if not COG_CID:
    raise Exception("Environment variable COGNITO_CLIENT_ID missing")
S3_RESOURCES = os.environ.get("S3_RESOURCES_BUCKET")
if not S3_RESOURCES:
    raise Exception("Environment variable S3_RESOURCES_BUCKET missing")
S3_OUTPUTS = os.environ.get("S3_DOWNLOAD_BUCKET")
if not S3_OUTPUTS:
    raise Exception("Environment variable S3_DOWNLOADS_BUCKET missing")
INSTALLER_SCRIPT = os.environ.get("DEFAULT_INSTALLER_SCRIPT_NAME")
if not INSTALLER_SCRIPT:
    raise Exception("Environment variable INSTALLER_SCRIPT_NAME missing.")
GG_CFG_FILE = os.environ.get("DEFAULT_GREENGRASS_CONFIG_FILE")
if not GG_CFG_FILE:
    raise Exception("Environment variable DEFAULT_GREENGRASS_CONFIG_FILE missing.")
THING_PROV_TEMPLATE = os.environ.get("DEFAULT_THING_PROVISIONING_TEMPLATE")
if not THING_PROV_TEMPLATE:
    raise Exception("Environment variable DEFAULT_THING_PROVISIONING_TEMPLATE missing.")

# Set some boto3 clients
cog_client = boto3.client('cognito-idp')
s3_client = boto3.client('s3')
iot_client = boto3.client('iot')

# Validity period of the S3 pre-signed URL
PRESIGNED_EXPIRATION = 600


def bad_request(msg: str, status_code: int = 403) -> dict:
    """
    :param msg: error message to display
    :param status_code: error code
    :return: response
    """
    # TODO: Make better HTML response for the user
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def internal_error(status_code: int = 500) -> dict:
    """
    No custom message supported to avoid leaking of info
    :param status_code: error code
    :return: response
    """
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def get_authorizer_params(event: dict, to_retrieve: List[str]) -> dict:
    """
    Returns a dictionary containing the elements in to_retrieve fetched from the Authorizer parameters
    :param event: the event passed by API Gateway to the handler
    :param to_retrieve: list of strings describing the parameters to retrieve
    :return: dictionary with the retrieved parameters
    """
    params = event['requestContext'].get('authorizer')
    d = {}
    if params:
        for p in to_retrieve:
            d[p] = params[p]
    # logger.debug("Authorizer Params: {}".format(d))
    return d


def get_form_elements(event: dict) -> dict:
    """
    Parses the form to retrieve its fields
    :param event: the event passed by API Gateway to the handler
    :return: dictionary with form elements
    """
    params = event['body']
    if params:
        parsed = parse_qs(params)
    d = {}
    for k, v in parsed.items():
        d[k] = v[0]
    logger.debug("Form Elements: {}".format(d))
    return d


def get_app_token(cognito_url: str, client_id: str, client_secret: str) -> str:
    """
    :param cognito_url: Cognito domain for this app
    :param client_id: Cognito client ID for this app
    :param client_secret: Cognito client secret for this app
    :return: Cognito Access token or an empty string
    """
    url = "{}/oauth2/token".format(cognito_url)
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


def get_installer_script(installer_script: str, bucket: str) -> str:
    """
    Retrieve the installation script from S3. This script is sufficiently compact to be returned as a string
    :param installer_script: S3 key pointing to the script
    :param bucket: S3 Bucket name
    :return: the script or an emtpy string
    """
    try:
        response = s3_client.get_object(Bucket=bucket, Key=installer_script)
        script = response['Body'].read().decode('utf-8')
        logger.debug("S3 object read: {}/{}".format(bucket, installer_script))
        return script
    except Exception as e:
        logger.critical("Exception when reading Script {}/{} from S3: \n{}".format(bucket, installer_script, e))
        return ""


def write_to_s3(bucket: str, data: str, key: str, s3_client: boto3.client) -> bool:
    """
    Write data to S3
    :param bucket: S3 Bucket name
    :param data: body of the objet to write
    :param key: S3 object key
    :param s3_client: boto3 client for S3
    :return: True for success or False
    """
    try:
        if not isinstance(data, bytes):
            data = bytes(data, "utf-8")
        _ = s3_client.put_object(Body=data,
                                 Bucket=bucket,
                                 Key=key)
        return True
    except Exception as e:
        logger.critical("Exception when writing to S3: \n{}".format(e))
        return False


def create_presigned_url(bucket: str, key: str, s3_client: boto3.client, expiration: int) -> str:
    """
    Return a pre-signed URL for the S3 object
    :param bucket: S3 Bucket name
    :param key:S3 object key
    :param s3_client:  boto3 client for S3
    :param expiration: URL expiration time in seconds
    :return: pre-signed URL as string
    """
    try:
        logger.debug("Creating presigned URL for: {}/{}".format(bucket, key))
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket,
                                                            'Key': key},
                                                    ExpiresIn=expiration)
        logger.debug("Presigned URL is:\n{}".format(response))
        return response
    except Exception as e:
        logger.critical("Exception when generating the presigned URL: \n{}".format(e))
        return ""


def make_response(url: str, script_name: str = "install_gg.py") -> dict:
    """
    Returns an HTML page giving instructions to the user to proceed with installation
    :param url: pre-sgined URL to download the script
    :param script_name: the suggested name of the script once downloaded
    :return: Response containing the HTML page in the body
    """
    html = '''
    <!DOCTYPE html>
    <html>
    <body>

    <h2>Congratulations: you're ready to provision your device.</h2>
    <p>1. Copy the download URL by right-clicking on the link below.<br>
    <a class="ulink" href="{0}" target="_blank">Right click here and copy the link</a>.<br><br>
    2. Using of the commands below as a reference, download the installation script on the device.<br>
    <p>If you use wget: <br>
    <pre><code style="background-color: #eee; border: 1px solid #999; display: block;">
    wget -O {1} "&ltpaste download link here (leave the double quotes)&gt"
    </code></pre>
    </p>
    <p>If you use curl: <br>
    <pre><code style="background-color: #eee; border: 1px solid #999; display: block;">
    curl -o {1} "&ltpaste download link here (leave the double quotes)&gt"
    </code></pre>
    </p>
    3. Then launch the installation script with:</p>
    <pre><code style="background-color: #eee; border: 1px solid #999; display: block;">
    sudo python3 {1}
    </code></pre>

    </body>
    </html>
    '''.format(url, script_name)

    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': html
    }


def lambda_handler(event, context) -> dict:
    """
    Expects a form to be passed in the event body with the following elements:
    * thingName: the name of the IoT Thing to be created
    * deviceId: an identifer for the device like a serial number
    :return: HTML page with instructions for installing Greengrass on teh device
    """
    try:
        logger.debug("event is:\n{}".format(event))
        # Retrieve the form elements
        params = get_form_elements(event=event)
        if not ('thingName' in params and 'deviceId' in params):
            return bad_request("Malformed Form data")
        msg = ""
        thing_name = params['thingName']
        device_id = params['deviceId']
        installer_script = params.get('installScript', INSTALLER_SCRIPT)
        gg_cfg_file = params.get('greengrasConfigFile', GG_CFG_FILE)
        thing_prov_template = params.get('thingProvisioningTemplate', THING_PROV_TEMPLATE)

        # Check validity of the elements
        if not is_valid_thing_name(thing_name):
            msg += "Thing Name must comply with specification: '{}'\n".format("^[0-9a-zA-Z:\-_]*$")
        if not is_new_iot_thing(thing_name=thing_name, iot_client=iot_client):
            msg += "This Thing Name is already used: {}".format(thing_name)
        if " " in device_id:
            # FIXME: remove if/when spaces are supported
            msg += "Device Id cannot contain spaces\n"
        if msg:
            return bad_request(msg=msg)

        # Prepare the customized constants for the script
        user_data = get_authorizer_params(event, ['username', 'email'])
        api_uri = "{}/{}".format(event['requestContext']['domainName'],
                                 event['requestContext']['stage']).rstrip("/")
        secret = get_user_pool_secret(cog_client=cog_client,
                                      user_pool_id=COG_POOL,
                                      client_id=COG_CID)

        token = get_app_token(cognito_url=COG_URL, client_id=COG_CID, client_secret=secret)
        if not token:
            logger.critical("Could not get the token for the app.")
            return internal_error()

        # WARNING: The keys of this dict must match placeholders in the installation (raw) script
        cfg_const = {'$USER_NAME$': user_data['username'],
                     '$THING_NAME$': thing_name,
                     '$DEVICE_SERIAL$': device_id,
                     '$API_URI$': api_uri,
                     '$TOKEN$': token,
                     '$GG_CFG_FILE$': gg_cfg_file,
                     '$THING_PROV_TEMPLATE$': thing_prov_template
                     }
        logger.debug("Config String:\n{}".format(cfg_const))

        # Fetch the raw script from S3 and replace the constant values
        script = get_installer_script(installer_script=installer_script, bucket=S3_RESOURCES)
        if not script:
            logger.critical("Could not read the script from S3.")
            return internal_error()

        for k, v in cfg_const.items():
            script = script.replace(k, v, 1)

        # Save to S3 and get a pre-signed URL
        out_file_name = "{}-{}-{}".format(thing_name, device_id, installer_script)
        if write_to_s3(bucket=S3_OUTPUTS, key=out_file_name, data=script, s3_client=s3_client) is not True:
            logger.critical("Could not write the script to S3.")
            return internal_error()

        presigned_url = create_presigned_url(bucket=S3_OUTPUTS, key=out_file_name,
                                             s3_client=s3_client, expiration=PRESIGNED_EXPIRATION)
        if not presigned_url:
            logger.critical("Could not get the pre-signed URL.")
            return internal_error()

        # Return the HTML response page
        return make_response(url=presigned_url)

    except Exception as e:
        logger.critical("Exception: {}".format(e))
        return internal_error()
