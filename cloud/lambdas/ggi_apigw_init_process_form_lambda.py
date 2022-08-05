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
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

import boto3
from urllib.parse import parse_qs

# Cognito Configuration
COG_POOL = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_POOL:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_CID = os.environ.get("COG_CLIENT_ID")
if not COG_CID:
    raise Exception("Environment variable COG_CLIENT_ID missing")
S3_RESOURCES = os.environ.get("S3_RESOURCES_BUCKET")
if not S3_RESOURCES:
    raise Exception("Environment variable S3_RESOURCES_BUCKET missing")
S3_OUTPUTS = os.environ.get("S3_DOWNLOAD_BUCKET")
if not S3_RESOURCES:
    raise Exception("Environment variable S3_DOWNLOADS_BUCKET missing")
INSTALLER_SCRIPT = os.environ.get("INSTALLER_SCRIPT_NAME", "install_gg.py")

# Set some boto3 clients
cog_client = boto3.client('cognito-idp')
s3_client = boto3.client('s3')
iot_client = boto3.client('iot')

INSERT_STRING = "# INSERT CONSTANTS BELOW"
PRESIGNED_EXPIRATION = 600


def bad_request(msg, status_code=403):
    # TODO: Make better HTML response for the user
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def internal_error(status_code=500):
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def get_authorizer_params(event, to_retrieve):
    params = event['requestContext'].get('authorizer')
    d = {}
    if params:
        for p in to_retrieve:
            d[p] = params[p]
    # logger.debug("Authorizer Params: {}".format(d))
    return d


def get_form_elements(event):
    """
    """
    params = event['body']
    d = {}
    if params:
        d = parse_qs(params)
    logger.debug("Form Elements: {}".format(d))
    return d


def get_app_token(cognito_url, client_id, client_secret):
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
        return None


def get_installer_script(installer_script, bucket):
    try:
        response = s3_client.get_object(Bucket=bucket, Key=installer_script)
        script = response['Body'].read().decode('utf-8')
        logger.debug("S3 object read: {}/{}".format(bucket, installer_script))
        return script
    except Exception as e:
        logger.critical("Exception when reading Script {}/{} from S3: \n{}".format(bucket, installer_script, e))
        return None


def write_to_s3(bucket, data, key, s3_client):
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


def create_presigned_url(bucket_name, key, s3_client, expiration):
    try:
        logger.debug("Creating presigned URL for: {}/{}".format(bucket_name, key))
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': key},
                                                    ExpiresIn=expiration)
        logger.debug("Presigned URL is:\n{}".format(response))
        return response
    except Exception as e:
        logger.critical("Exception when generating the presigned URL")
        return None

    # The response contains the presigned URL
    return response


def make_response(url, script_name="install_gg.py"):
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
    python3 {1}
    </code></pre>

    </body>
    </html>
    '''.format(url, script_name)


    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': html
    }

def lambda_handler(event, context):
    try:
        logger.debug("event is:\n{}".format(event))
        params = get_form_elements(event=event)
        if not ('thingName' in params and 'deviceId' in params):
            return bad_request("Malformed Form data")
        msg = ""
        thing_name = params['thingName'][0]
        device_id = params['deviceId'][0]
        if not is_valid_thing_name(thing_name):
            msg += "Thing Name must comply with specification: '{}'\n".format("^[0-9a-zA-Z:\-_]*$")
        if not is_new_iot_thing(thing_name=thing_name, iot_client=iot_client):
            msg += "This Thing Name is already used: {}".format(thing_name)
        if " " in device_id:
            msg += "Device Id cannot contain spaces\n"
        if msg:
            return bad_request(msg=msg)

        user_data = get_authorizer_params(event, ['username', 'email'])
        api_uri = "https://{}/{}".format(event['requestContext']['domainName'],
                                         event['requestContext']['stage']).rstrip("/")
        secret = get_user_pool_secret(cog_client=cog_client,
                                      user_pool_id=COG_POOL,
                                      client_id=COG_CID)

        token = get_app_token(cognito_url=COG_URL, client_id=COG_CID, client_secret=secret)
        if not token:
            logger.critical("Could not get the token for the app.")
            return internal_error()

        cfg_const = {'$USER_NAME$': user_data['username'],
                     '$THING_NAME$': thing_name,
                     '$DEVICE_SERIAL$': device_id,
                     '$API_URI$': api_uri,
                     '$TOKEN$': token
                     }
        logger.debug("Config String:\n{}".format(cfg_const))

        script = get_installer_script(installer_script=INSTALLER_SCRIPT, bucket=S3_RESOURCES)
        if not script:
            logger.critical("Could not read the script from S3.")
            return internal_error()

        for k,v in cfg_const.items():
            script = script.replace(k, v, 1)

        out_file_name = "{}-{}-{}".format(thing_name, device_id, INSTALLER_SCRIPT)
        if write_to_s3(bucket=S3_OUTPUTS, key=out_file_name, data=script, s3_client=s3_client) is not True:
            logger.critical("Could not write the script to S3.")
            return internal_error()

        presigned_url = create_presigned_url(bucket_name=S3_OUTPUTS, key=out_file_name,
                                             s3_client=s3_client, expiration=PRESIGNED_EXPIRATION)

        return make_response(url = presigned_url)

    except Exception as e:
        logger.critical("Exception: {}".format(e))
        return internal_error()
