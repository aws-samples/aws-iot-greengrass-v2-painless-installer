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
Returns a 302 Redirect to Cognito log-in page with a call-back URL to display the Provisioning Request initiation
Form after successful log-in.
This is a 'trick' to force log-in before accessing the form but tnot require log-in again when submitting it.
The Authorization Code returned by Cognito afer log-in will be embedded in the Form POST payload, which will
allow the Form resource to exchange eh code for a token in order to authenticate the user.
If you know a better way to do a two-step auth without a client app, let me know: lautip@amazon.com
"""
import boto3
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Cognito Configuration
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_C_NAME = os.environ.get("COGNITO_CLIENT_NAME")
if not COG_C_NAME:
    raise Exception("Environment variable COG_CLIENT_ID missing")
COG_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_USER_POOL_ID:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")
FORM_RESOURCE = "form/"


def internal_error(status_code: int = 500) -> dict:
    """
    Something went wrong
    :param status_code: status code to use - default = 500
    :return: response
    """
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def lambda_handler(event, context):

    cid = get_cognito_client_id_from_name(cog_client=boto3.client('cognito-idp'),
                                          pool_id=COG_USER_POOL_ID,
                                          name=COG_C_NAME)
    if not cid:
        logger.critical("Couldn't determine the Cognito Client ID from its name: {}".format(COG_C_NAME))
        return internal_error()

    auth_url = "{0}/login?client_id={1}&response_type=code".format(COG_URL, cid)
    redirect = "&redirect_uri=https://{0}{1}/{2}".format(event['requestContext']['domainName'],
                                                         event['requestContext']['path'],
                                                         FORM_RESOURCE)
    location = "{0}{1}".format(auth_url, redirect)
    logger.debug("Redirecting to: {}".format(location))

    return {
        'statusCode': 302,
        'headers': {'Content-Type': "application.json",
                    'Location': location},
        'body': json.dumps({})
    }
