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

# Cognito Configuration
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_CID = os.environ.get("COG_CLIENT_ID")
if not COG_CID:
    raise Exception("Environment variable COG_CLIENT_ID missing")
FORM_RESOURCE = "form/"


def lambda_handler(event, context):
    auth_url = "{0}/login?client_id={1}&response_type=code".format(COG_URL, COG_CID)
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
