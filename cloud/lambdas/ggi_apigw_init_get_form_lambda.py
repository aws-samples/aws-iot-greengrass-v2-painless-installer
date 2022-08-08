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


def get_form_html(resource_path, code, thing_name="", serial="", message=""):
    action = "{}?code={}".format(resource_path, code)
    html = '''
    <!DOCTYPE html>
    <html>
    <body>

    <h2>Enter the Provisioning Request properties below and submit</h2>
    <p>{3}</p><br>
    <form method="post" action={0}>
      <label for="deviceId">Device serial number:</label><br>
      <input type="text" id="deviceId" name="deviceId" value="{1}"><br>
      <label for="thingName">Thing name:</label><br>
      <input type="text" id="thingName" name="thingName" value="{2}"><br><br>
      <input type="submit" value="Submit">
    </form> 

    </body>
    </html>
    '''.format(action, serial, thing_name, message)
    return html


def lambda_handler(event, context):

    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': get_form_html(resource_path=event['requestContext']['path'],
                              code=event['queryStringParameters'].get('code'))
    }

