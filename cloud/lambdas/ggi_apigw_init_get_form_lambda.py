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
Returns the HTML form for the user to input the properties to configure the IoT Thing and Greengrass provisioning.
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *


def get_form_html(resource_path: str, code: str, thing_name: str = "", serial: str = "", message: str = "") -> str:
    """

    :param resource_path: API Gateway URL to POST the form when submitted
    :param code: Authorisation code to be exchanged later for a token
    :param thing_name: AWS IoT Thing name to be created
    :param serial: A string for identifying the Device, like a serial number
    :param message: Message to be displayed on the form
    :return: HTML document as a string
    """
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
    logger.debug("HTML Form doc: \n{}".format(html))
    return html


def lambda_handler(event, context) -> dict:
    """
    Expects the following query string parameter(s):
    * code: Authorisation code to be exchanged later for a token
    :return: response dict
    """
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': get_form_html(resource_path=event['requestContext']['path'],
                              code=event['queryStringParameters'].get('code'))
    }
