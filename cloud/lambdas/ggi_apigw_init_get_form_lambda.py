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
import os

import boto3

from ggi_lambda_utils import *

# S3 bucket containing the template documents
THING_S3_BUCKET = os.environ.get("S3_BUCKET_THING_TEMPLATES")
if not THING_S3_BUCKET:
    raise Exception("Environment variable S3_BUCKET_THING_TEMPLATES missing")

# S3 bucket containing the greengrass configuration files
GG_S3_BUCKET = os.environ.get("S3_BUCKET_GG_CONFIGS")
if not GG_S3_BUCKET:
    raise Exception("Environment variable S3_BUCKET_GG_CONFIGS missing")

S3_RESOURCES = os.environ.get("S3_RESOURCES_BUCKET")
if not S3_RESOURCES:
    raise Exception("Environment variable S3_RESOURCES_BUCKET missing")


def make_html_dropdown(item_id: str, label: str, choices: list[str]):
    dropdown = '<label for="{0}">{1}<br></label>\n'.format(item_id, label)
    dropdown += '<select required name="{0}" id="{0}">\n'.format(item_id)
    for choice in choices:
        dropdown += '<option value="{0}">{0}</option>\n'.format(choice)
    dropdown += '</select>'
    return dropdown


def get_form_html(resource_path: str, code: str, thing_name: str = "", serial: str = "", message: str = "",
                  install_scripts: list[str] = [], prov_tplts: list[str] = [], gg_configs: list[str] = []) -> str:
    """
    :param install_scripts: A list of provisioning templates to build a dropdown from
    :param gg_configs: A list of configuration files to build a dropdown from
    :param prov_tplts: A list of provisioning templates to build a dropdown from
    :param resource_path: API Gateway URL to POST the form when submitted
    :param code: Authorisation code to be exchanged later for a token
    :param thing_name: AWS IoT Thing name to be created
    :param serial: A string for identifying the Device, like a serial number
    :param message: Message to be displayed on the form
    :return: HTML document as a string
    """

    install_scripts_dropdown = make_html_dropdown(item_id="installScript",
                                                  label="Select the Installation Script:",
                                                  choices=install_scripts)

    gg_configs_dropdown = make_html_dropdown(item_id="greengrasConfigFile",
                                             label="Select the Greengrass Configuration File:",
                                             choices=gg_configs
                                             )
    prov_tplts_dropdown = make_html_dropdown(item_id="thingProvisioningTemplate",
                                             label="Select the Thing Provisioning Template:",
                                             choices=prov_tplts
                                             )

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
      {4}<br><br>
      {5}<br><br>
      {6}<br><br>
      <input type="submit" value="Submit">
    </form> 
    </body>
    </html>
    '''.format(action, serial, thing_name, message, install_scripts_dropdown, prov_tplts_dropdown, gg_configs_dropdown)
    logger.debug("HTML Form doc: \n{}".format(html))
    return html


def lambda_handler(event, context) -> dict:
    """
    Expects the following query string parameter(s):
    * code: Authorisation code to be exchanged later for a token
    :return: response dict
    """
    s3 = boto3.client("s3")

    install_scripts = list_bucket(
        s3_client=s3,
        bucket_name=S3_RESOURCES,
        suffix='.py'
    )

    prov_tplts = list_bucket(
        s3_client=s3,
        bucket_name=THING_S3_BUCKET,
        suffix=".json"
    )
    gg_configs = list_bucket(
        s3_client=s3,
        bucket_name=GG_S3_BUCKET,
        suffix=".yaml"
    )

    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': get_form_html(resource_path=event['requestContext']['path'],
                              code=event['queryStringParameters'].get('code'),
                              install_scripts=install_scripts,
                              prov_tplts=prov_tplts,
                              gg_configs=gg_configs)
    }
