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

import logging
import os
import sys

# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)


def ok_200():
    page = '<!doctype html><html lang="en-us"> <body><h1>The provisioning has been approved</h1></body></html>'
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def lambda_handler(event, context):
    # TODO: Implement the real funcion
    logger.debug("Event: {}".format(event))
    return ok_200()
