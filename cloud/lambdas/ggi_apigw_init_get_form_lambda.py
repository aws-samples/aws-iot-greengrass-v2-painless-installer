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

FORM_RESOURCE_PATH = "/manage/init/form/"


def get_authorizer_params(event):
    to_retrieve = ['code']
    params = event['requestContext'].get('authorizer')
    d = {}
    if params:
        for p in to_retrieve:
            d[p] = params[p]
    # logger.debug("Authorizer Params: {}".format(d))
    return d


def lambda_handler(event, context):

    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html"},
        'body': get_form_html(resource_path=FORM_RESOURCE_PATH,
                              code=get_authorizer_params(event).get('code'))
    }

