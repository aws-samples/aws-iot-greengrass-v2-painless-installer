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

from constructs import Construct
from aws_cdk import (
    aws_dynamodb as dyndb
)
from cdk.environment_variables import RuntimeEnvVars
from cdk_nag import NagSuppressions


class DynamodbSetup(Construct):

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self._ddb_table = dyndb.Table(
            self, "ggProvisioningTacking",
            partition_key=dyndb.Attribute(name="deviceId", type=dyndb.AttributeType.STRING),
            sort_key=dyndb.Attribute(name="transactionId", type=dyndb.AttributeType.STRING),
            billing_mode=dyndb.BillingMode.PAY_PER_REQUEST)
        NagSuppressions.add_resource_suppressions(self._ddb_table,
                                                  [{'id': "AwsSolutions-DDB3",
                                                    'reason': "Not necessary for this table",
                                                    }
                                                   ])

        idx1 = "deviceId-transactionId-index"
        self._ddb_table.add_global_secondary_index(
            index_name=idx1,
            partition_key=dyndb.Attribute(name="deviceId", type=dyndb.AttributeType.STRING),
            sort_key=dyndb.Attribute(name="transactionId", type=dyndb.AttributeType.STRING),
        )

        idx2 = "thingName-transactionId-index"
        self._ddb_table.add_global_secondary_index(
            index_name=idx2,
            partition_key=dyndb.Attribute(name="thingName", type=dyndb.AttributeType.STRING),
            sort_key=dyndb.Attribute(name="transactionId", type=dyndb.AttributeType.STRING),
        )

        idx3 = "transactionId-deviceId-index"
        self._ddb_table.add_global_secondary_index(
            index_name=idx3,
            partition_key=dyndb.Attribute(name="transactionId", type=dyndb.AttributeType.STRING),
            sort_key=dyndb.Attribute(name="deviceId", type=dyndb.AttributeType.STRING),
        )

        # Update the relevant Environment variables values
        env.dynamodb_table_name.value = self._ddb_table.table_name
        env.dynamodb_idx_dev_trans.value = idx1
        env.dynamodb_idx_thing_trans.value = idx2
        env.dynamodb_idx_trans_dev.value = idx3

    @property
    def table(self):
        return self._ddb_table
