#!/usr/bin/env python3
"""
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""
import aws_cdk as cdk

from cdk.greengrass_installer_stack import GreengrassInstallerStack
from cdk.environment_variables import check_deploy_env_vars, RuntimeEnvVars
from cdk_nag import AwsSolutionsChecks, NagSuppressions

# Check that required Environment Variables are effectively declared
check_deploy_env_vars()
my_env = RuntimeEnvVars()

app = cdk.App()
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
GreengrassInstallerStack(app, "GreengrassInstallerStack", env=my_env)

app.synth()
# print("Runtime environment variables: \n" + str(my_env))

