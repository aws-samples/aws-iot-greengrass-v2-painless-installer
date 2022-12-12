#!/usr/bin/env python3

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

