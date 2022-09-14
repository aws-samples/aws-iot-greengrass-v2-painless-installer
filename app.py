#!/usr/bin/env python3
import os

import aws_cdk as cdk

from cdk.greengrass_installer_stack import GreengrassInstallerStack
from cdk.environment_variables import check_deploy_env_vars, RuntimeEnvVars

# Check that required Environment Variables are effectively declared
check_deploy_env_vars()
my_env = RuntimeEnvVars()

app = cdk.App()
GreengrassInstallerStack(app, "GreengrassInstallerStack", env=my_env)

app.synth()


