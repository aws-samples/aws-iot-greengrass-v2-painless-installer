import aws_cdk as core
import aws_cdk.assertions as assertions

from cdk.greengrass_installer_stack import GreengrassInstallerStack


# example tests. To run these tests, uncomment this file along with the example
# resource in cdk_root/greengrass_installer_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = GreengrassInstallerStack(app, "cdk-root")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
