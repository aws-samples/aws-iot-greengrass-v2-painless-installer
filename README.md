# Welcome to the Greengrass V2 Installation solution

## Overview
This solution allows installing Greengrass V2 on an edge gateway without requiring access to the AWS account
where the device will connect. The User supervising the installation only needs to be able to authenticate
with Amazon Cognito in order to initiate the installation process. No specific knowledge of the AWS Cloud nor
Greengrass is necessary. The solution can be further customized for instance to federate user authentication to
your enterprise identity management system (e.g. Active Directory).

## Architecture diagram
The architecture uses a minimum number of AWS services to keep it easy to maintain and cost-effective.
Amazon DynamoDB tracks the state of each installation process.
A combination of Amazon API Gateway resources and AWS Lambda functions takes care of the various actions to be
performed.
Amazon S3 buckets store the various scripts and templates used in the process. Those can be customized as necessary.
![Architecture Diagram](./doc/ArchitectureDiagrams-OverallArchitecture.png)

### API Endpoints
![Endpoints](./doc/ArchitectureDiagrams-APIEndpoints.png)

## Flow Diagram
![Flow Diagram](./doc/ArchitectureDiagrams-FlowDiagram.png)

* The User triggers a new provisioning by filling a form after authentication.
* In response to the form the user receives a short-lived pre-signed URL to a script stored in an Amazon S3 bucket.
This script is customised for this provisioning and contains a time-limited access token to interact with the API.
* The User downloads and runs this script on the device.
* The script registers the star of the provisioning to the backend and waits for approval by the User (second factor authentication)
* The User receives an email with clickable 'allow' and a 'deny' links.
* If the provisioning is denied, the script ends there. If approved it continues.
* The script:
  * Downloads Greengrass V2 installation archive.
  * Generates the secrets and a CSR locally.
  * Contacts the backend for registering an IoT Thing and signing the CSR.
  * Stores locally the signed certificate received in the response.
  * Fetches a Greengrass Configuration Template from the backend. This template has been customised by the backend 
with all the necessary cloud-side information.
  * Finishes customising the Greengrass Configuration Template with local information.
  * Runs the Greengrass installer included in the downloaded archive.
  * Et voilà!

## Solution deployment on your AWS account

This application should be deployed using the AWS Cloud Development Kit (AWS CDK).
The CDK Stack has been written in Python 3 to stay consistent with the application language.
After installation all the operators will be able to provision a Greengrass V2 device in a few minutes without
requiring access to the AWS account.
As a summary, after installing a stable version of Node.js:

```bash
# Install the AWS CDK in Node.js
npm install -g aws-cdk
# Install the python3 packages required by CDK to generate the CloudFormation template
pip3 install -r requirements.txt
# If new account, you need to bootstrap the CDK (there is no risk to run it again...)
cdk bootstrap
# Then deploy the solution on your account
cdk deploy
```

More details on AWS CDK here: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html

In addition to providing the account ID, region and credentials to CDK, 
you will have to declare two environment variables:
* COGNITO_DOMAIN_PREFIX: a unique URL prefix for the Cognito domain, like `something-123456`. 
  Note that `aws`, `amazon` and `congnito` text are not allowed (https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html).
* SES_VERIFIED_EMAIL: the verified email address that SES will use to send emails. You'll receive an email for 
  verifying this address, so make sure you can access the mailbox.

**Important**: SES will be in Sandbox mode. Provisioning will fail until you take one of the actions described in the following 
documentation: https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html

Once deployed:
* Create users in Cognito (enable invitation message to be sent to each user)
* Add them to the User Group created by the CDK (by default: `GreengrassProvisioningOperators`)
* Make sure that users validate their email address

## Usage
All you have to do is:

1. Note the Output, provided by the CDK deployment, giving you the URL of the API.
2. From a web browser, hit this URL with the endpoint /manage/init/ 
    (for instance https://something.execute-api.eu-central-1.amazonaws.com/prod/manage/init)
3. Follow the instructions

You can test the process from an `Amazon Linux 2` EC2 instance (t2.micro is sufficient for testing). 
After launching the instance and connecting to it, you'll have to install Java with:

```
sudo amazon-linux-extras install java-openjdk11 -y
```

Once done you can terminate the instance and delete the Greengrass Code device, the IoT Thing and the 
Certificate created in IoT Core.

## Known Issues
Deployment on an AWS Account which never had API Gateway configured might fail. This is due to the logging which is
enabled in the CDK script. To solve the issue you can create a fake API and enable the logging. Then
delete this API. Subsequent deployments should not fail.

## Good to know
Five buckets are deployed by CDK:

* **Scripts**: This is where the script installing Greegrass on the device is located. You can add customized scripts
  to this Bucket and they will be listed as options in the selection form if their extension is `.py`.
* **provTemplate**: This is where the IoT Provisioning Template is stored. You can add customized templates
  to this Bucket and they will be listed as options in the selection form if their extension is `.json`.
* **GreengrassConfig**: This is where the IoT Greengrass Configuration File is stored. You can add customized configurations
  to this Bucket and they will be listed as options in the selection form if their extension is `.yaml`.
* **GreengrassArtifacts**: This Bucket is empty. It is where the deployable Greengrass artifacts should be stored. This
  Bucket is created at this time to be able to set read access for the Greengrass devices.
* **Downloads**: This is where the installations script is stored after being customised. It is then downloaded manually
  with a pre-signed URL provided to you in the process.

Bear in mind that CDK will customise the above Bucket names to make them unique. So you'll have to 
interpret what you read!

Logs are enabled by default for the Lambda functions. Log level can be set individually for each function using an
environment variable.

Amazon API Gateway logs have to be enabled manually to avoid the risk of modifying existing configurations. 
A role with a name starting with `GreengrassInstallerStack-CWRole` is created by the CDK for allowing API Gateway to 
log to CloudWatch. The instructions on how to enable logging can be found here: 
https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-cloudwatch-logs/

## Planned features

* Add possibility to deploy an application to Greengrass after installation.

## Limitations

* Only Linux devices are supported.

## More

If you're looking for a feature-rich and ready to use machine-to-cloud connectivity solution, you will be interested in 
this very nice AWS Solution: https://aws.amazon.com/solutions/implementations/machine-to-cloud-connectivity-framework/
