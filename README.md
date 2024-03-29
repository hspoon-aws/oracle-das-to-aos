# Process RDS for Oracle Database Activity Stream (DAS) into Amazon OpenSearch (AOS) 2.x using Lambda 

`This is for demo and reference only, not production-ready`

This project contains source code and supporting files for a serverless application that you can deploy with the SAM CLI. It includes the following files and folders.

- rds_das_to_aos - Code for the application's Lambda function to put RDS for Oracle Database Activity Stream (DAS) into Amazon OpenSearch (AOS) 
- template.yaml - A template that defines the application's AWS resources.


## Overview

![Architecture](RDS-DAS-to-AOS.drawio.png)

1. RDS for Oracle enable Database Activity Stream to send Unified Audit Policy events into Kinesis Data Stream
2. Data in Kinesis Data stream are encrypted by KMS using customer-managed key
3. Kinesis Data stream triggers rds_das_to_aos Lambda function (100 item/batch by default)
4. Lambda function decrypt, decode, filter the data stream into Opensearch documents format
5. Lambda function call PUT index API to ingest events into Amazon Opensearch
6. Oracle database activity events can be indexed in Amazon Opensearch in near real-time for log analysis and monitoring

*PS: please make sure all components and actions are governed by IAM policy permission)*

Reference: 

- For the overview conceptual steps, please follow this workshop https://catalog.us-east-1.prod.workshops.aws/workshops/098605dc-8eee-4e84-85e9-c5c6c9e43de2/en-US/lab5-db-activity-stream (Although the workshop is talking about postgresql)


## Prerequisite and manual configuration

This SAM template is not a complete infrastructure of the project, but just Lambda part of the whole arcthiecture. It requires user to 

1. Setup RDS for Oracle with Database Activity Stream enabled [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/DBActivityStreams.html]
   - remember to enable audit policy e.g. https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html
   - run sql script which will do audit log in database activity stream
2. Setup Amazon OpenSearch cluster [https://docs.aws.amazon.com/opensearch-service/latest/developerguide/gsg.html]
   - remember to add lambda role with write index permission in the opensearch
3. Add Trigger event as Kinesis data stream in Lambda function after SAM deploy
   - make sure the lambda role is the KMS key user



## Development guide using SAM

The Lambda resource is defined in the `template.yaml` file in this project. You can update the template to add AWS resources through the same deployment process that updates your application code.

## Deploy the sample application

The Serverless Application Model Command Line Interface (SAM CLI) is an extension of the AWS CLI that adds functionality for building and testing Lambda applications. It uses Docker to run your functions in an Amazon Linux environment that matches Lambda. It can also emulate your application's build environment and API.

To use the SAM CLI, you need the following tools.

* SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* [Python 3 installed](https://www.python.org/downloads/)
* Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

To build and deploy your application for the first time, run the following in your shell:

```bash
sam build
sam deploy --guided
```

The first command will build the source of your application. The second command will package and deploy your application to AWS, with a series of prompts:

* **Stack Name**: The name of the stack to deploy to CloudFormation. This should be unique to your account and region, and a good starting point would be something matching your project name.
* **AWS Region**: The AWS region you want to deploy your app to.
* **Confirm changes before deploy**: If set to yes, any change sets will be shown to you before execution for manual review. If set to no, the AWS SAM CLI will automatically deploy application changes.
* **Allow SAM CLI IAM role creation**: Many AWS SAM templates, including this example, create AWS IAM roles required for the AWS Lambda function(s) included to access AWS services. By default, these are scoped down to minimum required permissions. To deploy an AWS CloudFormation stack which creates or modifies IAM roles, the `CAPABILITY_IAM` value for `capabilities` must be provided. If permission isn't provided through this prompt, to deploy this example you must explicitly pass `--capabilities CAPABILITY_IAM` to the `sam deploy` command.
* **Save arguments to samconfig.toml**: If set to yes, your choices will be saved to a configuration file inside the project, so that in the future you can just re-run `sam deploy` without parameters to deploy changes to your application.

You can find your API Gateway Endpoint URL in the output values displayed after deployment.

## Cleanup

To delete the sample application that you created, use the AWS CLI. Assuming you used your project name for the stack name, you can run the following:

```bash
aws cloudformation delete-stack --stack-name sam-kinesis-rds-das
```

## Resources

See the [AWS SAM developer guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html) for an introduction to SAM specification, the SAM CLI, and serverless application concepts.

Next, you can use AWS Serverless Application Repository to deploy ready to use Apps that go beyond hello world samples and learn how authors developed their applications: [AWS Serverless Application Repository main page](https://aws.amazon.com/serverless/serverlessrepo/)
