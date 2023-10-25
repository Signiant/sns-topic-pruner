# sns-topic-pruner

A tool that deletes all subscriber-less SNS topics not being used as CloudFormation stack resources in an AWS account
and posts a report to slack.

In addition to the base script, a CloudFormation template is included to facilitate the creation of a scheduled Lambda.

## Requirements

Alongside **Python 3.11+**, the following packages must be installed to run this tool:
- boto3
- requirements

Additionally, you need to have both AWS CLI & AWS SAM CLI installed and configured. The following guides provide 
detailed instructions on how to do so:
1. [Install or update the latest version of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
2. [Set up the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html)
3. [Installing the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)


## Setup

There are two ways to use this tool: through local execution or a scheduled lambda.

### Running the script locally

1. Clone this repository or download the most recent release.
2. Export a webhook to the desired Slack channel for the report as an environment variable called 
   **SLACK_WEBHOOK_URL**
3. In the same folder as the script, run the following command (with the addition of any arguments from the list below):  
   `$ python -m sns-topic-pruner -p [PROFILES ...]`

Command line argument reference:

|      Option      | Description                               |  Required  |        Default        |
|:----------------:|-------------------------------------------|:----------:|:---------------------:|
|  -p, --profiles  | A list of profiles to prune the topics of |    Yes     |          N/A          |
|  -o, --override  | A list of topics to ignore                |     No     |         None          |
|  -r, --regions   | A list of regions to prune through        |     No     |  All Enabled Regions  |
|  -v, --verbose   | Output more info in logs during execution |     No     |         False         |
|  -d, --dry-run   | Execute without making changes            |     No     |         False         |
|    -h, --help    | Show help message and exit                |     No     |          N/A          |


### Deploying the Lambda function

1. Clone this repository or download the most recent release.
2. In template.yaml, replace each commented line with relevant data. Refer to the **Lambda event variable** 
table below when filling out the **Input** property.
3. In sns_topic_pruner.py, replace the **EXTERNAL_ID** global variable string with the ExternalId specified in 
template.yaml.
4. In the same directory as the template file, create the build directory for the project using the following command:  
`$ sam build`
5. Deploy the development Lambda function and associated IAM role with the following command:  
`$ sam deploy --stack-name TEXT --s3-bucket TEXT --s3-prefix TEXT --region TEXT`  
OR  
Deploy the production Lambda function and associated IAM role, meaning it will run on a schedule, with the following 
command:  
`$ sam deploy --stack-name TEXT --s3-bucket TEXT --s3-prefix TEXT --region TEXT --parameter-overrides "EnvName="prod""`  
(Optional) *Create an AWS SAM CLI config file to skip entering these arguments every time you want to deploy. Learn about that 
[here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html).*


Lambda event variable reference:

|  Event Variable  | Description                                      |  Required  |        Default        |
|:----------------:|--------------------------------------------------|:----------:|:---------------------:|
| account_numbers  | A list of account numbers to prune the topics of |    Yes     |          N/A          |
|    overrides     | A list of topics to ignore                       |     No     |         None          |
|     regions      | A list of regions to prune through               |     No     |  All Enabled Regions  |
|     verbose      | Output more info in logs during execution        |     No     |         True          |
|     dry_run      | Execute without making changes                   |     No     |         True          |
