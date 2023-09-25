import argparse
import boto3
from botocore.exceptions import ClientError, ProfileNotFound
import json
import logging
import os
import re
import requests
import sys

logging.basicConfig(format="%(asctime)s - %(levelname)8s: %(message)s", stream=sys.stdout)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)


def post_to_slack(blocks):
    """
    Post summary blocks to slack

    :param blocks: the summary blocks to be posted
    """
    try:
        slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        if not slack_webhook_url:
            logging.error("SLACK_WEBHOOK_URL environment variable is required for Slack notifications.")
            sys.exit(1)
        payload = {"blocks": blocks}
        headers = {"Content-Type": "application/json"}
        response = requests.post(slack_webhook_url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.exception(f"Error posting to Slack: {e}")


def post_summary_blocks_to_slack(summary_blocks, max_blocks_per_message=10):
    """
    Post a series of summary blocks to slack

    :param summary_blocks: the summary blocks to be posted
    :param max_blocks_per_message: the maximum number of blocks per message
    """
    logging.info("Posting report to slack")

    # Split the summary blocks into smaller chunks(Slack is truncating the payload if we send entire summary)
    for i in range(0, len(summary_blocks), max_blocks_per_message):
        chunked_summary_blocks = summary_blocks[i:i + max_blocks_per_message]
        post_to_slack(chunked_summary_blocks)


def construct_topics_summary_block(header, topics):
    """
    Create a summary block containing a list of topics with a defined header

    :param header: the title of this block
    :param topics: the topics to be listed
    :return: a summary block containing a header and a number of topics
    """
    text = header

    for topic in topics:
        if type(topic) is dict:
            name = topic["Topic"].arn.split(":")[5]
            text += name + "\n"
            for tag in topic["Tags"]:
                text += "- _" + tag["Key"] + ": " + tag["Value"] + "_\n"
        else:
            name = topic.arn.split(":")[5]
            text += name + "\n"

    summary_block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"{text}"
        }
    }

    return summary_block


def generate_report(summaries, dry_run=False):
    """
    Create a report detailing the pruning results

    :param summaries: the topic pruning results of each account/profile
    :param dry_run: a flag that dictates if the script is to delete topics
    :return: a report of all accounts/profiles that have been pruned
    """
    logging.info("Generating report")

    summary_blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "SNS Topic Pruning Report"
            }
        },
        {
            "type": "divider"
        }
    ]

    totals = []

    # Build summary blocks for each account
    for summary in summaries:
        account_totals = {
            "Account": summary["AccountName"],
            "Regions": len(summary["RegionSummaries"]),
            "Topics": {
                "Deleted": 0,
                "Tagged": 0,
                "Overridden": 0
            }
        }

        summary_blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Account: *" + account_totals["Account"] + "*"
                }
            }
        )

        summary_blocks.append(
            {
                "type": "divider"
            }
        )

        # Build summary blocks for each region
        for region_summary in summary["RegionSummaries"]:
            if "Deleted" not in region_summary["Topics"]:
                continue

            region = region_summary["Region"]

            summary_blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{region}*"
                    }
                }
            )

            # Construct deleted topics summary block
            if len(region_summary["Topics"]["Deleted"]) != 0:
                text = "Deleted topics:\n"

                if dry_run:
                    text = "Topics eligible for deletion:\n"

                account_totals["Topics"]["Deleted"] += len(region_summary["Topics"]["Deleted"])
                summary_blocks.append(construct_topics_summary_block(text, region_summary["Topics"]["Deleted"]))

            # Construct tagged topics summary block
            if len(region_summary["Topics"]["Tagged"]) != 0:
                text = "Tagged topics eligible for deletion:\n"
                account_totals["Topics"]["Tagged"] += len(region_summary["Topics"]["Tagged"])
                summary_blocks.append(construct_topics_summary_block(text, region_summary["Topics"]["Tagged"]))

            # Construct overridden topics summary block
            if len(region_summary["Topics"]["Overridden"]) != 0:
                text = "Overridden topics:\n"
                account_totals["Topics"]["Overridden"] += len(region_summary["Topics"]["Overridden"])
                summary_blocks.append(construct_topics_summary_block(text, region_summary["Topics"]["Overridden"]))

            summary_blocks.append(
                {
                    "type": "divider"
                }
            )
        totals.append(account_totals)
    summary_blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Summary"
            }
        }
    )

    text = ""

    # Build end of report summary block text for each account
    for account_total in totals:
        account_name = account_total["Account"]
        deleted = account_total["Topics"]["Deleted"]
        tagged = account_total["Topics"]["Tagged"]
        overridden = account_total["Topics"]["Overridden"]
        regions = account_total["Regions"]

        account_summary = (
            f"*{account_name}*:\n"
            f"- *{deleted} topics* deleted\n"
            f"- *{tagged} topics* tagged\n"
            f"- *{overridden} topics* overridden\n"
            f"across *{regions} regions*.\n\n"
        )
        if dry_run:
            account_summary = (
                f"*{account_name}*:\n"
                f"- *{deleted} topics* eligible for deletion\n"
                f"- *{tagged} topics* tagged\n"
                f"- *{overridden} topics* overridden\n"
                f"across *{regions} regions*.\n\n"
            )
        text += account_summary
    summary_blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text
            }
        }
    )

    return summary_blocks


def match_override(topic, override):
    """
    Search for a topic in the override list

    :param topic: A topic to search for in the list of override patterns
    :param override: A list of patterns to ignore
    :return: a boolean dictating if a topic should be ignored
    """
    for pattern in override:
        pattern = re.compile(pattern)
        if pattern.search(topic.arn) is not None:
            return True

    return False


def output_topics_to_log(header, topics):
    """
    Output a list of topics in the log

    :param header: a header for this section of the log output
    :param topics: the topics to be listed
    """
    if len(topics) != 0:
        logging.debug(header)
        for topic in topics:
            if type(topic) is dict:
                logging.debug(topic["Topic"].arn)
            else:
                logging.debug(topic.arn)


def delete_topics(client, topics, region, override=None, dry_run=False):
    """
    Delete a series of topics

    :param client: the SNS client the topics belong to
    :param topics: the list of topics to be deleted
    :param region: the region the topics are being deleted in
    :param override: A list of topics to ignore
    :param dry_run: a boolean that dictates if the script is to delete topics
    :return: A dictionary of all deleted, tagged, and overridden topics
    """
    if dry_run:
        logging.info("**Topics eligible for deletion in " + region + "**")
    else:
        logging.debug("**Deleting topics**")
    overridden_topics = []
    deleted_topics = []
    tagged_topics = []

    for topic in topics:
        if match_override(topic, override):
            overridden_topics.append(topic)
            continue

        tags = client.list_tags_for_resource(ResourceArn=topic.arn)["Tags"]
        if len(tags) != 0:
            tagged_topics.append({"Topic": topic, "Tags": tags})
            continue

        deleted_topics.append(topic)

        if not dry_run:
            # Delete topic
            topic.delete()
            logging.debug("DELETED - " + topic.arn)
        else:
            logging.info(topic.arn)
    if len(deleted_topics) == 0:
        if dry_run:
            logging.info("No eligible topics.")
        else:
            logging.debug("No deleted topics.")

    output_topics_to_log("**Tagged topics eligible for deletion**", tagged_topics)
    output_topics_to_log("**Overridden topics**", overridden_topics)

    return {"Deleted": deleted_topics, "Overridden": overridden_topics, "Tagged": tagged_topics}


def get_unused_topics(cloudformation, topics):
    """
    Get all topics currently not being used in CloudFormation stacks

    :param cloudformation: a CloudFormation client
    :param topics: a list of topics that have no subscribers
    :return: a list of topics not being used as resources in CloudFormation stacks
    """
    logging.debug("**Checking stack usage**")
    unused_topics = []

    for topic in topics:
        try:
            # Check if a CloudFormation stack utilizes the topic
            stack_resources = cloudformation.describe_stack_resources(PhysicalResourceId=topic.arn)["StackResources"]
            stack_name = stack_resources[0]['StackName']
            logging.debug("    IN STACK - " + topic.arn + " (Stack: " + stack_name + ")")
        except ClientError as e:
            # Store topic in list if not associated with a stack
            if e.response["Error"]["Message"] == f"Stack for {topic.arn} does not exist":
                unused_topics.append(topic)
                logging.debug("NOT IN STACK - " + topic.arn)
            else:
                logging.error(e)

    return unused_topics


def get_no_subscriber_topics(sns):
    """
    Get all SNS topics that currently have no subscribers

    :param sns: an SNS resource
    :return: a list of topics that have no subscribers
    """
    logging.debug("**Checking subscriptions**")
    topics = []

    try:
        for topic in sns.topics.all():
            has_subscribers = False

            # Check if topic has subscribers
            for _ in topic.subscriptions.all():
                has_subscribers = True
                break

            # Ignore topics that have subscribers
            if has_subscribers:
                logging.debug("HAS SUBSCRIBERS - " + topic.arn)
                continue

            logging.debug(" NO SUBSCRIBERS - " + topic.arn)
            topics.append(topic)
    except ClientError as e:
        logging.error(e)
        topics = None

    return topics


def get_resource(session, service, region, credentials=None):
    """
    Get a boto3 service resource

    :param session: a boto3 session
    :param service: the service to create a resource instance of
    :param region: the region the service resource is associated with
    :param credentials: the assumed role credentials to be used
    :return: a service resource
    """
    if credentials is not None:
        return session.resource(
            service,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region
        )
    else:
        return session.resource(service, region_name=region)


def get_client(session, service, region, credentials=None):
    """
        Get a boto3 service client

        :param session: a boto3 session
        :param service: the service to create a client instance of
        :param region: the region the service client is associated with
        :param credentials: assumed role credentials
        :return: a service client
        """
    if credentials is not None:
        return session.client(
            service,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region
        )
    else:
        return session.client(service, region_name=region)


def prune_region_topics(session, region, override, dry_run, credentials=None):
    """
    Prune the account/profile topics of a region

    :param session: a boto3 session
    :param region: the region to prune topics in
    :param override: a list of topics to ignore during deletion
    :param dry_run: a flag that dictates if the script is to delete topics
    :param credentials: assumed role credentials
    :return: a dict detailing the result of pruning topics in this region
    """
    region_summary = {"Region": region, "Topics": {}}
    logging.debug("Beginning topic pruning in region: " + region)

    sns_resource = get_resource(session, "sns", region, credentials)
    topics = get_no_subscriber_topics(sns_resource)

    if topics is None:
        logging.debug("Skipping " + region + "...")
        return region_summary

    if len(topics) != 0:
        cloudformation = get_client(session, "cloudformation", region, credentials)
        unused_topics = get_unused_topics(cloudformation, topics)

        sns_client = get_client(session, "sns", region, credentials)

        # Report all topics that would be deleted if dry-run mode is enabled
        # Otherwise, delete topics
        region_summary["Topics"] = delete_topics(sns_client, unused_topics, region, override, dry_run)
        if not dry_run:
            logging.info(region + " - Topics deleted")
    else:
        logging.debug(region + " - No topics without subscribers")
    return region_summary


def get_enabled_regions(session, regions=None):
    """
    Get all regions that are currently enabled on an account

    Retrieves all enabled regions on an account or checks if
    all user defined regions are valid.

    :param session: a boto3 session
    :param regions: a list of user defined regions
    :return: all enabled/valid regions in an account
    """
    # Get the data of all regions enabled on an account
    account = session.client('account')
    regions_data = account.list_regions(RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'])["Regions"]
    region_names = []

    # Extract region names
    for region in regions_data:
        region_names.append(region["RegionName"])

    valid_regions = []

    if regions is not None:
        for region in regions:
            if region not in region_names:
                logging.error("Invalid region: " + region + ". Region either disabled or does not exist.")
            else:
                valid_regions.append(region)
    else:
        valid_regions = region_names

    return valid_regions


def prune_profile_topics(profile, override=None, regions=None, dry_run=False):
    """
    Prune all topics under a specific profile

    :param profile: an AWS profile
    :param override: A list of topics to ignore during deletion
    :param regions: A list of user defined regions to prune topics in
    :param dry_run: a flag that dictates if the script is to delete topics
    :return: the result of pruning topics in all valid regions of a profile
    """
    profile_summary = {"AccountName": profile, "RegionSummaries": []}

    try:
        session = boto3.Session(profile_name=profile)
    except ProfileNotFound:
        logging.error("Profile " + profile + " not found. Skipping...")
        return None

    regions = get_enabled_regions(session, regions)

    # Prune the topics of each region in a profile
    for region in regions:
        region_summary = prune_region_topics(session, region, override, dry_run)
        profile_summary["RegionSummaries"].append(region_summary)

    return profile_summary


def prune_account_topics(account_number, override=None, regions=None, dry_run=False):
    """
    Prune all topics under a specific profile

    :param account_number: a list of AWS account numbers
    :param override: A list of topics to ignore during deletion
    :param regions: A list of user defined regions to prune topics in
    :param dry_run: a flag that dictates if the script is to delete topics
    :return: the result of pruning topics in all valid regions of an account
    """
    try:
        assumed_role = boto3.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{account_number}:role/SNSTopicPrunerRole",
            RoleSessionName="Topic-Pruner",
            ExternalId="UNIQUE-ID"  # the unique id required to assume the topic pruner role
        )
    except ClientError as e:
        logging.error(e)
        return None

    credentials = assumed_role["Credentials"]

    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    iam = get_client(session, "iam", None, credentials)
    account_name = iam.list_account_aliases()["AccountAliases"][0]
    account_summary = {"AccountName": account_name, "AccountNumber": account_number, "RegionSummaries": []}

    regions = get_enabled_regions(session, regions)

    # Prune the topics of each region on an account
    for region in regions:
        region_summary = prune_region_topics(session, region, override, dry_run, credentials)
        account_summary["RegionSummaries"].append(region_summary)

    return account_summary


def start(account_numbers=None, profiles=None, override=None, regions=None, verbose=False, dry_run=False):
    """
    Initiate the pruning process

    :param account_numbers: a list of AWS account numbers
    :param profiles: a list of AWS profiles
    :param override: a list of topics to ignore during deletion
    :param regions: a list of regions to prune topics in
    :param verbose: a flag that changes the volume of logging messages
    :param dry_run: a flag that determines if topics are to be deleted
    """
    if account_numbers is not None and profiles is not None:
        logging.error("Cannot pass both account numbers and profiles to main.")
        sys.exit(1)

    # Configure root logger level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if override is None:
        override = ()

    summaries = []

    # Prune profile topics sequentially
    if profiles is not None:
        for profile in profiles:
            logging.info("Pruning topics under profile: " + profile)
            summary = prune_profile_topics(profile, override, regions, dry_run)

            if summary is None:
                continue

            summaries.append(summary)
    elif account_numbers is not None:
        for account_number in account_numbers:
            logging.info("Pruning topics under account: " + account_number)
            summary = prune_account_topics(account_number, override, regions, dry_run)

            if summary is None:
                continue

            summaries.append(summary)

    summary_blocks = generate_report(summaries, dry_run)
    post_summary_blocks_to_slack(summary_blocks)


def lambda_handler(event, context):
    """
    A function that handles events received by a Lambda

    :param event: data to be processed
    :param context: lambda invocation, function, and runtime environment info
    """
    if "account_numbers" not in event:
        logging.error("Account number not found in event.")
        sys.exit(1)

    start(account_numbers=event.get("account_numbers"),
          override=event.get("override"),
          regions=event.get("regions"),
          verbose=event.get("verbose", True),
          dry_run=event.get("dry_run", True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SNS Topic pruning script")

    parser.add_argument(
        "-v", "--verbose",
        help="Cause script to be verbose, outputting more info in the logs.",
        dest="verbose",
        action='store_true'
    )
    parser.add_argument(
        "-d", "--dry-run",
        help="Execute without making changes.",
        dest="dry_run",
        action='store_true'
    )
    parser.add_argument(
        "-o", "--override",
        help="A list of topics to ignore.",
        dest="override",
        nargs="+"
    )
    parser.add_argument(
        "-r", "--regions",
        help="A list of regions to check. Checks all enabled regions by default.",
        dest="regions",
        nargs="+"
    )
    parser.add_argument(
        "-p", "--profiles",
        help="A list of profiles to prune the topics of",
        dest="profiles",
        nargs="+",
        required=True
    )

    args = parser.parse_args()
    start(profiles=args.profiles,
          override=args.override,
          regions=args.regions,
          verbose=args.verbose,
          dry_run=args.dry_run)
