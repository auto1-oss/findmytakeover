import boto3
import botocore
import click


# get data from configured regions
class aws:
    def dns(accounts, iamrole):
        dnsdata = []
        for aws_account in accounts:
            click.echo("Reading DNS data from AWS Account - " + str(aws_account))
            if len(str(aws_account)) == 12:
                sts_client = boto3.client("sts")
                assume_role_object = sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{aws_account}:role/{iamrole}",
                    RoleSessionName="findmytakeover",
                )
                credentials = assume_role_object["Credentials"]

                client = boto3.client(
                    "route53",
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
                response = client.list_hosted_zones()["HostedZones"]

                for i in response:
                    # if i["Config"]["PrivateZone"] is False:
                    record = client.list_resource_record_sets(HostedZoneId=i["Id"])[
                        "ResourceRecordSets"
                    ]
                    for j in record:
                        if (
                            j["Type"] == "A"
                            or j["Type"] == "AAAA"
                            or j["Type"] == "CNAME"
                        ):
                            if j.get("ResourceRecords") is not None:
                                for k in j.get("ResourceRecords"):
                                    dnsdata.append(
                                        [
                                            aws_account,
                                            clean_dns(j["Name"]),
                                            clean_dns(k["Value"]),
                                        ]
                                    )

                            if j.get("AliasTarget") is not None:
                                dnsdata.append(
                                    [
                                        aws_account,
                                        clean_dns(j["Name"]),
                                        clean_dns(j.get("AliasTarget")["DNSName"]),
                                    ]
                                )
            else:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does seem to be invalid."
                )
        return dnsdata

    def infra(accounts, regions, iamrole):
        infradata = []
        for aws_account in accounts:
            click.echo(
                "Getting Infrastructure details from AWS Account - " + str(aws_account)
            )
            if len(str(aws_account)) == 12:
                sts_client = boto3.client("sts")
                assume_role_object = sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{aws_account}:role/{iamrole}",
                    RoleSessionName="findmytakeover",
                )
                credentials = assume_role_object["Credentials"]

                for r in regions:
                    try:
                        client = boto3.client(
                            "ec2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        paginator = client.get_paginator('describe_instances')

                        for page in paginator.paginate():
                        try:
                            for reservation in page.get("Reservations", []):
                                for instance in reservation.get("Instances", []):
                                    for network_interface in instance.get("NetworkInterfaces", []):
                                        association = network_interface.get("Association")
                                        if association:
                                            public_ip = association.get("PublicIp")
                                            public_dns_name = association.get("PublicDnsName")
                                            if public_ip:
                                                infradata.append([aws_account, "ec2-ip", public_ip])
                                            if public_dns_name:
                                                infradata.append([aws_account, "ec2-ip", public_dns_name])
                        except KeyError:
                            pass

                        elb_client = boto3.client(
                            "elb",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = elb_client.describe_load_balancers()
                        try:
                            for i in response["LoadBalancerDescriptions"]:
                                infradata.append(
                                    [aws_account, "elb", clean_dns(i["DNSName"])]
                                )
                        except KeyError:
                            pass

                        elbv2_client = boto3.client(
                            "elbv2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = elbv2_client.describe_load_balancers()
                        try:
                            for i in response["LoadBalancers"]:
                                infradata.append(
                                    [aws_account, "elbv2", clean_dns(i["DNSName"])]
                                )
                        except KeyError:
                            pass

                        beanstalk_client = boto3.client(
                            "elasticbeanstalk",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = beanstalk_client.describe_applications()
                        try:
                            for i in response["Applications"]:
                                result = beanstalk_client.describe_environments(
                                    ApplicationName=i["ApplicationName"]
                                )
                                for j in result["Environments"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "elasticbeanstalk",
                                            j["EndpointURL"],
                                        ]
                                    )
                                    infradata.append(
                                        [aws_account, "elasticbeanstalk", j["CNAME"]]
                                    )
                        except KeyError:
                            pass

                        client = boto3.client(
                            "s3",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = client.list_buckets()
                        try:
                            for i in response["Buckets"]:
                                infradata.append([aws_account, "s3", i["Name"]])
                        except KeyError:
                            pass

                        client = boto3.client(
                            "rds",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = client.describe_db_instances()
                        try:
                            for i in response["DBInstances"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "rds",
                                        clean_dns(i["Endpoint"]["Address"]),
                                    ]
                                )
                        except KeyError:
                            pass

                        response = client.describe_db_cluster_endpoints()
                        try:
                            for i in response["DBClusterEndpoints"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "rds",
                                        clean_dns(i["Endpoint"]),
                                    ]
                                )
                        except KeyError:
                            pass

                        # Collect VPC Endpoint Address
                        client = boto3.client(
                            "ec2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        response = client.describe_vpc_endpoints()
                        try:
                            for i in response["VpcEndpoints"]:
                                for dns in i["DnsEntries"]:
                                    infradata.append(
                                        [aws_account, "vpce", clean_dns(dns["DnsName"])]
                                    )
                        except KeyError:
                            pass

                        # Collect ACM DNS Validation Address
                        client = boto3.client(
                            "acm",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for cert in client.list_certificates()[
                                "CertificateSummaryList"
                            ]:
                                for dvo in client.describe_certificate(
                                    CertificateArn=cert["CertificateArn"]
                                )["Certificate"]["DomainValidationOptions"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "acm",
                                            clean_dns(dvo["ResourceRecord"]["Value"]),
                                        ]
                                    )
                        except KeyError:
                            pass

                        # Collect SES DKIM Validation Address
                        client = boto3.client(
                            "sesv2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for identity in client.list_email_identities()[
                                "EmailIdentities"
                            ]:
                                for token in client.get_email_identity(
                                    EmailIdentity=identity["IdentityName"]
                                )["DkimAttributes"]["Tokens"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "ses",
                                            "{0}.dkim.amazonses.com".format(token),
                                        ]
                                    )
                        except KeyError:
                            pass

                        # Collect api gateway Address
                        client = boto3.client(
                            "apigatewayv2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for domain_name in client.get_domain_names()["Items"]:
                                for dnc in domain_name["DomainNameConfigurations"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "apigw",
                                            dnc["ApiGatewayDomainName"],
                                        ]
                                    )
                        except KeyError:
                            pass

                        # Collect transfer family server Address
                        client = boto3.client(
                            "transfer",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for server in client.list_servers()["Servers"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "transfer",
                                        "{0}.server.transfer.{1}.amazonaws.com".format(
                                            server["ServerId"], r
                                        ),
                                    ]
                                )
                        except KeyError:
                            pass

                        # Collect redshift server Address
                        client = boto3.client(
                            "redshift",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for c in client.describe_clusters()["Clusters"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "redshift",
                                        c["Endpoint"]["Address"],
                                    ]
                                )
                        except KeyError:
                            pass

                        # Collect redshift serverless Address
                        client = boto3.client(
                            "redshift-serverless",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            for c in client.list_workgroups()["workgroups"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "redshift-serverless",
                                        c["endpoint"]["address"],
                                    ]
                                )
                        except KeyError:
                            pass

                        # Collect elasticache server Address
                        client = boto3.client(
                            "elasticache",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        try:
                            # redis replication groups
                            for c in client.describe_replication_groups()[
                                "ReplicationGroups"
                            ]:
                                for c in c["NodeGroups"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "ecache",
                                            c["PrimaryEndpoint"]["Address"],
                                            r,
                                        ]
                                    )
                                    infradata.append(
                                        [
                                            aws_account,
                                            "ecache",
                                            c["ReaderEndpoint"]["Address"],
                                            r,
                                        ]
                                    )
                                    for c in c["NodeGroupMembers"]:
                                        infradata.append(
                                            [
                                                aws_account,
                                                "ecache",
                                                c["ReadEndpoint"]["Address"],
                                                r,
                                            ]
                                        )

                            # memcache and single redis nodes
                            for c in client.describe_cache_clusters(
                                ShowCacheNodeInfo=True,
                                ShowCacheClustersNotInReplicationGroups=True,
                            )["CacheClusters"]:
                                if "ConfigurationEndpoint" in c:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "ecache",
                                            c["ConfigurationEndpoint"]["Address"],
                                            r,
                                        ]
                                    )
                                for c in c["CacheNodes"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "ecache",
                                            c["Endpoint"]["Address"],
                                            r,
                                        ]
                                    )
                        except KeyError:
                            pass

                        click.echo(
                            "Completed collecting Infrastructure details from the account - "
                            + str(aws_account)
                            + " in the region - "
                            + r
                        )

                    except botocore.exceptions.ClientError:
                        click.echo(
                            "Could not collect Infrastructure details from the account - "
                            + str(aws_account)
                            + " in the region - "
                            + r
                        )
                        continue

                # collect us-east-1 only CFDs and matching certs
                try:
                    client = boto3.client(
                        "cloudfront",
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                        region_name="us-east-1",
                    )
                    try:
                        paginator = client.get_paginator("list_distributions")
                        for page in paginator.paginate():
                            if (
                                "DistributionList" in page
                                and "Items" in page["DistributionList"]
                            ):
                                for i in page["DistributionList"]["Items"]:
                                    infradata.append(
                                        [
                                            aws_account,
                                            "cloudfront",
                                            clean_dns(i["DomainName"]),
                                        ]
                                    )
                    except KeyError:
                        pass
                    client = boto3.client(
                        "acm",
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                        region_name="us-east-1",
                    )
                    try:
                        for cert in client.list_certificates()[
                            "CertificateSummaryList"
                        ]:
                            for dvo in client.describe_certificate(
                                CertificateArn=cert["CertificateArn"]
                            )["Certificate"]["DomainValidationOptions"]:
                                infradata.append(
                                    [
                                        aws_account,
                                        "acm",
                                        clean_dns(dvo["ResourceRecord"]["Value"]),
                                    ]
                                )
                    except KeyError:
                        pass
                except botocore.exceptions.ClientError:
                    click.echo(
                        "Could not collect Infrastructure details from the account - "
                        + str(aws_account)
                        + " in the region - us-east-1"
                    )
                    continue
            else:
                print(
                    f"Please check the AWS Account number {str(aws_account)}. It does seem to be invalid."
                )
        return infradata


def clean_dns(dns):
    return dns.rstrip(".").removeprefix("https://").removeprefix("dualstack.")
