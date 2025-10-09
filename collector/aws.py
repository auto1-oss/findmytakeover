import boto3
import botocore
import click
import json


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

                paginator_zones = client.get_paginator("list_hosted_zones")

                # Use the paginator to iterate through all pages of hosted zones
                for page in paginator_zones.paginate():
                    hosted_zones = page.get("HostedZones", [])
                    for zone in hosted_zones:
                        hosted_zone_id = zone.get("Id")
                        if hosted_zone_id:
                            # Create a paginator for the list_resource_record_sets method
                            paginator_records = client.get_paginator(
                                "list_resource_record_sets"
                            )

                            # Use the paginator to iterate through all pages of resource record sets
                            for record_page in paginator_records.paginate(
                                HostedZoneId=hosted_zone_id
                            ):
                                record_sets = record_page.get("ResourceRecordSets", [])
                                for record in record_sets:
                                    # Check if the record is associated with a Traffic Policy
                                    if "TrafficPolicyInstanceId" in record:
                                        traffic_policy_instance_id = record[
                                            "TrafficPolicyInstanceId"
                                        ]
                                        aws.extract_endpoints_from_policy_instance(
                                            client,
                                            traffic_policy_instance_id,
                                            aws_account,
                                            record["Name"],
                                            dnsdata,
                                        )
                                    else:
                                        # Handle regular records of type A, AAAA, CNAME
                                        if record["Type"] in ["A", "AAAA", "CNAME"]:
                                            if (
                                                record.get("ResourceRecords")
                                                is not None
                                            ):
                                                for resource_record in record.get(
                                                    "ResourceRecords"
                                                ):
                                                    dnsdata.append(
                                                        [
                                                            aws_account,
                                                            clean_dns(record["Name"]),
                                                            clean_dns(
                                                                resource_record["Value"]
                                                            ),
                                                        ]
                                                    )

                                            if record.get("AliasTarget") is not None:
                                                dnsdata.append(
                                                    [
                                                        aws_account,
                                                        clean_dns(record["Name"]),
                                                        clean_dns(
                                                            record.get("AliasTarget")[
                                                                "DNSName"
                                                            ]
                                                        ),
                                                    ]
                                                )
            else:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does seem to be invalid."
                )
        return dnsdata

    def extract_endpoints_from_policy_instance(
        client, policy_instance_id, aws_account, record_name, dnsdata
    ):
        # Retrieve the traffic policy instance
        policy_instance = client.get_traffic_policy_instance(Id=policy_instance_id)
        policy_id = policy_instance.get("TrafficPolicyInstance").get("TrafficPolicyId")
        policy_version = policy_instance.get("TrafficPolicyInstance").get(
            "TrafficPolicyVersion"
        )

        # Retrieve the traffic policy
        policy_details = client.get_traffic_policy(Id=policy_id, Version=policy_version)
        policy_document = policy_details.get("TrafficPolicy", {}).get("Document")

        if policy_document:
            # Parse the JSON document
            policy_json = json.loads(policy_document)
            aws.extract_endpoints_from_policy(
                policy_json, aws_account, record_name, dnsdata
            )

    def extract_endpoints_from_policy(policy_json, aws_account, record_name, dnsdata):
        # Traverse the policy document to extract endpoint values
        for endpoint in policy_json.get("Endpoints", {}).values():
            value = endpoint.get("Value")
            if value:
                dnsdata.append([aws_account, clean_dns(record_name), clean_dns(value)])

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
                        paginator = client.get_paginator("describe_instances")

                        for page in paginator.paginate():
                            try:
                                for reservation in page.get("Reservations", []):
                                    for instance in reservation.get("Instances", []):
                                        for network_interface in instance.get(
                                            "NetworkInterfaces", []
                                        ):
                                            association = network_interface.get(
                                                "Association"
                                            )
                                            if association:
                                                public_ip = association.get("PublicIp")
                                                public_dns_name = association.get(
                                                    "PublicDnsName"
                                                )
                                                if public_ip:
                                                    infradata.append(
                                                        [
                                                            aws_account,
                                                            "ec2-ip",
                                                            public_ip,
                                                        ]
                                                    )
                                                if public_dns_name:
                                                    infradata.append(
                                                        [
                                                            aws_account,
                                                            "ec2-ip",
                                                            public_dns_name,
                                                        ]
                                                    )
                                            # Extract IPv6 addresses
                                            ipv6_addresses = network_interface.get(
                                                "Ipv6Addresses", []
                                            )
                                            for ipv6 in ipv6_addresses:
                                                ipv6_address = ipv6.get("Ipv6Address")
                                                if ipv6_address:
                                                    infradata.append(
                                                        [
                                                            aws_account,
                                                            "ec2-ipv6",
                                                            ipv6_address,
                                                        ]
                                                    )

                            except KeyError:
                                pass

                        client = boto3.client(
                            "elb",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        paginator = client.get_paginator("describe_load_balancers")

                        # Use the paginator to iterate through all pages of load balancers
                        for page in paginator.paginate():
                            try:
                                for load_balancer in page.get(
                                    "LoadBalancerDescriptions", []
                                ):
                                    dns_name = load_balancer.get("DNSName")
                                    if dns_name:
                                        infradata.append(
                                            [aws_account, "elb", clean_dns(dns_name)]
                                        )
                            except KeyError:
                                pass

                        client = boto3.client(
                            "elbv2",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        paginator = client.get_paginator("describe_load_balancers")

                        for page in paginator.paginate():
                            try:
                                for load_balancer in page.get("LoadBalancers", []):
                                    dns_name = load_balancer.get("DNSName")
                                    if dns_name:
                                        infradata.append(
                                            [aws_account, "elbv2", clean_dns(dns_name)]
                                        )
                            except KeyError:
                                pass

                        client = boto3.client(
                            "elasticbeanstalk",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        # not pageable
                        response = client.describe_applications()
                        try:
                            for i in response["Applications"]:
                                result = client.describe_environments(
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
                        paginator_instances = client.get_paginator(
                            "describe_db_instances"
                        )

                        for page in paginator_instances.paginate():
                            try:
                                for db_instance in page.get("DBInstances", []):
                                    endpoint_address = db_instance.get(
                                        "Endpoint", {}
                                    ).get("Address")
                                    if endpoint_address:
                                        infradata.append(
                                            [
                                                aws_account,
                                                "rds",
                                                clean_dns(endpoint_address),
                                            ]
                                        )
                            except KeyError:
                                pass

                        paginator_clusters = client.get_paginator(
                            "describe_db_cluster_endpoints"
                        )

                        for page in paginator_clusters.paginate():
                            try:
                                for db_cluster_endpoint in page.get(
                                    "DBClusterEndpoints", []
                                ):
                                    endpoint = db_cluster_endpoint.get("Endpoint")
                                    if endpoint:
                                        infradata.append(
                                            [aws_account, "rds", clean_dns(endpoint)]
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
                        paginator = client.get_paginator("describe_vpc_endpoints")

                        for page in paginator.paginate():
                            try:
                                for vpc_endpoint in page.get("VpcEndpoints", []):
                                    for dns_entry in vpc_endpoint.get("DnsEntries", []):
                                        dns_name = dns_entry.get("DnsName")
                                        if dns_name:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "vpce",
                                                    clean_dns(dns_name),
                                                ]
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
                        paginator = client.get_paginator("list_certificates")

                        for page in paginator.paginate():
                            try:
                                for cert in page.get("CertificateSummaryList", []):
                                    certificate_arn = cert.get("CertificateArn")
                                    if certificate_arn:
                                        # Describe the certificate to get domain validation options
                                        cert_details = client.describe_certificate(
                                            CertificateArn=certificate_arn
                                        )
                                        domain_validation_options = cert_details.get(
                                            "Certificate", {}
                                        ).get("DomainValidationOptions", [])
                                        for dvo in domain_validation_options:
                                            resource_record = dvo.get(
                                                "ResourceRecord", {}
                                            )
                                            dns_value = resource_record.get("Value")
                                            if dns_value:
                                                infradata.append(
                                                    [
                                                        aws_account,
                                                        "acm",
                                                        clean_dns(dns_value),
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

                            for identity in client.list_email_identities(PageSize=1000)[
                                "EmailIdentities"
                            ]:

                                identity_name = identity.get("IdentityName")
                                if identity_name:
                                    identity_details = client.get_email_identity(
                                        EmailIdentity=identity_name
                                    )
                                    dkim_tokens = identity_details.get(
                                        "DkimAttributes", {}
                                    ).get("Tokens", [])
                                    for token in dkim_tokens:
                                        infradata.append(
                                            [
                                                aws_account,
                                                "ses",
                                                f"{token}.dkim.amazonses.com",
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
                        paginator = client.get_paginator("get_domain_names")

                        for page in paginator.paginate():
                            try:
                                for domain_name in page.get("Items", []):
                                    for dnc in domain_name.get(
                                        "DomainNameConfigurations", []
                                    ):
                                        api_gateway_domain_name = dnc.get(
                                            "ApiGatewayDomainName"
                                        )
                                        if api_gateway_domain_name:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "apigw",
                                                    api_gateway_domain_name,
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
                        paginator = client.get_paginator("list_servers")

                        for page in paginator.paginate():
                            try:
                                for server in page.get("Servers", []):
                                    server_id = server.get("ServerId")
                                    if server_id:
                                        endpoint = f"{server_id}.server.transfer.{r}.amazonaws.com"
                                        infradata.append(
                                            [aws_account, "transfer", endpoint]
                                        )
                            except KeyError:
                                pass

                        # Collect sagemaker domains
                        client = boto3.client(
                            "sagemaker",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )
                        paginator = client.get_paginator("list_domains")

                        for page in paginator.paginate():
                            try:
                                for domain in page.get("Domains", []):
                                    url = domain.get("Url")
                                    if url:
                                        infradata.append(
                                            [aws_account, "sagemaker", url]
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
                        paginator = client.get_paginator("describe_clusters")

                        # Use the paginator to iterate through all pages of clusters
                        for page in paginator.paginate():
                            try:
                                for cluster in page.get("Clusters", []):
                                    endpoint_address = cluster.get("Endpoint", {}).get(
                                        "Address"
                                    )
                                    if endpoint_address:
                                        infradata.append(
                                            [aws_account, "redshift", endpoint_address]
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
                        paginator = client.get_paginator("list_workgroups")

                        for page in paginator.paginate():
                            try:
                                for workgroup in page.get("workgroups", []):
                                    endpoint_address = workgroup.get(
                                        "endpoint", {}
                                    ).get("address")
                                    if endpoint_address:
                                        infradata.append(
                                            [
                                                aws_account,
                                                "redshift-serverless",
                                                endpoint_address,
                                            ]
                                        )
                            except KeyError:
                                pass

                        # Collect elasticache Address
                        client = boto3.client(
                            "elasticache",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"],
                            region_name=r,
                        )

                        paginator_replication = client.get_paginator(
                            "describe_replication_groups"
                        )

                        for page in paginator_replication.paginate():
                            try:
                                for replication_group in page.get(
                                    "ReplicationGroups", []
                                ):
                                    for node_group in replication_group.get(
                                        "NodeGroups", []
                                    ):
                                        primary_endpoint = node_group.get(
                                            "PrimaryEndpoint", {}
                                        ).get("Address")
                                        reader_endpoint = node_group.get(
                                            "ReaderEndpoint", {}
                                        ).get("Address")

                                        if primary_endpoint:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "ecache",
                                                    primary_endpoint,
                                                    r,
                                                ]
                                            )
                                        if reader_endpoint:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "ecache",
                                                    reader_endpoint,
                                                    r,
                                                ]
                                            )

                                        for node_group_member in node_group.get(
                                            "NodeGroupMembers", []
                                        ):
                                            read_endpoint = node_group_member.get(
                                                "ReadEndpoint", {}
                                            ).get("Address")
                                            if read_endpoint:
                                                infradata.append(
                                                    [
                                                        aws_account,
                                                        "ecache",
                                                        read_endpoint,
                                                        r,
                                                    ]
                                                )
                            except KeyError:
                                pass

                        paginator_clusters = client.get_paginator(
                            "describe_cache_clusters"
                        )

                        for page in paginator_clusters.paginate(
                            ShowCacheNodeInfo=True,
                            ShowCacheClustersNotInReplicationGroups=True,
                        ):
                            try:
                                for cache_cluster in page.get("CacheClusters", []):
                                    configuration_endpoint = cache_cluster.get(
                                        "ConfigurationEndpoint", {}
                                    ).get("Address")

                                    if configuration_endpoint:
                                        infradata.append(
                                            [
                                                aws_account,
                                                "ecache",
                                                configuration_endpoint,
                                                r,
                                            ]
                                        )

                                    for cache_node in cache_cluster.get(
                                        "CacheNodes", []
                                    ):
                                        endpoint = cache_node.get("Endpoint", {}).get(
                                            "Address"
                                        )
                                        if endpoint:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "ecache",
                                                    endpoint,
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
                    paginator = client.get_paginator("list_certificates")

                    for page in paginator.paginate():
                        try:
                            for cert in page.get("CertificateSummaryList", []):
                                certificate_arn = cert.get("CertificateArn")
                                if certificate_arn:
                                    # Describe the certificate to get domain validation options
                                    cert_details = client.describe_certificate(
                                        CertificateArn=certificate_arn
                                    )
                                    domain_validation_options = cert_details.get(
                                        "Certificate", {}
                                    ).get("DomainValidationOptions", [])
                                    for dvo in domain_validation_options:
                                        resource_record = dvo.get(
                                            "ResourceRecord", {}
                                        )
                                        dns_value = resource_record.get("Value")
                                        if dns_value:
                                            infradata.append(
                                                [
                                                    aws_account,
                                                    "acm",
                                                    clean_dns(dns_value),
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
