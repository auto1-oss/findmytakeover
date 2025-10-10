from azure.mgmt.dns import DnsManagementClient
from azure.identity import ClientSecretCredential
from azure.identity import CertificateCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.search import SearchManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.sql import SqlManagementClient
from tqdm import tqdm

# TODO - Change from ClientSecretCredential to CertificateCredential


class azure:
    def dns(account, cred):
        dnsdata = []
        credentials = ClientSecretCredential(
            cred["AZURE_TENANT_ID"],
            cred["AZURE_CLIENT_ID"],
            cred["AZURE_CLIENT_SECRET"],
        )
        total_accounts = len(account)

        with tqdm(
            total=total_accounts,
            desc="Processing Azure subscriptions",
            unit="subscription",
        ) as pbar:
            for account_idx, a in enumerate(account, 1):
                pbar.set_postfix_str(
                    f"Subscription {account_idx}/{total_accounts}: {a}"
                )
                resourcegroup_client = ResourceManagementClient(credentials, a)
                dns_client = DnsManagementClient(credentials, a)
                result = resourcegroup_client.resource_groups.list()
                for r in result:
                    zone = dns_client.zones.list_by_resource_group(
                        resource_group_name=r.name
                    )
                    for z in zone:
                        result = dns_client.record_sets.list_by_dns_zone(
                            resource_group_name=r.name, zone_name=z.name
                        )
                        for i in result:
                            if i.a_records != None:
                                for j in i.a_records:
                                    dnsdata.append([a, i.fqdn[:-1], j.ipv4_address])
                            elif i.aaaa_records != None:
                                for j in i.aaaa_records:
                                    dnsdata.append([a, i.fqdn[:-1], j.ipv6_address])
                            elif i.cname_record != None:
                                dnsdata.append([a, i.fqdn[:-1], i.cname_record.cname])
                            # TODO - Implement ALIAS Records
                            # elif i.target_resource.id != None:
                            #    dnsdata.append([a, i.fqdn[:-1], i.target_resource])
                            # Traffic Manager
                            # Public IP Address
                            # Azure CDN
                            # Front Door
                            # Static Web Page
                            else:
                                continue

                pbar.update(1)

        return dnsdata

    def infra(account, cred):
        infradata = []
        credentials = ClientSecretCredential(
            cred["AZURE_TENANT_ID"],
            cred["AZURE_CLIENT_ID"],
            cred["AZURE_CLIENT_SECRET"],
        )
        total_accounts = len(account)

        with tqdm(
            total=total_accounts,
            desc="Processing Azure subscriptions",
            unit="subscription",
        ) as pbar:
            for account_idx, a in enumerate(account, 1):
                pbar.set_postfix_str(
                    f"Subscription {account_idx}/{total_accounts}: {a}"
                )
                resourcegroup_client = ResourceManagementClient(credentials, a)
                ip_client = NetworkManagementClient(credentials, a)
                cdn_client = CdnManagementClient(credentials, a)
                tm_client = TrafficManagerManagementClient(credentials, a)
                web_client = WebSiteManagementClient(credentials, a)
                storage_client = StorageManagementClient(credentials, a)
                api_client = ApiManagementClient(credentials, a)
                database_client = SqlManagementClient(credentials, a)
                ecr_client = ContainerRegistryManagementClient(credentials, a)
                container_client = ContainerInstanceManagementClient(credentials, a)
                search_client = SearchManagementClient(credentials, a)
                redis_client = RedisManagementClient(credentials, a)

                result = resourcegroup_client.resource_groups.list()

                # Azure Functions (global)
                function = web_client.web_apps.list()
                for f in function:
                    infradata.append([a, "ipaddress", f.host_names[0]])

                # Process each resource group
                for rg in result:
                    cdn = cdn_client.profiles.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for c in cdn:
                        for u in cdn_client.endpoints.list_by_profile(
                            resource_group_name=rg.name, profile_name=c.name
                        ):
                            infradata.append([a, "ipaddress", str(u.host_name)])

                        for afd in cdn_client.afd_endpoints.list_by_profile(
                            resource_group_name=rg.name, profile_name=c.name
                        ):
                            infradata.append([a, "ipaddress", str(afd.host_name)])

                        for cd in cdn_client.afd_custom_domains.list_by_profile(
                            resource_group_name=rg.name, profile_name=c.name
                        ):
                            infradata.append([a, "ipaddress", str(cd.host_name)])

                    database = database_client.servers.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for d in database:
                        infradata.append(
                            [a, "ipaddress", d.fully_qualified_domain_name]
                        )

                    ip = ip_client.public_ip_addresses.list(resource_group_name=rg.name)
                    for ipaddr in ip:
                        infradata.append([a, "ipaddress", ipaddr.ip_address])

                    tm = tm_client.profiles.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for t in tm:
                        infradata.append([a, "ipaddress", str(t.dns_config.fqdn)])

                    storage = storage_client.storage_accounts.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for container in storage:
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.primary_endpoints.blob)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.primary_endpoints.queue)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.primary_endpoints.table)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.primary_endpoints.file)[8:-1],
                            ]
                        )
                        infradata.append(
                            [a, "ipaddress", str(container.primary_endpoints.web)[8:-1]]
                        )
                        infradata.append(
                            [a, "ipaddress", str(container.primary_endpoints.dfs)[8:-1]]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.blob)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.queue)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.table)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.file)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.web)[8:-1],
                            ]
                        )
                        infradata.append(
                            [
                                a,
                                "ipaddress",
                                str(container.secondary_endpoints.dfs)[8:-1],
                            ]
                        )

                    # Azure API Management
                    api = api_client.api_management_service.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for aa in api:
                        infradata.append([a, "ipaddress", str(aa.gateway_url[8:])])
                        infradata.append([a, "ipaddress", str(aa.public_ip_addresses)])

                    # Azure Container Registry
                    ecr = ecr_client.registries.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for e in ecr:
                        infradata.append([a, "ipaddress", str(e.login_server)])

                    # Azure Container Instances
                    container_groups = (
                        container_client.container_groups.list_by_resource_group(
                            resource_group_name=rg.name
                        )
                    )
                    for c in container_groups:
                        infradata.append([a, "ipaddress", str(c.ip_address.ip)])

                    # Azure Cognitive Search
                    search = search_client.services.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for s in search:
                        infradata.append(
                            [a, "ipaddress", str(s.name) + ".search.windows.net"]
                        )

                    # Azure Redis Cache
                    redis = redis_client.redis.list_by_resource_group(
                        resource_group_name=rg.name
                    )
                    for redis_cache in redis:
                        infradata.append([a, "ipaddress", str(redis_cache.host_name)])

                # Global resources (subscription-level, not per resource group)
                web_static = web_client.static_sites.list()
                for w in web_static:
                    infradata.append([a, "ipaddress", str(w.default_hostname)])

                pbar.update(1)

        return infradata
