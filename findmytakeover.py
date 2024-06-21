#!/usr/bin/env python3

import argparse
import yaml
import click
import os
import pandas as pd
import ipaddress


def readConfig(data):
    dnsprovider = {}
    infraprovider = {}
    exclude_cidrs = []
    exclude_domains = []

    # Loading the YAML configuration
    cf = open(data, "rt")
    try:
        config = yaml.safe_load(cf)
    except yaml.YAMLError:
        print("Invalid YAML file!")
        exit(1)

    # Reading the configuration file for runtime configuration
    try:
        if "exclude" in config.keys():
            if "ipaddress" in config["exclude"].keys():
                for ipadd in config["exclude"]["ipaddress"]:
                    exclude_cidrs.append(ipaddress.ip_network(ipadd))

            if "domains" in config["exclude"].keys():
                for domains in config["exclude"]["domains"]:
                    exclude_domains.append(str(domains))

    except KeyError:
        click.echo(
            "Invalid Configuration! please check the findmytakeover section in configuration file."
        )
        exit(1)

    # Reading the configuration file for DNS providers
    try:
        if "dns" in config.keys():
            for i in config["dns"]:
                if config["dns"][i]["enabled"] == True:
                    dnsprovider[i] = {
                        "credentials": config["dns"][i]["credentials"],
                        "accounts": config["dns"][i]["accounts"],
                    }
                    if None in dnsprovider[i].values():
                        raise KeyError
        else:
            click.echo(
                "Invalid Configuration! please check that DNS provider is configured."
            )

        if dnsprovider == {}:
            click.echo(
                "Invalid Configuration! please check atleast one DNS provider needs to be enabled."
            )

        if None in dnsprovider.values():
            raise KeyError

    except KeyError:
        click.echo(
            "Invalid Configuration! please check the DNS section in configuration file."
        )
        exit(1)

    # Reading the configuration file for Infrastructure
    try:
        if "infra" in config.keys():
            for i in config["infra"]:
                if config["infra"][i]["enabled"] == True:
                    infraprovider[i] = {
                        "credentials": config["infra"][i]["credentials"],
                        "regions": config["infra"][i]["regions"],
                        "accounts": config["infra"][i]["accounts"],
                    }
                    if None in infraprovider[i].values():
                        raise KeyError
        else:
            click.echo(
                "Invalid Configuration! please check that Infrastructure provider is configured."
            )

        if infraprovider == {}:
            click.echo(
                "Invalid Configuration! please check atleast one Infrastructure provider needs to be enabled."
            )

        if None in infraprovider.values():
            raise KeyError

    except KeyError:
        click.echo(
            "Invalid Configuration! please check the Infrastructure section in configuration file."
        )
        exit(1)

    return dnsprovider, infraprovider, exclude_cidrs, exclude_domains


def main():
    CLI_PROMPT = r"""        
        __ _           _                 _        _                            
        / _(_)         | |               | |      | |                           
        | |_ _ _ __   __| |_ __ ___  _   _| |_ __ _| | _____  _____   _____ _ __ 
        |  _| | '_ \ / _` | '_ ` _ \| | | | __/ _` | |/ / _ \/ _ \ \ / / _ \ '__|
        | | | | | | | (_| | | | | | | |_| | || (_| |   <  __/ (_) \ V /  __/ |   
        |_| |_|_| |_|\__,_|_| |_| |_|\__, |\__\__,_|_|\_\___|\___/ \_/ \___|_|   
                                    __/ |                                      
                                    |___/                                       
        """

    click.secho(CLI_PROMPT, bold=True, fg="green")

    # Read the arguments that have been passed in to the program.
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c",
        "--config-file",
        default=os.getcwd() + "/findmytakeover.config",
        type=str,
        help="Enter the path to the configuration file that you want the tool to use.",
    )

    parser.add_argument(
        "-d",
        "--dump-file",
        type=str,
        help="Enter the path to where all the DNS and Infrastructre data would be saved.",
    )

    args = parser.parse_args()

    click.echo("Reading the config from file - " + args.config_file)
    dns, infra, exclude_cidrs, exclude_domains = readConfig(args.config_file)

    # print(dns, infra, exclude)

    recordlist = []
    infrastructurelist = []

    # parse the provider and invoke appropriate collector
    for d in dns:
        if d == "aws":
            from collector.aws import aws

            awsdns = aws.dns(dns["aws"]["accounts"], dns["aws"]["credentials"])
            for f in awsdns:
                recordlist.append(["Amazon Web Services", f[0], f[1], f[2]])

        elif d == "gcp":
            from collector.gcp import gcp

            gcpdns = gcp.dns(dns["gcp"]["accounts"], dns["gcp"]["credentials"])
            for f in gcpdns:
                recordlist.append(["Google Cloud Platform", f[0], f[1], f[2]])

        elif d == "azure":
            from collector.msazure import azure

            azuredns = azure.dns(dns["azure"]["accounts"], dns["azure"]["credentials"])
            for f in azuredns:
                recordlist.append(["Microsoft Azure", f[0], f[1], f[2]])
        else:
            print(
                "The DNS provider configured"
                + d
                + "is not supported by the tool. Please read the documentation."
            )

    records = pd.DataFrame(recordlist, columns=["csp", "account", "dnskey", "dnsvalue"])

    for i in infra:
        if i == "aws":
            from collector.aws import aws

            awsinfra = aws.infra(
                infra["aws"]["accounts"],
                infra["aws"]["regions"],
                infra["aws"]["credentials"],
            )
            for f in awsinfra:
                infrastructurelist.append(["Amazon Web Services", f[0], f[1], f[2]])

        elif i == "gcp":
            from collector.gcp import gcp

            gcpinfra = gcp.infra(infra["gcp"]["accounts"], infra["gcp"]["credentials"])
            for f in gcpinfra:
                infrastructurelist.append(["Google Cloud Platform", f[0], f[1], f[2]])

        elif i == "azure":
            from collector.msazure import azure

            azureinfra = azure.infra(
                dns["azure"]["accounts"], dns["azure"]["credentials"]
            )
            for f in azureinfra:
                infrastructurelist.append(["Microsoft Azure", f[0], f[1], f[2]])
        else:
            print(
                "The Infrastructure provider configured"
                + d
                + "is not supported by the tool. Please read the documentation."
            )

    infrastructure = pd.DataFrame(
        infrastructurelist, columns=["csp", "account", "service", "value"]
    )

    # Dumping data
    if args.dump_file:
        print("Dumping data at file at - " + args.dump_file)
        infrastructure.to_csv(args.dump_file, mode="a")
        with open(args.dump_file, "a") as f:
            f.write("--" * 50)
        records.to_csv(args.dump_file, mode="a")

    click.echo("Checking for possible dangling DNS records...")
    if dns != {} or infra != {}:
        # filter out the records which internally forward to different dns record or where forwarded record would get matched by wildcard
        for dnskey in records["dnskey"]:
            forward_mask = records["dnsvalue"].str.fullmatch(
                dnskey.replace(".", "\\.").replace("\\052", ".*")
            )
            records = records[~forward_mask]

        # merge remaining records with extracted current infrastructure
        result = pd.merge(
            records,
            infrastructure,
            left_on="dnsvalue",
            right_on="value",
            how="left",
        ).fillna(value="")

        click.echo("Reducing records to dangling ones...")
        dangling_mask = result["value"].apply(lambda x: x != "")
        result = result[~dangling_mask]

        # Checking for exclusions in the results
        click.echo("Removing excluded IPs and domains...")
        for exclude in exclude_domains:
            domain_mask = result["dnsvalue"].str.contains(exclude)
            result = result[~domain_mask]

        ip_mask = result["dnsvalue"].apply(
            lambda x: is_ip_in_cidr_ranges(x, exclude_cidrs)
        )
        result = result[~ip_mask]

        click.echo("Printing danglind DNS records:")
        for i in result.index:
            if result["value"][i] == "":
                click.echo(
                    "Found dangling DNS record - "
                    + str(result["dnskey"][i])
                    + " with the value "
                    + str(result["dnsvalue"][i])
                    + " in "
                    + str(result["csp_x"][i])
                    + " cloud in the account/subscription/project - "
                    + str(result["account_x"][i])
                )
    else:
        print(
            "To check for dangling domains, both DNS and Infrastructure provider needs to be configured."
        )


def is_ip_in_cidr_ranges(ip, cidr_ranges):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidr_ranges:
            if ip_obj in cidr:
                return True
    except ValueError:
        # If ip is not a valid IP address, return False
        return False
    return False


if __name__ == "__main__":
    main()
