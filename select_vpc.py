#!/usr/bin/env python3
"""Helper script to select an existing VPC and find available CIDR for SHCA deployment."""

import boto3
import ipaddress
import json


def get_vpcs():
    """Get all VPCs in the region."""
    ec2 = boto3.client("ec2")
    response = ec2.describe_vpcs()
    vpcs = []
    for vpc in response["Vpcs"]:
        name = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), "-")
        vpcs.append({"id": vpc["VpcId"], "cidr": vpc["CidrBlock"], "name": name})
    return vpcs


def get_subnets(vpc_id):
    """Get all subnets in a VPC."""
    ec2 = boto3.client("ec2")
    response = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    return [s["CidrBlock"] for s in response["Subnets"]]


def find_available_cidr(vpc_cidr, existing_subnets, prefix=24):
    """Find an available CIDR block within the VPC range."""
    vpc_net = ipaddress.ip_network(vpc_cidr)
    existing = [ipaddress.ip_network(s) for s in existing_subnets]
    
    for candidate in vpc_net.subnets(new_prefix=prefix):
        if not any(candidate.overlaps(e) for e in existing):
            return str(candidate)
    return None


def main():
    vpcs = get_vpcs()
    if not vpcs:
        print("No VPCs found.")
        return

    print("\nAvailable VPCs:")
    print("-" * 60)
    for i, vpc in enumerate(vpcs, 1):
        print(f"  {i}. {vpc['id']}  {vpc['cidr']:18} {vpc['name']}")
    print("-" * 60)

    choice = input("\nSelect VPC [1-{}] (or 'q' to quit): ".format(len(vpcs)))
    if choice.lower() == 'q':
        return
    
    try:
        vpc = vpcs[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    subnets = get_subnets(vpc["id"])
    print(f"\nExisting subnets in {vpc['id']}:")
    if subnets:
        for s in sorted(subnets):
            print(f"  - {s}")
    else:
        print("  (none)")

    suggested = find_available_cidr(vpc["cidr"], subnets, prefix=24)
    if not suggested:
        print("\nNo available /26 CIDR found. Try a smaller block or different VPC.")
        return

    print(f"\nSuggested CIDR for SHCA: {suggested}")
    print("\n" + "=" * 60)
    print("Add to cdk.json:")
    print(f'    "existing_vpc_id": "{vpc["id"]}",')
    print(f'    "vpc_cidr": "{suggested}",')
    print("=" * 60)


if __name__ == "__main__":
    main()
