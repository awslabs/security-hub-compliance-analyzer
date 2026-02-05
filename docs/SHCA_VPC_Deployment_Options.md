# SHCA VPC Deployment Options

## Problem Statement

Security Hub Compliance Analyzer (SHCA) requires a VPC with **Private Isolated subnets** for Lambda function deployment. When deploying into accounts that have reached their VPC limit, or where network architecture standards require using existing VPCs, the current "create new VPC" approach fails.

## Current State

SHCA Lambda functions require:
- Private Isolated subnets (no internet access)
- VPC endpoints for S3 and Security Hub
- Security groups for Lambda and VPC endpoints

## Deployment Options

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A** | Deploy into existing VPC with isolated subnets | No new VPC needed; fits enterprise network standards | Requires VPC with pre-existing isolated subnets |
| **B** | Create new standalone VPC | Self-contained; no dependencies | Consumes VPC quota; may conflict with network policies |
| **C** | Deploy into existing VPC and create isolated subnets | Flexible; works with any VPC | More complex; modifies existing VPC |

## Option Details

### Option A: Use Existing VPC (Current Implementation)

**Requirements:**
- User provides `existing_vpc_id` in `cdk.json`
- Target VPC must already have Private Isolated subnets

**Implementation Status:** Partially complete. VPC lookup works, but fails if VPC lacks isolated subnets.

### Option B: Create New VPC (Original Behavior)

**Requirements:**
- Available VPC quota in account
- User provides `vpc_cidr` for new VPC

**Implementation Status:** Complete. Set `existing_vpc_id` to empty string.

### Option C: Create Subnets in Existing VPC (Proposed Enhancement)

**Requirements:**
- User provides `existing_vpc_id` and `vpc_cidr` for new subnets
- Available CIDR space within existing VPC

**Implementation:** SHCA would create isolated subnets within the specified VPC using the provided CIDR block.

## Recommendation

Implement **Option C** as the default behavior when `existing_vpc_id` is provided. This provides maximum flexibility:

1. Works with any existing VPC regardless of current subnet configuration
2. Creates dedicated isolated subnets for SHCA workloads
3. Does not require pre-configuration of target VPC
4. Maintains security posture with isolated subnets

## Helper Tool

A `select_vpc.py` script has been created to assist users:
1. Lists available VPCs in the account
2. Shows existing subnets and their CIDRs
3. Suggests an available CIDR block for SHCA subnets
4. Outputs values ready to paste into `cdk.json`

## Decision Required

Which option should be the primary supported deployment model?

- [ ] Option A only (require pre-existing isolated subnets)
- [ ] Option B only (always create new VPC)
- [ ] Option C (create subnets in existing VPC) - **Recommended**
- [ ] Support all options with configuration flags

## Next Steps

1. Team decision on preferred option
2. Complete implementation of selected option
3. Update README with deployment instructions
4. Test in target environments
