#!/usr/bin/env python3
"""
Cluster Autoscaler Installation Script
Installs Cluster Autoscaler on EKS cluster with proper IAM role and Helm chart
"""

import boto3
import yaml
import json
import subprocess
import sys
import os
from datetime import datetime
import base64

def get_caller_identity(sts):
    """Get current caller identity for tagging"""
    caller_identity = sts.get_caller_identity()
    return caller_identity

def get_eks_cluster_info(eks, cluster_name, caller_identity, region):
    """Get EKS cluster information including OIDC details"""
    try:
        cluster = eks.describe_cluster(name=cluster_name)
        cluster_info = cluster['cluster']
        
        # Extract OIDC information
        oidc_url = cluster_info['identity']['oidc']['issuer']
        oidc_arn_data = oidc_url.split('/')[-1]
        oidc_provider_arn = f"arn:aws:iam::{caller_identity['Account']}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{oidc_arn_data}"
        
        return {
            'cluster_id': cluster_info['name'],
            'cluster_arn': cluster_info['arn'],
            'oidc_url': oidc_url,
            'oidc_provider_arn': oidc_provider_arn,
            'oidc_arn_data': oidc_arn_data
        }
    except eks.exceptions.ResourceNotFoundException:
        print(f"Error: EKS cluster '{cluster_name}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error getting EKS cluster info: {e}")
        sys.exit(1)

def create_iam_policy(iam, account, name, environment):
    """Create IAM policy for Cluster Autoscaler"""
    # Use DNS-compliant naming for consistency
    policy_name = f"{name}-{environment}-AmazonEKSClusterAutoscalerPolicy"
    
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeAutoScalingInstances",
                    "autoscaling:DescribeInstances",
                    "autoscaling:DescribeScalingActivities",
                    "autoscaling:DescribeLaunchConfigurations",
                    "autoscaling:DescribeTags",
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:TerminateInstanceInAutoScalingGroup",
                    "ec2:DescribeLaunchTemplateVersions",
                    "ec2:DescribeInstanceTypes",
                    "ec2:DescribeImages",
                    "ec2:GetInstanceTypesFromInstanceRequirements",
                    "eks:DescribeNodegroup"
                ],
                "Resource": "*",
                "Effect": "Allow"
            }
        ]
    }
    
    try:
        # Check if policy already exists
        try:
            existing_policy = iam.get_policy(PolicyArn=f"arn:aws:iam::{account}:policy/{policy_name}")
            print(f"IAM Policy '{policy_name}' already exists")
            return existing_policy['Policy']['Arn']
        except iam.exceptions.NoSuchEntityException:
            pass
        
        # Create new policy
        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description="EKS Cluster Autoscaler Policy"
        )
        print(f"Created IAM Policy: {policy_name}")
        return response['Policy']['Arn']
        
    except Exception as e:
        print(f"Error creating IAM policy: {e}")
        sys.exit(1)

def create_iam_role(iam, account, name, environment, oidc_provider_arn, oidc_url, caller_identity):
    """Create IAM role for Cluster Autoscaler"""
    # Use DNS-compliant naming for consistency
    role_name = f"{name}-{environment}-cluster-autoscaler"
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Effect": "Allow",
                "Sid": "",
                "Principal": {
                    "Federated": oidc_provider_arn
                },
                "Condition": {
                    "StringEquals": {
                        f"{oidc_url.replace('https://', '')}:sub": "system:serviceaccount:kube-system:cluster-autoscaler"
                    }
                }
            }
        ]
    }
    
    try:
        # Check if role already exists
        try:
            existing_role = iam.get_role(RoleName=role_name)
            print(f"IAM Role '{role_name}' already exists")
            return existing_role['Role']['Arn']
        except iam.exceptions.NoSuchEntityException:
            pass
        
        # Create new role
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="EKS Cluster Autoscaler IAM Role",
            Tags=[
                {'Key': 'Account', 'Value': account},
                {'Key': 'Environment', 'Value': environment},
                {'Key': 'CreatedBy', 'Value': caller_identity.get('UserId', 'Unknown')},
                {'Key': 'CreatedByArn', 'Value': caller_identity['Arn']},
                {'Key': 'LaunchMonthYear', 'Value': datetime.now().strftime('%b-%Y')},
                {'Key': 'Name', 'Value': f"{name}-{environment}_Cluster-AutoScaler-Role"}
            ]
        )
        print(f"Created IAM Role: {role_name}")
        return response['Role']['Arn']
        
    except Exception as e:
        print(f"Error creating IAM role: {e}")
        sys.exit(1)

def attach_policy_to_role(iam, role_name, policy_arn):
    """Attach IAM policy to IAM role"""
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f"Attached policy to role: {role_name}")
    except Exception as e:
        print(f"Error attaching policy to role: {e}")
        sys.exit(1)

def create_helm_values_file(account, name, environment, cluster_id, aws_region, role_arn):
    """Create Helm values file for Cluster Autoscaler"""
    values_content = f"""# Cluster Autoscaler Helm Values
# Generated by install_cluster_autoscaler.py

cloudProvider: aws
image:
  tag: "v1.30.0"

autoDiscovery:
  clusterName: "{cluster_id}"

awsRegion: "{aws_region}"

rbac:
  serviceAccount:
    create: true
    name: cluster-autoscaler
    annotations:
      eks.amazonaws.com/role-arn: "{role_arn}"

extraArgs:
  expander: priority

expanderPriorities: |
  100:
    - ".*m8g.*SPOT.*"      # Graviton4
    - ".*c8g.*SPOT.*"
    - ".*r8g.*SPOT.*"      # Graviton4 memory-optimized
  99:
    - ".*t3a.*SPOT.*"
  98:
    - ".*t4g.*SPOT.*"      # Cheapest (Graviton2 burstable)
  97:
    - ".*m6g.*SPOT.*"      # Graviton2 general purpose
    - ".*c6g.*SPOT.*"
    - ".*r6g.*SPOT.*"      # Graviton2 memory-optimized
  96:
    - ".*m7g.*SPOT.*"      # Graviton3
    - ".*c7g.*SPOT.*"
    - ".*r7g.*SPOT.*"      # Graviton3 memory-optimized
  92:
    - ".*m5a.*SPOT.*"      # AMD-based general purpose
    - ".*c5a.*SPOT.*"
    - ".*r5a.*SPOT.*"      # AMD-based memory-optimized
    - ".*r5.*SPOT.*"      # Intel-based memory-optimized  
  91:
    - ".*m6a.*SPOT.*"
    - ".*c6a.*SPOT.*"      # AMD-based general purpose
    - ".*r6a.*SPOT.*"
  90:
    - ".*m5a.*SPOT.*"
    - ".*c5a.*SPOT.*"      # AMD-based general purpose
    - ".*r5a.*SPOT.*"      # AMD-based memory-optimized
  10:
    - ".*infra.*SPOT.*"
  1:
    - ".*"

resources:
  limits:
    cpu: 50m
    memory: 100Mi
  requests:
    cpu: 50m
    memory: 100Mi

nodeSelector:
  app_type: "critical"

tolerations:
  - key: "deployToArch"
    operator: "Equal"
    value: "arm64"
    effect: "NoSchedule"
  - key: "critical"
    operator: "Equal"
    value: "true"
    effect: "NoSchedule"
"""
    
    values_file = f"cluster_autoscaler_values_{account}_{environment}.yaml"
    with open(values_file, 'w') as f:
        f.write(values_content)
    
    print(f"Created Helm values file: {values_file}")
    return values_file

def check_existing_helm_release(release_name, namespace="kube-system"):
    """Check if Helm release already exists"""
    try:
        result = subprocess.run([
            'helm', 'list', '--namespace', namespace, '--output', 'json'
        ], check=True, capture_output=True, text=True)
        
        releases = json.loads(result.stdout)
        for release in releases:
            if release['name'] == release_name:
                return True
        return False
    except:
        return False

def install_helm_chart(release_name, values_file, chart_version="9.37.0"):
    """Install Cluster Autoscaler using Helm"""
    try:
        # Check if Helm is installed
        subprocess.run(['helm', 'version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Helm is not installed or not in PATH")
        print("Please install Helm: https://helm.sh/docs/intro/install/")
        sys.exit(1)
    
    try:
        # Add the autoscaler repository
        subprocess.run([
            'helm', 'repo', 'add', 'autoscaler', 
            'https://kubernetes.github.io/autoscaler'
        ], check=True, capture_output=True)
        
        # Update Helm repositories
        subprocess.run(['helm', 'repo', 'update'], check=True, capture_output=True)
        
        # Check if release already exists
        if check_existing_helm_release(release_name):
            print(f"Helm release '{release_name}' already exists. Upgrading...")
            action = "upgrade"
        else:
            print(f"Installing new Helm release '{release_name}'...")
            action = "install"
        
        # Install/upgrade the chart
        cmd = [
            'helm', 'upgrade', '--install', release_name,
            'autoscaler/cluster-autoscaler',
            '--version', chart_version,
            '--namespace', 'kube-system',
            '--values', values_file,
            '--force',  # Force update if there are ownership conflicts
            '--wait'
        ]
        
        print(f"Installing Cluster Autoscaler with command: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        print("✅ Cluster Autoscaler installed successfully!")
        print(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"Error installing Helm chart: {e}")
        print(f"Error output: {e.stderr}")
        
        # If there are ownership conflicts, try to delete and reinstall
        if "invalid ownership metadata" in str(e.stderr) or "missing key" in str(e.stderr):
            print("\n🔄 Detected ownership conflicts. Attempting to resolve...")
            try:
                # Comprehensive cleanup of all Cluster Autoscaler resources
                print("Performing comprehensive cleanup of Cluster Autoscaler resources...")
                
                resources_to_delete = [
                    'serviceaccount cluster-autoscaler',
                    'deployment cluster-autoscaler',
                    'configmap cluster-autoscaler-status',
                    'clusterrole cluster-autoscaler',
                    'clusterrolebinding cluster-autoscaler',
                    'role cluster-autoscaler',
                    'rolebinding cluster-autoscaler'
                ]
                
                for resource in resources_to_delete:
                    print(f"Deleting {resource}...")
                    try:
                        subprocess.run([
                            'kubectl', 'delete', resource, 
                            '--namespace', 'kube-system', '--ignore-not-found=true'
                        ], check=True, capture_output=True)
                        print(f"✅ {resource} deleted successfully")
                    except subprocess.CalledProcessError as kubectl_error:
                        print(f"⚠️  Could not delete {resource}: {kubectl_error}")
                
                # Also try to delete any resources that might be in default namespace
                print("Checking for resources in default namespace...")
                for resource in resources_to_delete:
                    try:
                        subprocess.run([
                            'kubectl', 'delete', resource, 
                            '--namespace', 'default', '--ignore-not-found=true'
                        ], check=True, capture_output=True)
                    except subprocess.CalledProcessError:
                        pass  # Ignore errors for default namespace
                
                # Also try to uninstall any existing Helm release (ignore if it doesn't exist)
                print("Attempting to uninstall any existing Helm release...")
                try:
                    subprocess.run([
                        'helm', 'uninstall', release_name, '--namespace', 'kube-system'
                    ], check=True, capture_output=True)
                    print("✅ Existing Helm release uninstalled")
                except subprocess.CalledProcessError:
                    print("ℹ️  No existing Helm release to uninstall (this is normal)")
                
                # Wait for cleanup and verify resources are gone
                import time
                print("Waiting for resource cleanup to complete...")
                time.sleep(10)
                
                # Verify that the ServiceAccount is actually gone
                print("Verifying cleanup...")
                try:
                    result = subprocess.run([
                        'kubectl', 'get', 'serviceaccount', 'cluster-autoscaler', 
                        '--namespace', 'kube-system'
                    ], capture_output=True, text=True)
                    if result.returncode == 0:
                        print("⚠️  ServiceAccount still exists, forcing deletion...")
                        subprocess.run([
                            'kubectl', 'delete', 'serviceaccount', 'cluster-autoscaler', 
                            '--namespace', 'kube-system', '--force', '--grace-period=0'
                        ], check=True, capture_output=True)
                        time.sleep(5)
                    else:
                        print("✅ ServiceAccount successfully removed")
                except subprocess.CalledProcessError:
                    print("✅ ServiceAccount successfully removed")
                
                # Try to install again
                print("Reinstalling Cluster Autoscaler...")
                cmd = [
                    'helm', 'upgrade', '--install', release_name,
                    'autoscaler/cluster-autoscaler',
                    '--version', chart_version,
                    '--namespace', 'kube-system',
                    '--values', values_file,
                    '--wait'
                ]
                
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                print("✅ Cluster Autoscaler installed successfully after resolving conflicts!")
                print(result.stdout)
                
            except subprocess.CalledProcessError as retry_error:
                print(f"❌ Failed to resolve conflicts: {retry_error}")
                print("Manual intervention may be required:")
                print(f"1. kubectl delete serviceaccount cluster-autoscaler -n kube-system")
                print(f"2. kubectl delete deployment cluster-autoscaler -n kube-system")
                print(f"3. Run this script again")
                sys.exit(1)
        else:
            sys.exit(1)

def main():
    # Configuration
    aws_profile = 'adda-aiml'
    region = 'ap-south-1'
    cluster_name = 'doubtsolver'
    account = '667706656695'
    name = 'aiml'
    environment = 'devo'
    chart_version = '9.37.0'
    
    print("🚀 Starting Cluster Autoscaler installation...")
    print(f"Cluster: {cluster_name}")
    print(f"Region: {region}")
    print(f"Account: {account}")
    print()
    
    # Initialize AWS clients
    session = boto3.Session(profile_name=aws_profile, region_name=region)
    iam = session.client('iam')
    eks = session.client('eks')
    sts = session.client('sts')
    
    # Get caller identity
    caller_identity = get_caller_identity(sts)
    print(f"Using AWS identity: {caller_identity['Arn']}")
    print()
    
    # Get EKS cluster information
    print("📋 Getting EKS cluster information...")
    cluster_info = get_eks_cluster_info(eks, cluster_name, caller_identity, region)
    print(f"Cluster ID: {cluster_info['cluster_id']}")
    print(f"OIDC URL: {cluster_info['oidc_url']}")
    print()
    
    # Create IAM policy
    print("🔐 Creating IAM policy...")
    policy_arn = create_iam_policy(iam, account, name, environment)
    print()
    
    # Create IAM role
    print("👤 Creating IAM role...")
    role_arn = create_iam_role(
        iam, account, name, environment, 
        cluster_info['oidc_provider_arn'], 
        cluster_info['oidc_url'], 
        caller_identity
    )
    print()
    
    # Attach policy to role
    print("🔗 Attaching policy to role...")
    role_name = f"{account}-{name}-{environment}-cluster-autoscaler"
    attach_policy_to_role(iam, role_name, policy_arn)
    print()
    
    # Create Helm values file
    print("📝 Creating Helm values file...")
    values_file = create_helm_values_file(
        account, name, environment, 
        cluster_info['cluster_id'], 
        region, role_arn
    )
    print()
    
    # Install Helm chart
    print("📦 Installing Cluster Autoscaler with Helm...")
    # Fix DNS naming: Kubernetes names must start with alphabetic character
    release_name = f"aiml-{environment}-cluster-as"
    install_helm_chart(release_name, values_file, chart_version)
    print()
    
    print("🎉 Cluster Autoscaler installation completed successfully!")
    print(f"Release name: {release_name}")
    print(f"IAM Role ARN: {role_arn}")
    print(f"Values file: {values_file}")

if __name__ == "__main__":
    main()
