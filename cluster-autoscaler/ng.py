import boto3
import yaml
from datetime import datetime
import sys
import base64
import os
import glob

USER_DATA = '''
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="
--==MYBOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"
#!/bin/bash -xe
sudo /etc/eks/bootstrap.sh --apiserver-endpoint '${var.eks_cluster.cluster-endpoint}' --b64-cluster-ca '${var.eks_cluster.cluster-certificate-authority-data}' '${var.account}-${var.name}-${var.environment}'
echo "Running custom user data script" > /tmp/me.txt
yum install -y amazon-ssm-agent
echo "yum'd agent" >> /tmp/me.txt
yum update -y
systemctl enable amazon-ssm-agent && systemctl start amazon-ssm-agent
date >> /tmp/me.txt
--==MYBOUNDARY==--
'''

def ensure_launch_template(cfg, ec2):
    try:
        lt_name = f"lt-{cfg['node_capacity']}-{cfg['node_group_name']}-{cfg['environment']}"
        resp = ec2.describe_launch_templates(
            LaunchTemplateNames=[lt_name]
        )
        if resp['LaunchTemplates']:
            print("Launch template exists")
            return resp['LaunchTemplates'][0]['LaunchTemplateName'], resp['LaunchTemplates'][0]['LatestVersionNumber']
    except ec2.exceptions.ClientError as e:
        if "InvalidLaunchTemplateName.NotFoundException" in str(e):
            print("Launch template does not exist, will create")
        else:
            print("Error describing launch template:", e)
            print("Continuing to next node group...\n")
            return None, None

    print("Creating new launch template")
    lt_data = {
        'KeyName': cfg['pem_key'],
        'InstanceType': cfg['node_instance_types'][0],  # Must be string, not list
        'SecurityGroupIds': cfg['node_sgs'],
        'BlockDeviceMappings': [{
            'DeviceName': cfg['device_name'],
            'Ebs': {
                'VolumeSize': cfg['node_disk_size'],
                'VolumeType': 'gp3',
                'Encrypted': True,
                'KmsKeyId': cfg['aws_kms_key_arn']
            }
        }],
        'TagSpecifications': [{
            'ResourceType': 'instance',
            'Tags': [
                {'Key': 'Name', 'Value': lt_name},
                {'Key': 'Account', 'Value': cfg['account']},
                {'Key': 'Environment', 'Value': cfg['environment']}
            ]
        }]
    }
    if 'user_data' in cfg:
        lt_data['UserData'] = base64.b64encode(USER_DATA.encode('utf-8')).decode('utf-8')

    if 'launch_template_metadata_options' in cfg and cfg['launch_template_metadata_options']:
        lt_data['MetadataOptions'] = cfg['launch_template_metadata_options']

    try:
        res = ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            VersionDescription="Created by automation",
            LaunchTemplateData=lt_data,
        )
        lt_name = res['LaunchTemplate']['LaunchTemplateName']
        version_number = res['LaunchTemplate']['LatestVersionNumber']
        print(f"Created launch template {lt_name} v{version_number}")
        return lt_name, version_number
    except ec2.exceptions.ClientError as e:
        print(f"Error creating launch template: {e}")
        print("Continuing to next node group...\n")
        return None, None

def create_eks_nodegroup_from_yaml(yaml_file, aws_profile):
    with open(yaml_file, 'r') as f:
        cfg = yaml.safe_load(f)

    session = boto3.Session(profile_name=aws_profile, region_name=cfg['region'])
    ec2 = session.client('ec2')
    eks = session.client('eks')
    sts = session.client('sts')
    
    # Get caller identity for tagging
    caller_identity = sts.get_caller_identity()
    caller_arn = caller_identity['Arn']

    # Make sure launch template exists, get version
    launch_template_name, lt_version = ensure_launch_template(cfg, ec2)
    
    # If launch template creation failed, skip this node group
    if launch_template_name is None or lt_version is None:
        print(f"Skipping node group creation due to launch template issues...\n")
        return

    params = {
        'clusterName': cfg['cluster_name'],
        'nodegroupName': 'ng-' + cfg['node_group_name'] + '-' + cfg['environment'] + '-' + cfg['node_capacity'],
        'nodeRole': cfg['node_role_arn'],
        'subnets': cfg['subnet_ids'],
        'amiType': cfg['node_ami_type'],
        'capacityType': cfg.get('node_capacity', 'ON_DEMAND'),
        'launchTemplate': {
            'name': launch_template_name,
            'version': str(cfg.get('lt_version', lt_version))
        },
        'scalingConfig': {
            'minSize': cfg['node_min_size'],
            'maxSize': cfg['node_max_size'],
            'desiredSize': cfg['node_desired_size']
        },
        'updateConfig': {
            'maxUnavailable': cfg.get('node_max_unavailable', 1)
        },
        'labels': cfg.get('node_group_labels', {}),
        'tags': {
            'Account': cfg['account'],
            'Environment': cfg['environment'],
            'CreatedBy': 'ng.py',
            'CreatedByArn': caller_arn,
            'LaunchMonthYear': datetime.now().strftime('%b-%Y'),
            'Name': f"{cfg['account']}-{cfg['node_group_name']}-{cfg['environment']}-{cfg['node_capacity']}",
            f"k8s.io/cluster-autoscaler/{cfg['cluster_name']}": "owned",
            'k8s.io/cluster-autoscaler/enabled': "TRUE"
        }
    }

    if cfg.get('allow_taints') and cfg.get('node_taints'):
        params['taints'] = [
            {'key': t['key'], 'value': t['value'], 'effect': t['effect']}
            for t in cfg['node_taints']
        ]

    try:
        response = eks.create_nodegroup(**params)
        print(f"Node group create initiated: {response['nodegroup']['nodegroupName']}")
    except eks.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceInUseException':
            nodegroup_name = params['nodegroupName']
            print(f"Node group '{nodegroup_name}' already exists. Checking for drift...")
            
            # Check if node group exists and get its details
            try:
                existing_ng = eks.describe_nodegroup(
                    clusterName=cfg['cluster_name'],
                    nodegroupName=nodegroup_name
                )
                print(f"Existing node group details:")
                print(f"  - Status: {existing_ng['nodegroup'].get('status', 'Unknown')}")
                
                # Safely get instance types (might be in different field)
                existing_instance_types = existing_ng['nodegroup'].get('instanceTypes', 
                                                                      existing_ng['nodegroup'].get('instanceType', []))
                if isinstance(existing_instance_types, str):
                    existing_instance_types = [existing_instance_types]
                print(f"  - Instance Types: {existing_instance_types}")
                
                existing_capacity_type = existing_ng['nodegroup'].get('capacityType', 'Unknown')
                print(f"  - Capacity Type: {existing_capacity_type}")
                
                existing_ami_type = existing_ng['nodegroup'].get('amiType', 'Unknown')
                print(f"  - AMI Type: {existing_ami_type}")
                
                existing_scaling_config = existing_ng['nodegroup'].get('scalingConfig', {})
                print(f"  - Scaling Config: {existing_scaling_config}")
                
                # Check for potential drift
                drift_detected = False
                
                # Compare instance types (handle both list and string formats)
                desired_instance_types = params.get('instanceTypes', [])
                if isinstance(desired_instance_types, str):
                    desired_instance_types = [desired_instance_types]
                
                if existing_instance_types != desired_instance_types:
                    print(f"  ⚠️  DRIFT: Instance types differ")
                    print(f"     Existing: {existing_instance_types}")
                    print(f"     Desired:  {desired_instance_types}")
                    drift_detected = True
                
                if existing_capacity_type != params.get('capacityType'):
                    print(f"  ⚠️  DRIFT: Capacity type differs")
                    print(f"     Existing: {existing_capacity_type}")
                    print(f"     Desired:  {params.get('capacityType')}")
                    drift_detected = True
                
                if existing_ami_type != params.get('amiType'):
                    print(f"  ⚠️  DRIFT: AMI type differs")
                    print(f"     Existing: {existing_ami_type}")
                    print(f"     Desired:  {params.get('amiType')}")
                    drift_detected = True
                
                if not drift_detected:
                    print(f"  ✅ No drift detected - node group configuration matches desired state")
                
            except eks.exceptions.ClientError as describe_error:
                print(f"  ❌ Could not describe existing node group: {describe_error}")
            
            print(f"Continuing to next node group...\n")
            return  # Continue to next node group instead of exiting
            
        else:
            # Re-raise other errors
            print(f"Error creating node group: {e}")
            raise e

def get_yaml_files_from_directory(directory_path):
    """Get all YAML files from the specified directory"""
    if not os.path.exists(directory_path):
        print(f"Error: Directory '{directory_path}' does not exist")
        sys.exit(1)
    
    # Find all .yaml and .yml files in the directory
    yaml_pattern = os.path.join(directory_path, "*.yaml")
    yml_pattern = os.path.join(directory_path, "*.yml")
    
    yaml_files = glob.glob(yaml_pattern) + glob.glob(yml_pattern)
    yaml_files.sort()  # Sort for consistent ordering
    
    if not yaml_files:
        print(f"No YAML files found in directory '{directory_path}'")
        sys.exit(1)
    
    print(f"Found {len(yaml_files)} YAML files in '{directory_path}':")
    for file in yaml_files:
        print(f"  - {os.path.basename(file)}")
    print()
    
    return yaml_files

if __name__ == "__main__":
    aws_profile = 'adda-aiml'
    yaml_directory = 'aiml-ngs-temp'
    
    # Get all YAML files from the specified directory
    yaml_files = get_yaml_files_from_directory(yaml_directory)
    
    for yaml_file in yaml_files:
        print(f"Creating node group from {yaml_file}")
        create_eks_nodegroup_from_yaml(yaml_file, aws_profile)
        print(f"Node group created from {yaml_file}")
    print("All node groups created")