import boto3
import time
import subprocess
import os
import botocore.exceptions
import threading
import re
import configparser

def get_aws_credentials():
    """Fetch AWS credentials from environment variables."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("AWS_SESSION_TOKEN")
    return access_key, secret_key, session_token

def aws_sso_login():
    """Ensure AWS SSO session is active."""
    print("🔄 Ensuring AWS SSO session is active...")
    attempts = 3
    for attempt in range(attempts):
        try:
            subprocess.run(["aws", "sso", "login"], check=True)
            print("✅ AWS SSO login successful.")
            return
        except subprocess.CalledProcessError:
            print(f"❌ AWS SSO login failed (attempt {attempt + 1}/{attempts}). Retrying...")
            time.sleep(5)

    print("❌ All AWS SSO login attempts failed. Please log in manually using 'aws sso login'.")
    exit(1)

def aws_sso_login_for_profile(profile_name):
    """Ensure AWS SSO session is active for the selected profile."""
    print(f"🔐 Logging in with AWS SSO for profile: {profile_name}")
    try:
        subprocess.run(["aws", "sso", "login", "--profile", profile_name], check=True)
        print(f"✅ AWS SSO login successful for profile: {profile_name}")
    except subprocess.CalledProcessError as e:
        print(f"❌ AWS SSO login failed for profile: {profile_name}")
        print(e)
        exit(1)


def choose_aws_profile():
    """Prompt the user to select an AWS profile from the ~/.aws/config."""
    # Load profiles from ~/.aws/config
    config = configparser.ConfigParser()
    config.read(os.path.expanduser("~/.aws/config"))
    
    # Extract profile names from config file
    profiles = [section for section in config.sections() if section.startswith("profile ")]
    
    if not profiles:
        print("❌ No profiles found in your AWS config file.")
        return None
    
    print("Available AWS Profiles:")
    for idx, profile in enumerate(profiles, 1):
        print(f"{idx}. {profile.replace('profile ', '')}")
    
    # User selects a profile
    try:
        profile_index = int(input(f"Choose a profile (1-{len(profiles)}): ")) - 1
        if profile_index < 0 or profile_index >= len(profiles):
            raise ValueError("Invalid profile index.")
        selected_profile = profiles[profile_index].replace('profile ', '')
        print(f"✅ Selected profile: {selected_profile}")
        return selected_profile
    except (ValueError, IndexError):
        print("❌ Invalid selection. Please choose a valid profile.")
        return choose_aws_profile()  # Retry if invalid input
    

def ensure_aws_session(profile_name=None):
    """Ensure AWS session using a specific profile or fallback to SSO/credentials."""
    try:
        if profile_name:
            # If a profile is provided, use it to create the session
            print(f"✅ Using AWS profile: {profile_name}")
            return boto3.Session(profile_name=profile_name)
        
        # Fallback to the original method (environment variables or SSO)
        access_key, secret_key, session_token = get_aws_credentials()
        if access_key and secret_key:
            print("✅ Using AWS credentials from environment variables.")
            return boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)
        
        print("⏳ Starting AWS authentication process via SSO...")
        aws_sso_login()  # Ensure SSO login happens if no profile or credentials found
        return boto3.Session()  # Use SSO if no profile or credentials are found
    except Exception as e:
        print(f"❌ Failed to create AWS session: {e}")
        exit(1)



def get_aws_region(region_name):
    region_map = {
        "Oregon": "us-west-2",
        "N Virginia": "us-east-1",
        "Ireland": "eu-west-1",
        "Frankfurt": "eu-central-1",
        "Sydney": "ap-southeast-2",
        "Tokyo": "ap-northeast-1",
        "Singapore": "ap-southeast-1",
        "Mumbai": "ap-south-1",
        "Sao Paulo": "sa-east-1"
    }
    return region_map.get(region_name, region_name)

def get_ec2_instances(session, region, name_filter):
    ec2_client = session.client('ec2', region_name=region)
    response = ec2_client.describe_instances(
        Filters=[{'Name': 'tag:Name', 'Values': [f"*{name_filter}*"]}]
    )
    instances = {}
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            name_tag = next(
                (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None
            )
            if name_tag:
                instances[instance_id] = name_tag
    return instances


def get_target_groups(session, region):
    elbv2_client = session.client('elbv2', region_name=region)
    response = elbv2_client.describe_target_groups()
    return {tg['TargetGroupName']: tg['TargetGroupArn'] for tg in response['TargetGroups']}

def get_target_group_instances(session, target_group_arns, region):
    elb_client = session.client('elbv2', region_name=region)
    instances = []
    for arn in target_group_arns:
        response = elb_client.describe_target_health(TargetGroupArn=arn)
        instances.extend([target['Target']['Id'] for target in response['TargetHealthDescriptions']])
    return instances

def get_auto_scaling_group(session, region, instance_id):
    asg_client = session.client('autoscaling', region_name=region)
    response = asg_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
    if response['AutoScalingInstances']:
        return response['AutoScalingInstances'][0]['AutoScalingGroupName']
    return None

def get_asg_target_groups(session, region, asg_name):
    asg_client = session.client('autoscaling', region_name=region)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    if response['AutoScalingGroups']:
        target_groups = response['AutoScalingGroups'][0].get('TargetGroupARNs', [])
        print(f"✅ ASG {asg_name} is linked to Target Groups: {target_groups}")  # Debugging line
        return target_groups
    return []

def drain_instance(session, instance_id, target_group_arns, region):
    """Drain an instance by deregistering it from the target group(s) and ensuring it's fully drained before continuing."""
    try:
        print(f"🔄 Draining instance {instance_id} from target group(s) {target_group_arns}...")
        client = session.client('elbv2', region_name=region)
        
        # Deregister instance from each target group
        for target_group_arn in target_group_arns:
            client.deregister_targets(TargetGroupArn=target_group_arn, Targets=[{'Id': instance_id}])
            print(f"✅ Instance {instance_id} deregistered from {target_group_arn}")

        # Wait for the instance to be fully drained (not healthy or still draining in the target group)
        is_drained = False
        max_attempts = 30  # Maximum number of checks (5 minutes total)
        attempt = 0

        while not is_drained and attempt < max_attempts:
            time.sleep(10)  # Wait 10 seconds between health checks
            is_drained = True
            for target_group_arn in target_group_arns:
                response = client.describe_target_health(TargetGroupArn=target_group_arn, Targets=[{'Id': instance_id}])
                target_health = response['TargetHealthDescriptions'][0]['TargetHealth']['State']
                
                # Check if the health state is not 'healthy' and not 'draining'
                if target_health == 'healthy' or target_health == 'draining':
                    is_drained = False
                    print(f"🔄 Instance {instance_id} is still in state {target_health} in target group {target_group_arn}. Waiting for it to drain.")
                    break
                else:
                    print(f"✅ Instance {instance_id} is not healthy or draining in target group {target_group_arn}. Proceeding to next check.")

            attempt += 1
            if is_drained:
                print(f"✅ Instance {instance_id} is fully drained (no longer healthy or draining).")
            elif attempt == max_attempts:
                print(f"⚠️ Instance {instance_id} did not fully drain within the expected time. Please check manually.")

    except botocore.exceptions.ClientError as e:
        print(f"❌ Failed to drain instance {instance_id} from target group {target_group_arns}. Error: {e}")
        return False
    return True



def register_instance(session, instance_id, target_group_arns, region):
    elb_client = session.client('elbv2', region_name=region)
    for arn in target_group_arns:
        elb_client.register_targets(TargetGroupArn=arn, Targets=[{"Id": instance_id}])
        print(f"✅ Instance {instance_id} successfully re-registered. Waiting for health check...")

    while True:
        time.sleep(10)
        response = elb_client.describe_target_health(TargetGroupArn=target_group_arns[0], Targets=[{"Id": instance_id}])
        state = response['TargetHealthDescriptions'][0]['TargetHealth']['State']
        print(f"🔄 Instance {instance_id} health check state: {state}")
        if state == "healthy":
            print(f"✅ Instance {instance_id} is healthy!")
            break

def get_target_group_for_service(service_name, session, region):
    target_groups = get_target_groups(session, region)
    for tg_name, tg_arn in target_groups.items():
        if service_name in tg_name:
            print(f"✅ Found Target Group {tg_name} matching service {service_name}.")
            return tg_arn
    print(f"❌ No Target Group found for service {service_name}.")
    return None

def execute_ssm_command(session, instance_id, command, region, timeout=600):
    """Execute an SSM command on an instance and return stdout and stderr with a timeout."""
    print(f"⚙️ Executing command on instance {instance_id}: {command}")
    ssm_client = session.client("ssm", region_name=region)

    def run_command():
        """Helper function to send the command and get the result."""
        nonlocal stdout, stderr, status
        try:
            # Send command to SSM
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
                TimeoutSeconds=timeout,
            )
            command_id = response["Command"]["CommandId"]

            # Wait for the command to complete
            for _ in range(10):  # Prevent infinite loops
                time.sleep(5)
                try:
                    output = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                    status = output["Status"]

                    if status in ["Success", "Failed", "TimedOut", "Cancelled"]:
                        break  # Exit loop when command finishes

                except botocore.exceptions.ClientError as e:
                    if "ThrottlingException" in str(e):
                        print("⚠️ AWS is throttling requests, retrying...")
                        time.sleep(5)
                    else:
                        print(f"⚠️ AWS API error: {e}")
                        time.sleep(2)

            # Capture command output
            stdout = output.get("StandardOutputContent", "").strip()
            stderr = output.get("StandardErrorContent", "").strip()

            print(f"✅ Command output for {instance_id}:\n{stdout}")
            if stderr:
                print(f"❌ Error output:\n{stderr}")

        except botocore.exceptions.ClientError as e:
            print(f"❌ Failed to execute command on {instance_id}: {e}")
            stdout, stderr = None, str(e)  # Return error message

    # Initialize stdout, stderr, and status variables
    stdout, stderr, status = None, None, None

    # Start the command execution in a separate thread to enforce timeout
    command_thread = threading.Thread(target=run_command)
    command_thread.start()

    # Wait for the command to finish or timeout
    command_thread.join(timeout)

    # Check if the command is still running after the timeout
    if command_thread.is_alive():
        print(f"❌ Command on {instance_id} timed out after {timeout} seconds.")
        return None, "Command timed out"

    return stdout, stderr

def manage_chef_client(session, instance_id, region):
    """Check if chef-client is running, kill it if found, and restart if necessary."""
    # 1️⃣ Check if chef-client is running
    stdout, _ = execute_ssm_command(session, instance_id, "pgrep -x chef-client", region)

    if stdout:
        print(f"👀 chef-client is running on {instance_id}, attempting to kill it...")

        # 2️⃣ Kill the chef-client process
        execute_ssm_command(session, instance_id, "pkill -x chef-client", region)

        # 3️⃣ Wait for a moment and check again
        time.sleep(3)
        stdout, _ = execute_ssm_command(session, instance_id, "pgrep -x chef-client", region)

        if stdout:
            print(f"⚠️ chef-client is STILL running on {instance_id} after attempting to kill it!")
        else:
            print(f"✅ chef-client successfully stopped on {instance_id}.")

    # 4️⃣ If chef-client is NOT running, start it
    stdout, _ = execute_ssm_command(session, instance_id, "pgrep -x chef-client", region)

    if not stdout:
        print(f"🚀 chef-client is NOT running on {instance_id}, starting it now...")
        execute_ssm_command(session, instance_id, "sudo chef-client", region)
    else:
        print(f"✅ chef-client is already running, no action needed.")

def check_health(session, instance_id, service, target_group_arns, region):
    # Define key components and their corresponding health check URLs
    health_check_urls = {
        "auth": "http://localhost:8080/v1/manage/checkhealth",
        "workspace": "http://localhost:8080/api/v1/healthcheck",
        "devportal": "http://localhost:8080/healthcheck",
        "account": "http://localhost:8080/console/health_check",
        "kpns": "http://localhost:8080/service/healthcheck/json",
        "mtmw": "http://localhost:8080/admin/healthcheck?output=json"
    }

    # List of key components (can add more as needed)
    key_components = ["auth", "workspace", "devportal", "account", "kpns", "mtmw"]

    # Search for the key component in the service name
    matched_url = None
    for key in key_components:
        if re.search(key, service, re.IGNORECASE):  # Case-insensitive search
            matched_url = health_check_urls[key]
            break

    if not matched_url:
        print(f"❌ No matching health check URL found for service: {service}. Skipping health check.")
        return False

    # Perform health check using the matched URL
    command = f"curl -iv {matched_url}"
    print(f"⚙️ Checking health of {service} on instance {instance_id}: {matched_url}")
    output = execute_ssm_command(session, instance_id, command, region)

    if "200" in output[0]:
        print(f"✅ Instance {instance_id} passed health check. Re-registering...")
        register_instance(session, instance_id, target_group_arns, region)
        return True
    else:
        print(f"❌ Instance {instance_id} failed health check. Skipping re-registration.")
        return False

def check_health_before_deregistering(session, instance_id, service, target_group_arns, region):
    # Define key components and their corresponding health check URLs
    health_check_urls = {
        "auth": "http://localhost:8080/v1/manage/checkhealth",
        "workspace": "http://localhost:8080/api/v1/healthcheck",
        "devportal": "http://localhost:8080/healthcheck",
        "account": "http://localhost:8080/console/health_check",
        "kpns": "http://localhost:8080/service/healthcheck/json",
        "mtmw": "http://localhost:8080/admin/healthcheck?output=json"
    }

    # List of key components (can add more as needed)
    key_components = ["auth", "workspace", "devportal", "account", "kpns", "mtmw"]

    # Search for the key component in the service name
    matched_url = None
    for key in key_components:
        if re.search(key, service, re.IGNORECASE):  # Case-insensitive search
            matched_url = health_check_urls[key]
            break

    if not matched_url:
        print(f"❌ No matching health check URL found for service: {service}. Skipping health check.")
        return False

    # Perform health check using the matched URL
    command = f"curl -iv {matched_url}"
    print(f"⚙️ Checking health of {service} on instance {instance_id}: {matched_url}")
    output = execute_ssm_command(session, instance_id, command, region)

    if "200" in output[0]:
        print(f"✅ Instance {instance_id} passed health check before deregistering. Proceeding with deregistration.")
        return True
    else:
        print(f"❌ Instance {instance_id} failed health check before deregistering. Skipping further actions.")
        return False
    
    

def scale_instances_if_needed(session, target_group_arns, region):
    """Ensure at least 2 instances in the target group for high availability using Auto Scaling."""
    # Get instances in the target group
    instances = get_target_group_instances(session, target_group_arns, region)
    print(f"✅ Found instances in target group: {instances}")

    # If there's only 1 instance, scale up the Auto Scaling Group to ensure high availability
    new_instance_id = None
    if len(instances) == 1:
        print("❗ Only 1 instance in target group. Scaling up Auto Scaling Group to launch a new instance.")

        # Retrieve the Auto Scaling Group name for the target group
        asg_name = None
        for arn in target_group_arns:
            asg_name = get_auto_scaling_group(session, region, instances[0])
            if asg_name:
                break
        
        if not asg_name:
            print("❌ No Auto Scaling Group found for the target group. Exiting.")
            return None

        asg_client = session.client('autoscaling', region_name=region)
        
        # Get current Auto Scaling Group settings
        response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        asg_group = response['AutoScalingGroups'][0]
        
        # Adjust desired capacity to scale up the group by 1 instance
        desired_capacity = asg_group['DesiredCapacity']
        max_capacity = asg_group['MaxSize']
        
        # Make sure not to exceed max capacity
        if desired_capacity < max_capacity:
            asg_client.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                DesiredCapacity=desired_capacity + 1  # Increase desired capacity by 1
            )
            print(f"🔄 Updated desired capacity of ASG {asg_name} to {desired_capacity + 1}.")
            new_instance_id = launch_new_instance(session, asg_name, region)  # Launch a new instance if desired capacity increases
        else:
            print(f"❗ ASG {asg_name} has reached its max capacity ({max_capacity}). No more instances can be added.")
    else:
        print("✅ There are enough instances (>=2) in the target group.")
    
    return new_instance_id

def launch_new_instance(session, asg_name, region):
    """Helper function to launch a new instance in the Auto Scaling Group."""
    asg_client = session.client('autoscaling', region_name=region)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instances = response['AutoScalingGroups'][0].get('Instances', [])
    
    # Assuming the latest instance added is the new instance
    if instances:
        new_instance_id = instances[-1]['InstanceId']
        print(f"✅ Launched new instance {new_instance_id}.")
        return new_instance_id
    return None

def terminate_new_instance(session, new_instance_id, region):
    """Terminate the newly launched instance after completion."""
    if new_instance_id:
        ec2_client = session.client('ec2', region_name=region)
        ec2_client.terminate_instances(InstanceIds=[new_instance_id])
        print(f"🔴 Terminated the newly launched instance {new_instance_id}.")
    else:
        print("❌ No new instance to terminate.")

def revert_asg_capacity(session, asg_name, region, original_desired_capacity):
    """Revert the desired capacity of the Auto Scaling Group to its original value."""
    asg_client = session.client('autoscaling', region_name=region)
    asg_client.update_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        DesiredCapacity=original_desired_capacity
    )
    print(f"✅ Reverted the desired capacity of ASG {asg_name} back to {original_desired_capacity}.")

def process_instances(session, instance_target_group_map, service_name, region):
    processed_instances = set()
    new_instance_id = None
    original_asg_name = None
    original_desired_capacity = None

    # Flatten all target groups used, to check HA status globally
    all_target_group_arns = set()
    for tg_list in instance_target_group_map.values():
        all_target_group_arns.update(tg_list)
    all_target_group_arns = list(all_target_group_arns)

    # Step 1: High availability check — scale up if only one instance is active
    new_instance_id = scale_instances_if_needed(session, all_target_group_arns, region)

    # Step 2: Process instances (custom logic based on how many instances exist)
    all_instances = list(instance_target_group_map.keys())

    # ✅ FIXED LOGIC: process all if 2 or fewer, else half+1
    if len(all_instances) <= 2:
        instances_to_process = all_instances
    else:
        num_instances = (len(all_instances) + 1) // 2
        instances_to_process = all_instances[:num_instances]

    for instance_id in instances_to_process:
        if instance_id in processed_instances:
            continue

        target_group_arns = instance_target_group_map.get(instance_id, [])
        if not target_group_arns:
            print(f"⚠️ No target groups associated with instance {instance_id}. Skipping.")
            continue

        # Health check before deregistration
        if not check_health_before_deregistering(session, instance_id, service_name, target_group_arns, region):
            continue

        # Drain instance
        if not drain_instance(session, instance_id, target_group_arns, region):
            print(f"❌ Failed to drain instance {instance_id}. Skipping.")
            continue

        # Chef-client execution
        print(f"⚙️ Running chef-client on {instance_id}...")
        chef_output = execute_ssm_command(session, instance_id, "sudo chef-client", region)
        print(f"📄 Chef-client output:\n{chef_output[0]}")

        # Post-chef-client health check (informational only)
        print(f"🔍 Performing post-chef-client health check on {instance_id}...")
        post_chef_health = check_health_before_deregistering(session, instance_id, service_name, target_group_arns, region)
        status_msg = "✅ Passed" if post_chef_health else "❌ Failed"
        print(f"📊 Post-chef-client health check result: {status_msg}")

        # Re-register to target groups
        print(f"🔄 Re-registering instance {instance_id} to its original target group(s)...")
        register_instance(session, instance_id, target_group_arns, region)


        processed_instances.add(instance_id)

        # Store ASG capacity for revert
        if not original_asg_name:
            original_asg_name = get_auto_scaling_group(session, region, instance_id)
            if original_asg_name:
                asg_client = session.client('autoscaling', region_name=region)
                response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[original_asg_name])
                if response['AutoScalingGroups']:
                    original_desired_capacity = response['AutoScalingGroups'][0]['DesiredCapacity']

    print("✅ All selected instances processed successfully.")

    # Step 3: Cleanup — terminate temp instance if created and revert ASG scaling
    if new_instance_id:
        terminate_new_instance(session, new_instance_id, region)

    if original_asg_name and original_desired_capacity is not None:
        revert_asg_capacity(session, original_asg_name, region, original_desired_capacity)



def main():
    # Ask for the AWS profile to use (dev, qa, stg) or let the user choose from config
    profile_name = choose_aws_profile()
    if not profile_name:
        # Fallback to "dev" profile if no profile selected
        profile_name = "dev"
        print(f"Using default AWS profile: {profile_name}")

    # Create an AWS session using the selected or default profile
    session = ensure_aws_session(profile_name)

      # Create an AWS session using the selected or default profile
    session = ensure_aws_session(profile_name)

    # Request the AWS region
    region = input("Enter AWS region (e.g., us-west-2, us-east-1): ").strip()
    print(f"✅ Using AWS region: {region}")

    # Service name input
    service_input = input("Enter the service name(s), comma-separated (e.g., kpns, workspace, auth0, auth1): ")
    service_names = [s.strip() for s in service_input.split(",") if s.strip()]

    if not service_names:
        print("❌ No valid service names provided. Exiting.")
        return

    for service_name in service_names:
        print(f"\n🚀 Processing service: {service_name}")

        # Optional: still get a matching TG by service name
        target_group_arn = get_target_group_for_service(service_name, session, region)

        if not target_group_arn:
            print(f"❌ No Target Group found for service {service_name}. Skipping.")
            continue

        # Step 1: Get instances matching service name (instance_id → Name tag)
        instance_name_map = get_ec2_instances(session, region, service_name)
        if not instance_name_map:
            print(f"❌ No EC2 instances found for service {service_name}. Skipping.")
            continue

        print(f"✅ Found EC2 instances: {list(instance_name_map.keys())}")

        # Step 2: Map each instance to its own target groups
        instance_target_group_map = {}
        for instance_id, name_tag in instance_name_map.items():
            asg_name = get_auto_scaling_group(session, region, instance_id)
            if asg_name:
                asg_target_groups = get_asg_target_groups(session, region, asg_name)
                if asg_target_groups:
                    instance_target_group_map[instance_id] = asg_target_groups
                else:
                    print(f"⚠️ No target groups found for ASG {asg_name} (instance {instance_id})")
            else:
                print(f"⚠️ No ASG found for instance {instance_id}")

        if not instance_target_group_map:
            print(f"❌ No target group mappings found for any instances of {service_name}. Skipping.")
            continue

        # Step 3: Process each instance with its mapped target groups
        print(f"🔄 Starting instance processing for service '{service_name}'")
        process_instances(session, instance_target_group_map, service_name, region)

        print(f"✅ Finished processing service: {service_name}")

    print("\n✅ All provided services have been processed. Exiting script.")

if __name__ == "__main__":
    main()