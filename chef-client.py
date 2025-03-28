import boto3
import time
import subprocess
import os
import botocore.exceptions

def get_aws_credentials():
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("AWS_SESSION_TOKEN")
    return access_key, secret_key, session_token

def aws_sso_login():
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

def ensure_aws_session():
    try:
        access_key, secret_key, session_token = get_aws_credentials()
        if access_key and secret_key:
            print("✅ Using AWS credentials from environment variables.")
            return boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)
        
        print("⏳ Starting AWS authentication process...")
        aws_sso_login()
        return boto3.Session()
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

def get_target_group_arn(target_group_key):
    target_groups = {
        "kpns": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/kpns1-Targe-13V1608IJ4UIP/9a03fdfd5ffa425c",
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/kpns1-Targe-H8ENC3T5CY1R/57b1d0fc603b2a3c"
        ],
        "workspace": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/works-Targe-MHIT1X4QDXX/645cd5d9dee65e6c",
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/works-Targe-W822F6DIX4CB/0a7b8cfc959eb633"
        ],
        "mtmw": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/mtmw1-Targe-1PLHZ5GLXKSNZ/0d26413614ecddab",
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/mtmw1-Targe-IFCFDN4OPB6U/c10e1f7054c379d4"
        ],
        "auth0": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/auth0-Targe-IMCLXQP58IXU/0a213d0eb2d989a0",
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/auth0-Targe-1SHXIWCGIHSCL/f8173a6202e3cfd1"
        ],
        "auth1": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/auth1-Targe-1U4O3UL2PV8NZ/a785fa9c4d17ef5b",
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/auth1-Targe-SKH6BTC1SNI5/dd60e8144d1aab3f"
        ],
        "devportal": [
            "arn:aws:elasticloadbalancing:us-east-1:723696830269:targetgroup/devpo-Targe-5HGI5MWVU1KZ/4845b97bc143ee9b"
        ]
    }
    return target_groups.get(target_group_key, None)

def get_target_group_instances(session, target_group_arn, region):
    elb_client = session.client('elbv2', region_name=region)
    instances = []
    for arn in target_group_arn:
        response = elb_client.describe_target_health(TargetGroupArn=arn)
        for target in response['TargetHealthDescriptions']:
            instances.append(target['Target']['Id'])
    return instances

def drain_instance(session, instance_id, target_group_arns, region):
    elb_client = session.client('elbv2', region_name=region)
    for arn in target_group_arns:
        elb_client.deregister_targets(TargetGroupArn=arn, Targets=[{"Id": instance_id}])
    print(f"🔄 Draining instance {instance_id}...")
    while True:
        time.sleep(5)
        response = elb_client.describe_target_health(TargetGroupArn=target_group_arns[0], Targets=[{"Id": instance_id}])
        state = response['TargetHealthDescriptions'][0]['TargetHealth']['State']
        if state == "unused":
            print(f"✅ Instance {instance_id} successfully drained.")
            break

def register_instance(session, instance_id, target_group_arns, region):
    elb_client = session.client('elbv2', region_name=region)
    for arn in target_group_arns:
        elb_client.register_targets(TargetGroupArn=arn, Targets=[{"Id": instance_id}])
        print(f"✅ Instance {instance_id} successfully re-registered. Waiting for health check...")

    # Wait for instance to become healthy
    while True:
        time.sleep(10)
        response = elb_client.describe_target_health(TargetGroupArn=target_group_arns[0], Targets=[{"Id": instance_id}])
        state = response['TargetHealthDescriptions'][0]['TargetHealth']['State']
        print(f"🔄 Instance {instance_id} health check state: {state}")
        if state == "healthy":
            print(f"✅ Instance {instance_id} is healthy!")
            break

def execute_ssm_command(session, instance_id, command, region):
    """Execute an SSM command on an instance and return stdout and stderr."""
    print(f"⚙️ Executing command on instance {instance_id}: {command}")
    ssm_client = session.client("ssm", region_name=region)

    try:
        # Send command to SSM
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=600,
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

        return stdout, stderr  # Return both stdout and stderr

    except botocore.exceptions.ClientError as e:
        print(f"❌ Failed to execute command on {instance_id}: {e}")
        return None, str(e)  # Return error message


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
    health_check_urls = {
        "auth": "http://localhost:8080/v1/manage/checkhealth",
        "workspace": "http://localhost:8080/api/v1/healthcheck",
        "devportal": "http://localhost:8080/healthcheck",
        "account": "http://localhost:8080/console/health_check",
        "kpns": "http://localhost:8080/service/healthcheck/json",
        "mtmw": "http://localhost:8080/admin/healthcheck?output=json"
    }
    
    if service not in health_check_urls:
        print(f"❌ Unknown service: {service}. Skipping health check.")
        return False
    
    url = health_check_urls[service]
    command = f"curl -iv {url}"
    print(f"⚙️ Checking health of {service} on instance {instance_id}: {url}")
    output = execute_ssm_command(session, instance_id, command, region)
      
    if "200" in output[0]:
        print(f"✅ Instance {instance_id} passed health check. Re-registering...")
        register_instance(session, instance_id, target_group_arns, region)
        return True
    else:
        print(f"❌ Instance {instance_id} failed health check. Skipping re-registration.")
        return False

def process_instances(session, target_group_arns, target_group_key, region):
    instances = get_target_group_instances(session, target_group_arns, region)
    if not instances:
        print(f"❌ No instances found in target group {target_group_key}.")
        return
    
    num_instances = (len(instances) + 1) // 2
    instances_to_process = instances[:num_instances]
    
    for instance_id in instances_to_process:
        drain_instance(session, instance_id, target_group_arns, region)
        print(f"⚙️ Executing chef-client on {instance_id}...")
        execute_ssm_command(session, instance_id, "sudo chef-client", region)
        print(f"🔄 Running health check for instance {instance_id}...")

        # Stop processing other instances if health check fails
        if not check_health(session, instance_id, target_group_key, target_group_arns, region):
            print(f"❌ Health check failed for {instance_id}. Stopping further processing.")
            return  # Exit function, preventing further instances from being drained

        print(f"🔄 Re-registering instance {instance_id}...")
        register_instance(session, instance_id, target_group_arns, region)

def main():
    session = ensure_aws_session()
    region_input = input("Enter AWS region name (e.g., Oregon, N Virginia, Tokyo): ")
    region = get_aws_region(region_input)
    print(f"✅ Using AWS region: {region}")

    target_group_key = input("Enter target group key (kpns, workspace, etc.): ")
    target_group_arns = get_target_group_arn(target_group_key)
    if not target_group_arns:
        print("❌ Invalid target group key. Exiting.")
        return

    print("🔄 Processing instances for target group...")
    process_instances(session, target_group_arns, target_group_key, region)

if __name__ == "__main__":
    main()
