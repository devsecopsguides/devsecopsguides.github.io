---
layout: default
title: CloudFormation
parent: Rules
---

# CloudFormation
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### Hardcoded Name

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
# Noncompliant code
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
```

In this noncompliant code, an AWS CloudFormation template is used to create an S3 bucket. The bucket name is hardcoded as my-bucket without considering potential naming conflicts or security best practices. This approach introduces security risks, as the bucket name might already be taken or it might inadvertently expose sensitive information.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
# Compliant code
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: 
        Fn::Sub: "my-bucket-${AWS::StackName}-${AWS::Region}"
]
```


In the compliant code, the bucket name is dynamically generated using the Fn::Sub intrinsic function. The bucket name is composed of the string "my-bucket-", followed by the current CloudFormation stack name (AWS::StackName), and the AWS region (AWS::Region). This approach ensures uniqueness of the bucket name within the CloudFormation stack and helps mitigate potential naming conflicts.

By using dynamic naming with the Fn::Sub function, you can avoid hardcoded values and provide a more flexible and secure approach to resource creation in CloudFormation.

Additionally, you can implement other security measures such as:

* Leveraging IAM policies to control access permissions for the created resources.
* Implementing resource-level permissions using AWS Identity and Access Management (IAM) roles and policies.
* Encrypting sensitive data at rest using AWS Key Management Service (KMS) or other encryption mechanisms.
* Implementing stack-level or resource-level CloudFormation stack policies to control stack updates and prevent unauthorized modifications.

By following security best practices and utilizing dynamic values in CloudFormation templates, you can enhance the security, flexibility, and reliability of your infrastructure deployments in AWS.




Semgrep:


```
rules:
  - id: noncompliant-s3-bucket-properties
    patterns:
      - pattern: 'Type: AWS::S3::Bucket\n    Properties:\n      BucketName: .+'
    message: "Noncompliant S3 bucket properties"
```

CodeQL:



```
import cf

from Template t
where exists (Bucket b | b.getType().toString() = "AWS::S3::Bucket")
  and not exists (Bucket b | b.getType().toString() = "AWS::S3::Bucket" and b.getProperties().get("BucketName") != null)
select t
```



