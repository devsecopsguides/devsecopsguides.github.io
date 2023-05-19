---
layout: default
title: Terraform
parent: Rules
---

# Terraform
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Hardcoded Credential

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
resource "aws_instance" "my_instance" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t2.micro"
  key_name      = "my_key_pair"
  security_groups = ["${var.security_group_id}"]
}
```

In this noncompliant code, the aws_instance resource creates an EC2 instance in AWS using a hardcoded AMI ID, instance type, key pair, and security group ID. This approach introduces security risks as sensitive information and configuration details are hardcoded in the Terraform code, making it less flexible, maintainable, and prone to errors.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
variable "ami_id" {
  type    = string
  default = "ami-0123456789abcdef0"
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}

variable "key_name" {
  type    = string
  default = "my_key_pair"
}

variable "security_group_id" {
  type    = string
  default = ""
}

resource "aws_instance" "my_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  security_groups = [var.security_group_id]
}
```


In the compliant code, variables are defined to make the code more flexible and configurable. The ami_id, instance_type, key_name, and security_group_id are declared as variables, allowing them to be easily parameterized and specified during Terraform deployment. This allows for greater reusability, dynamic configuration, and separation of sensitive information from the Terraform code.

By using variables, you can store sensitive information and configuration details outside of the Terraform code. This approach enhances security by providing better control over sensitive data and allowing for easier management and customization of infrastructure resources.

Additionally, ensure that sensitive data stored in variables is properly protected, such as by utilizing Terraform's input variable validation, storing variables in secure and encrypted locations, or leveraging secret management systems.

Remember to follow secure coding practices when working with Terraform, such as implementing least privilege access, regularly updating Terraform versions to leverage security patches, and utilizing secure communication channels for Terraform state storage.

By adopting a more flexible and parameterized approach using variables, you can enhance the security, maintainability, and scalability of your Terraform infrastructure deployments.


