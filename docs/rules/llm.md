---
layout: default
title: LLM
parent: Rules
---

# LLM
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---






## LLM01:2023 - Prompt Injections


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
user_prompt = input("Enter your request: ")
response = LLM_model.generate_prompt(user_prompt)
print(response)
```

In the above code, the user is prompted to enter their request, which is then directly used as the prompt for the LLM model without any validation or sanitization. This code is susceptible to prompt injections as an attacker can input a malicious prompt to manipulate the LLM's behavior or extract sensitive information.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
import re

# Define a regular expression pattern to validate the user's input
input_pattern = r'^[a-zA-Z0-9\s\.,!?]+$'

def sanitize_input(user_input):
    # Remove any special characters or symbols from the input
    sanitized_input = re.sub(r'[^\w\s\.,!?]', '', user_input)
    return sanitized_input.strip()

def validate_input(user_input):
    # Validate the user's input against the defined pattern
    return re.match(input_pattern, user_input) is not None

user_prompt = input("Enter your request: ")

# Sanitize and validate the user's input
sanitized_prompt = sanitize_input(user_prompt)

if validate_input(sanitized_prompt):
    response = LLM_model.generate_prompt(sanitized_prompt)
    print(response)
else:
    print("Invalid input. Please enter a valid request.")
```


In the compliant code, several changes have been made to prevent prompt injections:

1.  A regular expression pattern (`input_pattern`) is defined to validate the user's input. It allows only alphanumeric characters, spaces, commas, periods, exclamation marks, and question marks.
    
2.  The `sanitize_input` function removes any special characters or symbols from the user's input, ensuring it contains only the allowed characters.
    
3.  The `validate_input` function checks whether the sanitized input matches the defined pattern. If it does, the LLM model is called to generate the prompt and produce the response. Otherwise, an error message is displayed.
    

By validating and sanitizing the user's input, the compliant code protects against prompt injections by ensuring that only safe and expected prompts are passed to the LLM model.





## LLM02:2023 - Data Leakage


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
user_prompt = input("Enter your request: ")
response = LLM_model.generate_prompt(user_prompt)
print(response)
```

In the above code, the user is prompted to enter their request, which is then directly used as the prompt for the LLM model without any validation or sanitization. This code is susceptible to prompt injections as an attacker can input a malicious prompt to manipulate the LLM's behavior or extract sensitive information.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
import re

user_prompt = input("Enter your request: ")

# Check if the user prompt contains sensitive information
if re.search(r'\b(?:password|credit card|social security)\b', user_prompt, re.IGNORECASE):
    print("Error: Your request contains sensitive information.")
else:
    response = LLM_model.generate_prompt(user_prompt)
    print(response)
```


In the compliant vulnerable code, an attempt is made to prevent data leakage by checking if the user prompt contains sensitive information using regular expressions. If the user prompt matches any sensitive information patterns (such as "password," "credit card," or "social security"), an error message is displayed instead of generating a response. However, the code is still vulnerable because the error message itself could potentially disclose the presence of sensitive information in the user's input.




## LLM03:2023 - Inadequate Sandboxing


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
import os

user_prompt = input("Enter your command: ")
os.system(user_prompt)
```

In this noncompliant code, the user is prompted to enter a command, and the `os.system()` function is used to execute the user's input directly. There is no proper sandboxing or restriction on the user's command, allowing them to execute any system-level command they desire. This lack of sandboxing exposes the underlying system to potential unauthorized actions and compromises its security.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
import subprocess

user_prompt = input("Enter your command: ")
subprocess.run(user_prompt, shell=False)
```


In the compliant vulnerable code, the `subprocess.run()` function is used instead of `os.system()`. The `shell` parameter is set to `False` to prevent command injection vulnerabilities. However, this code is still vulnerable because it lacks proper sandboxing or restriction on the user's command. The user can execute any command within the allowed privileges of the running process.




## LLM04:2023 - Unauthorized Code Execution


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
user_prompt = input("Enter your command: ")
exec(user_prompt)
```

In the noncompliant code, the user's input is directly passed to the `exec()` function, which executes the command as is without any validation or sanitization. This code is vulnerable to unauthorized code execution since an attacker can craft a malicious command to be executed by the LLM.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
import subprocess

def execute_command(command):
    subprocess.run(command, shell=True)

def process_user_prompt(user_prompt):
    # Sanitize and validate user input before executing the command
    if not valid_input(user_prompt):
        print("Invalid input. Please try again.")
        return
    
    execute_command(user_prompt)

def valid_input(user_prompt):
    # Implement input validation logic here
    # Ensure that user_prompt does not contain any malicious commands or unauthorized code

    # Example validation: Restrict specific commands or check for patterns indicative of malicious input
    if "rm -rf" in user_prompt:
        return False

    return True

user_prompt = input("Enter your command: ")
process_user_prompt(user_prompt)
```


In the compliant vulnerable code, input validation and sanitization have been added. The `valid_input()` function checks if the user's input is safe and does not contain any potentially malicious commands or unauthorized code. If the input is determined to be valid, the command is executed using the `execute_command()` function, which utilizes the `subprocess.run()` method with the `shell=True` argument. The `valid_input()` function can be customized to include additional validation logic based on the specific requirements and potential threats.



## LLM05:2023 - SSRF Vulnerabilities


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
import requests

def fetch_data(url):
    response = requests.get(url)
    return response.text

user_input = input("Enter the URL to fetch data from: ")
data = fetch_data(user_input)
print(data)
```

The noncompliant code directly uses the user-provided URL to make a request without any validation or restriction. This allows an attacker to provide a malicious URL that could target internal systems, APIs, or sensitive resources.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
import requests

ALLOWED_DOMAINS = ["example.com", "api.example.com"]

def fetch_data(url):
    response = requests.get(url)
    return response.text

def is_url_allowed(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain in ALLOWED_DOMAINS

user_input = input("Enter the URL to fetch data from: ")

if is_url_allowed(user_input):
    data = fetch_data(user_input)
    print(data)
else:
    print("Access to the specified URL is not allowed.")
```


The compliant vulnerable code introduces a basic URL validation mechanism. It defines a list of allowed domains (`ALLOWED_DOMAINS`) and checks if the user-provided URL belongs to one of these domains. If the URL is allowed, the code proceeds to fetch the data. Otherwise, it displays a message indicating that access to the specified URL is not allowed.


## LLM06:2023 - Overreliance on LLM-generated Content


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
user_input = input("Enter your question: ")
response = LLM_model.generate_response(user_input)
print(response)
```

In the noncompliant code above, there is an overreliance on the LLM-generated content. The user's input is directly passed to the LLM model without any verification or human oversight. The generated response is then printed without any further validation or review, leading to potential risks associated with overreliance on the LLM-generated content.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
user_input = input("Enter your question: ")
response = LLM_model.generate_response(user_input)
reviewed_response = review_content(response)
print(reviewed_response)

def review_content(content):
    # Implement human review process to validate and verify the LLM-generated content
    # Check for accuracy, factuality, and potential biases
    # Make corrections or additions as necessary
    return content
```


In the compliant vulnerable full code, there is an attempt to address the risks associated with overreliance on LLM-generated content. The user's input is still passed to the LLM model for generating a response. However, the generated response is then passed through a `review_content()` function, which represents a human review process. This function allows for validation, verification, and correction of the LLM-generated content. The reviewed response is then printed or used further in the application.



## LLM07:2023 - Inadequate AI Alignment


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
# Noncompliant code: Inadequate AI Alignment

def generate_response(user_prompt):
    # Arbitrary and poorly defined objectives
    if user_prompt == "get_personal_info":
        return get_personal_info()
    elif user_prompt == "generate_random_number":
        return generate_random_number()
    else:
        return "Invalid prompt"

def get_personal_info():
    # Code to retrieve and return personal information
    ...

def generate_random_number():
    # Code to generate a random number
    ...
```

The noncompliant code demonstrates inadequate AI alignment as it lacks well-defined objectives for the LLM. It has arbitrary and poorly defined objectives where different user prompts trigger different actions without clear alignment with the desired outcomes. The code does not consider factors like authorization or user validation, leading to potential security and privacy issues.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
# Compliant vulnerable code: Improved AI Alignment

def generate_response(user_prompt):
    if user_prompt == "get_personal_info":
        return handle_personal_info_request()
    elif user_prompt == "generate_random_number":
        return handle_random_number_request()
    else:
        return "Invalid prompt"

def handle_personal_info_request():
    # Perform necessary checks and validations
    if user_is_authorized():
        return retrieve_personal_info()
    else:
        return "Unauthorized access"

def retrieve_personal_info():
    # Code to retrieve and return personal information
    ...

def handle_random_number_request():
    # Perform necessary checks and validations
    if user_is_authorized():
        return generate_random_number()
    else:
        return "Unauthorized access"

def generate_random_number():
    # Code to generate a random number
    ...
```


The compliant vulnerable full code improves the AI alignment by considering more specific and well-defined objectives. It introduces separate functions to handle different user prompts, such as "get_personal_info" and "generate_random_number". Each function performs the necessary checks and validations before executing the corresponding action. For example, before retrieving personal information or generating a random number, the code checks if the user is authorized to perform those actions. This ensures that the LLM's behavior is aligned with the intended objectives and incorporates security measures.



## LLM08:2023 - Insufficient Access Controls


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
def generate_response(user_input):
    response = LLM_model.generate_prompt(user_input)
    return response

user_input = input("Enter your request: ")
response = generate_response(user_input)
print(response)
```

In the above noncompliant code, there are no access controls implemented. Any user can input a request, and the `generate_response()` function directly passes the user input to the LLM model without any authentication or authorization checks. This lack of access controls allows any user, authorized or unauthorized, to interact with the LLM and obtain responses.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
def generate_response(user_input, user_role):
    if user_role == "admin":
        response = LLM_model.generate_prompt(user_input)
        return response
    else:
        return "Unauthorized access"

def authenticate_user(username, password):
    # Code for authenticating the user

def get_user_role(username):
    # Code for retrieving the user's role

def main():
    username = input("Username: ")
    password = input("Password: ")

    if authenticate_user(username, password):
        user_role = get_user_role(username)
        user_input = input("Enter your request: ")

        response = generate_response(user_input, user_role)
        print(response)
    else:
        print("Authentication failed")

if __name__ == "__main__":
    main()
```


In the compliant vulnerable code, access controls are implemented to ensure that only authenticated and authorized users can interact with the LLM. The `generate_response()` function now takes an additional parameter `user_role`, which represents the role of the user. The function checks if the user has the "admin" role before generating the LLM response. If the user has the "admin" role, the response is generated and returned. Otherwise, an "Unauthorized access" message is returned.

The `main()` function handles the user authentication process by prompting for a username and password. It calls the `authenticate_user()` function to validate the credentials and retrieve the user's role using the `get_user_role()` function. If authentication is successful, the user is prompted to enter a request, and the `generate_response()` function is called with the user's input and role.



## LLM09:2023 - Improper Error Handling


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
# Noncompliant code
try:
    # Code that may raise an error
    result = perform_operation()
    print("Operation completed successfully!")
except Exception as e:
    # Displaying the detailed error message to the user
    print(f"An error occurred: {str(e)}")
```

The noncompliant code above demonstrates improper error handling practices. When an error occurs during the `perform_operation()` function call, the code catches the exception and displays the detailed error message to the user using `print(f"An error occurred: {str(e)}")`. This approach exposes sensitive information and potentially reveals implementation details to the user, which could be leveraged by attackers.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
# Compliant vulnerable code
import logging

try:
    # Code that may raise an error
    result = perform_operation()
    print("Operation completed successfully!")
except Exception as e:
    # Logging the error message for internal use
    logging.exception("An error occurred during the operation")
    # Displaying a generic error message to the user
    print("An error occurred. Please try again later.")
```


The compliant vulnerable code addresses the issue of improper error handling. It introduces logging using the `logging` module to capture the detailed error information for internal use. Instead of displaying the specific error message to the user, it provides a generic error message like "An error occurred. Please try again later." This prevents the leakage of sensitive details to the user while still indicating that an error occurred.



## LLM10:2023 - Training Data Poisoning


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```python
# Noncompliant code - Training Data Poisoning
import random

def get_training_data():
    # Retrieve training data from an untrusted source
    training_data = untrusted_source.get_data()
    
    # Introduce malicious examples into the training data
    poisoned_data = training_data + malicious_examples
    
    return poisoned_data

def train_model():
    data = get_training_data()
    
    # Train the model using the poisoned data
    model.train(data)
```

In the noncompliant code, the training data is retrieved from an untrusted source, which can be manipulated to introduce malicious examples. The code combines the untrusted data with malicious examples, resulting in a poisoned dataset. This allows the attacker to manipulate the model's behavior and introduce vulnerabilities or biases.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```python
# Compliant Vulnerable code - Training Data Poisoning
import random

def get_training_data():
    # Retrieve training data from a trusted source
    training_data = trusted_source.get_data()
    
    return training_data

def sanitize_data(data):
    # Implement data sanitization techniques to remove potential vulnerabilities or biases
    sanitized_data = perform_sanitization(data)
    
    return sanitized_data

def train_model():
    data = get_training_data()
    
    # Sanitize the training data to remove any potential poisoning or biases
    sanitized_data = sanitize_data(data)
    
    # Train the model using the sanitized data
    model.train(sanitized_data)
```


In the compliant vulnerable code, the training data is retrieved from a trusted source, ensuring its integrity and reliability. The data is then passed through a data sanitization process to remove potential vulnerabilities, biases, or malicious content. The sanitized data is used for training the model, reducing the risk of training data poisoning.