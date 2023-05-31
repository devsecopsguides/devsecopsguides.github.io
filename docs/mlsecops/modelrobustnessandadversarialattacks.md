---
layout: default
title: Model Robustness and Adversarial Attacks
parent: MlSecOps
---

# Model Robustness and Adversarial Attacks
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---



Assessing and improving the robustness of machine learning models against adversarial attacks. This involves testing models against various adversarial scenarios, developing defenses to mitigate attacks (e.g., adversarial training), and understanding the limitations of model robustness.



## OWASP Machine Learning Security Verification Standard (MLSVS)


- [ ] Familiarize with MLSVS  

Read the MLSVS documentation available on the OWASP website.

- [ ] Assess Threat Model

Conduct a threat modeling exercise to identify potential security risks and threats in your machine learning system.

- [ ] Verify Model Training Data  Perform data validation and integrity checks on the training dataset to ensure its quality and prevent adversarial tampering.

- [ ] Verify Model Training Process Validate the security measures implemented during the model training process, such as access controls, versioning, and secure storage.

- [ ] Evaluate Model Robustness Test the model against various attack techniques, such as evasion attacks, poisoning attacks, and adversarial inputs, to assess its resilience.

- [ ] Verify Model Explanations Validate the interpretability and explainability of the model's predictions to ensure transparency and accountability.

- [ ] Assess Model Deployment Security  Evaluate the security controls implemented during the deployment of the machine learning model, including access controls, authentication, and encryption.

- [ ] Monitor Model Performance Establish monitoring mechanisms to detect and mitigate model performance degradation, data drift, and adversarial attacks in real-time.

- [ ] Implement Privacy Protection  Apply privacy-preserving techniques, such as differential privacy, anonymization, or federated learning, to protect sensitive data used in the machine learning system.

- [ ] Regularly Update MLSVS Practices  Stay updated with the latest MLSVS guidelines and best practices to adapt to evolving machine learning security threats.


## Supply Chain Security for MLSecOps

* **Install Sigstore**

```
# Clone the Sigstore repository
git clone https://github.com/sigstore/sigstore

# Change to the Sigstore directory
cd sigstore

# Install the Sigstore CLI
make install
```

* **Generate and manage cryptographic keys**

```
# Generate a new key pair
sigstore keygen

# List the available keys
sigstore key list

# Set the active key
sigstore key set <key-id>
```

* **Sign a software artifact**

```
# Sign a software artifact using the active key
sigstore sign <artifact-file>
```

* **Verify the signature of a signed artifact:**

```
# Verify the signature of a signed artifact
sigstore verify <signed-artifact-file>
```

* **Integrate Sigstore into the supply chain**

Sigstore can be integrated into various stages of the supply chain, such as during software development, build, deployment, and distribution. For example, you can configure your CI/CD pipeline to sign artifacts with Sigstore after successful builds and verify signatures during deployment.


* **Real-world example**

Let's say you have a machine learning model file named "model.pkl" that you want to sign and verify using Sigstore:

```
# Sign the model file
sigstore sign model.pkl

# This will generate a signed artifact file named "model.pkl.sig"

# Verify the signature of the signed model file
sigstore verify model.pkl.sig
```

By signing and verifying the model file using Sigstore, you can ensure its integrity and authenticity throughout the software supply chain.





## Kubeflow

* **Environment Setup**

Set up a Kubernetes cluster for deploying Kubeflow.

```
# Create a Kubernetes cluster using a cloud provider
gcloud container clusters create my-cluster --num-nodes=3 --zone=us-central1-a

# Install Kubeflow using the Kubeflow deployment tool
kfctl init my-kubeflow-app --platform gcp --project=my-project
kfctl generate all -V
kfctl apply all -V
```



* **Model Development**

Develop an ML model using TensorFlow and package it as a Docker container.

```
# Create a Dockerfile for building the model container
FROM tensorflow/tensorflow:latest
COPY model.py /app/
WORKDIR /app/
CMD ["python", "model.py"]

# Build and tag the Docker image
docker build -t my-model-image .
```


* **Version Control**

Track ML code and artifacts using Git for reproducibility and traceability.

```
# Initialize a Git repository
git init

# Add ML code and artifacts
git add .

# Commit changes
git commit -m "Initial commit"
```

* **Continuous Integration and Continuous Deployment (CI/CD)**

Set up a CI/CD pipeline for automated build, test, and deployment of ML models.

```
# Configure Jenkins pipeline for ML model
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        // Build Docker image
        sh 'docker build -t my-model-image .'
      }
    }
    stage('Test') {
      steps {
        // Run unit tests
        sh 'python -m unittest discover tests'
      }
    }
    stage('Deploy') {
      steps {
        // Deploy model to Kubeflow
        sh 'kubectl apply -f deployment.yaml'
      }
    }
  }
}
```

* **Security Scanning**

Integrate security scanning tools to identify vulnerabilities in ML code and dependencies.

```
# Install Snyk CLI
npm install -g snyk

# Scan Docker image for vulnerabilities
snyk test my-model-image
```

* **Model Training**

Use Kubeflow Pipelines for defining and executing ML workflows.

```
# Define a Kubeflow Pipeline for training
@dsl.pipeline(name='Training Pipeline', description='Pipeline for model training')
def train_pipeline():
    ...

# Compile and run the pipeline
kfp.compiler.Compiler().compile(train_pipeline, 'pipeline.tar.gz')
kfp.Client().create_run_from_pipeline_package('pipeline.tar.gz')
```

* **Model Serving**

Deploy trained models as Kubernetes services using Kubeflow Serving.

```
# Deploy trained model as a service
kubectl apply -f serving.yaml
```

* **Monitoring and Observability**

Use monitoring and logging tools to track the performance and behavior of your ML models in real-time. This helps in detecting anomalies, monitoring resource utilization, and ensuring the overall health of your ML system.

```
# Install Prometheus and Grafana using Helm
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/prometheus
helm install grafana grafana/grafana

# Access the Grafana dashboard
kubectl port-forward service/grafana 3000:80

# Configure Prometheus as a data source in Grafana and create ML model monitoring dashboards
```

* **Automated Testing**

Implement automated testing for your ML models to ensure their correctness and performance. This can include unit tests, integration tests, and load tests to validate the behavior of your models.

```
# Install PyTest
pip install pytest

# Write tests for ML models
# Example test:
def test_model_prediction():
    model = load_model('my-model.h5')
    input_data = ...
    expected_output = ...
    prediction = model.predict(input_data)
    assert np.allclose(prediction, expected_output, atol=1e-5)

# Run tests
pytest tests/
```



* **Auditing and Compliance**

Implement audit trails and compliance measures to track model changes, data usage, and model performance. This helps with regulatory requirements and ensures the transparency and accountability of your ML operations.

```
# Define and implement auditing mechanisms
# Example:
- Keep track of model versions and associated metadata (e.g., timestamp, author, changes made).
- Implement data access logs to monitor data usage and permissions.
- Establish model performance metrics and logging for compliance monitoring.
- Regularly review and update auditing and compliance measures based on regulatory standards.
```





## Chef InSpec



### Run a basic compliance check

Execute a compliance check using InSpec against a target system.


```
inspec exec <path_to_profile>
```

an example of an InSpec profile that you can use to execute a compliance check against a target system:

```
# my_compliance_profile.rb

# Define the profile metadata
title 'My Compliance Profile'
maintainer 'Your Name'
license 'Apache-2.0'
description 'Compliance checks for the target system'

# Define the target system(s) to be checked
target_hostname = attribute('target_hostname', description: 'Hostname of the target system')

# Start writing controls for compliance checks
control 'check_os_version' do
  impact 0.7
  title 'Operating System Version Check'
  desc 'Verify that the operating system version meets the compliance requirements'
  
  only_if { os.linux? } # Run this control only on Linux systems

  describe command('uname -r') do
    its('stdout') { should cmp '4.19.0-10-amd64' } # Replace with the desired OS version
  end
end

control 'check_secure_password_policy' do
  impact 0.5
  title 'Secure Password Policy Check'
  desc 'Ensure that the system enforces a secure password policy'
  
  describe file('/etc/login.defs') do
    its('content') { should match(/PASS_MAX_DAYS\s+(\d+)/) }
    its('content') { should match(/PASS_MIN_LEN\s+(\d+)/) }
    # Add more password policy checks as required
  end
end

# Add more controls as needed...
```

In this example, the profile consists of two controls: one for checking the operating system version and another for verifying the secure password policy. You can add more controls to the profile based on your compliance requirements.

To use this profile, create a new file with the .rb extension (e.g., my_compliance_profile.rb) and copy the code into it. Customize the controls according to your specific compliance checks and requirements.



### Generate a compliance report

Run a compliance check and generate a report in a specific format.


```
inspec exec <path_to_profile> --reporter <reporter_name>
```


### Check a specific control within a profile

Run a compliance check for a specific control within a profile.

```
inspec exec <path_to_profile> --controls <control_name>
```

### Specify target hostname/IP for the compliance check

Run a compliance check against a specific target system.

```
inspec exec <path_to_profile> -t <target_hostname_or_ip>
```


### Profile development mode

Enable profile development mode to interactively write and test controls.


```
inspec init profile <profile_directory>
inspec shell
```











