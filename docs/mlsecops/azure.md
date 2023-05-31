---
layout: default
title: Azure
parent: MlSecOps
---


# Azure 
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Responsible AI principles



- [ ] Azure Machine Learning

Azure Machine Learning is a cloud-based service for building, training, and deploying machine learning models. It provides tools and capabilities to promote responsible AI practices.

```
az ml workspace create --workspace-name <workspace-name> --resource-group <resource-group> --location <location>
```




- [ ] Azure Machine Learning Interpretability

Azure Machine Learning Interpretability provides tools to understand and interpret machine learning models, making them more transparent and explainable.

```
azureml-interpret
```





- [ ] Azure Cognitive Services

Azure Cognitive Services offer pre-built AI models and APIs for tasks such as natural language processing, computer vision, and speech recognition. These services can be used responsibly by adhering to guidelines and incorporating fairness and bias considerations.

```
az cognitiveservices account create --name <service-name> --resource-group <resource-group> --kind TextAnalytics --sku <sku-name> --location <location>
```




- [ ] Azure AI Ethics and Governance

Azure provides various governance tools and features to ensure responsible AI practices, including Azure Policy, Azure Blueprints, and Azure Advisor.



