---
layout: default
title: XML
parent: Rules
---

# XML
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### XML External Entity (XXE)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
# Noncompliant code
xml_data = params[:xml_data]
xml_doc = Nokogiri::XML(xml_data)

# Process XML document
```

In this noncompliant code, XML data is obtained from the params object and passed directly to the Nokogiri::XML parser for processing. This code is vulnerable to various XML-related attacks, such as XML External Entity (XXE) attacks or Billion Laughs attacks. Attackers can supply malicious XML payloads that may cause denial of service, disclosure of sensitive information, or other security risks.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
# Compliant code
xml_data = params[:xml_data]

begin
  xml_doc = Nokogiri::XML::Document.parse(xml_data) do |config|
    config.strict
    config.nonet
  end

  # Process XML document
  
rescue Nokogiri::XML::SyntaxError => e
  # Handle XML parsing errors
  logger.error "Error parsing XML: #{e}"
end
```


In the compliant code, the XML data is still obtained from the params object, but it is parsed using the Nokogiri::XML::Document.parse method with additional security configurations. The strict configuration ensures strict parsing of the XML document, and the nonet configuration disables network-related features such as entity expansion, external entity references, and DTD processing. These settings help mitigate XML-related vulnerabilities by reducing the risk of malicious payloads and preventing the parsing of external entities.

It's important to note that XML processing vulnerabilities can have various manifestations and require different mitigations based on the specific context and requirements. The compliant code provided here focuses on general XML parsing security, but additional measures may be necessary depending on the use case.

Other security measures you can implement to mitigate XML-related vulnerabilities include:

* Implementing input validation and sanitization to ensure that XML data conforms to the expected structure and format.
* Applying XML schema validation to validate the structure and data types of the XML document.
* Utilizing XML security libraries or frameworks that provide features like XML signature verification and encryption.
* Implementing appropriate access controls and least privilege principles to limit the exposure of sensitive information via XML processing.

By implementing these security measures and adhering to best practices, you can mitigate XML-related vulnerabilities and enhance the overall security of your application when processing XML data.



