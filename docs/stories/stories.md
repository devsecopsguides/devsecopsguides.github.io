---
layout: default
title: Stories
nav_order: 12
has_children: false
permalink: stories
---

# Stories

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


## DevSecOps War Stories: The Challenges of Implementing SAST 

Source: [Devsecops War Stories](https://wehackpurple.com/devsecops-war-stories/)

DevSecOps has emerged as a culture shift in software development, aiming to improve software security by breaking down silos and fostering collaboration among security professionals and IT teams. However, the transition to DevSecOps is not without its challenges. In this article, we will explore one such challenge through a war story of a SAST (Static Application Security Testing) rollout.

The Context of DevOps

Before diving into the war story, let's briefly understand DevOps. DevOps is a modern software development approach that emphasizes close collaboration between developers and operations teams, leveraging automation to create reliable and high-quality products. DevOps encourages a focus on system efficiency, rapid feedback loops, and continuous learning and improvement.

DevOps and Security

The goals of DevOps align well with security objectives. Reliable and performant systems enhance availability, while automation reduces human error and increases opportunities for security testing. Additionally, the use of infrastructure-as-code allows security scanning of infrastructure configurations, similar to application code.

The Promise of DevSecOps

DevSecOps extends the DevOps philosophy by incorporating security into the development process from the start. It aims to integrate security practices, tools, and expertise seamlessly into the DevOps pipeline. However, realizing the full potential of DevSecOps requires addressing various challenges along the way.

The SAST Rollout Story

In this war story, we follow the journey of an AppSec professional tasked with introducing SAST into a client's DevOps pipeline. The client was already progressing on their DevOps journey, regularly pushing code to version control and running CI/CD pipelines every two weeks.

The Challenge of Integration

The client's development process involved a change management board (CAB) meeting, where teams presented their cases to move their code to production. Prior to the CAB meeting, developers conducted their own tests to ensure smooth approval. The AppSec professional introduced SAST, SCA (Software Composition Analysis), and IaC (Infrastructure-as-Code) scanning into the CI/CD pipeline, adding three additional tests.

Ancient Applications and Red Flags

While the newer applications successfully passed the security scans, the older ones presented a different story. The SAST scan results resembled a Christmas tree, with bright red flags indicating numerous security issues. This revealed a significant challenge in securing legacy applications within the DevSecOps framework.

The Emailing Mishap

In an effort to encourage developers to fix security issues early in the SDLC, the AppSec professional configured the SAST tool to email reports whenever code changes were detected. However, a crucial oversight occurred—every software developer in the company received an email for each code check-in, causing an overwhelming amount of emails and embarrassment for the developers.

The Road to Resolution

Upon learning about the unintended consequences of their approach, the AppSec professional recognized the mistake and took swift action. They restructured the tool's setup, creating two separate configurations: one providing a holistic view of the organization's security posture and another delivering reports specific to each DevOps team. This adjustment alleviated the spamming issue and allowed for accurate reporting while respecting the developers' workflow.

The Importance of Learning and Adapting

The SAST rollout experience serves as a valuable lesson in the DevSecOps journey. When confronted with the negative impact of their initial approach, the AppSec professional demonstrated the third way of DevOps—taking time to improve daily work. By acknowledging the mistake, making the necessary changes, and prioritizing the developers' experience, they exemplified the resilience and adaptability required for successful DevSecOps implementation.


## Integrating DevSecOps into the Software Development Lifecycle: A Case Study by Broadcom Software

Source: [Securing the DX NetOps Development Lifecycle with DevSecOps](https://academy.broadcom.com/blog/netops/dx-netops/securing-the-dx-netops-development-lifecycle-with-devsecops)

In today's digital landscape, the rise of cybersecurity exploits and software vulnerabilities has become a pressing concern for enterprises. Recent incidents, such as Sun Burst and Log4j, have highlighted the importance of securing software supply chains and adopting robust security practices. To address these challenges, forward-thinking organizations like Broadcom Software have turned to DevSecOps, a strategic approach that integrates security into the early stages of the software development lifecycle (SDLC).

Software Supply Chain Attacks:
Software supply chain attacks have emerged as a significant threat, targeting developers and suppliers. Attackers exploit unsecured networks and unsafe SDLC practices to inject malware into legitimate applications. For organizations relying on third-party software, it becomes nearly impossible to assess the security of every update from every supplier they use.

Embracing DevSecOps:
DevSecOps represents a paradigm shift in security tactics and strategies, moving away from traditional reactive approaches. By adopting DevSecOps, organizations can embed security practices throughout the SDLC, reducing issues, improving code reliability, and enabling faster product launches. Broadcom Software's DX NetOps development organization has embraced DevSecOps to ensure enterprise-grade software reliability and security.

Key Practices for Secure SDLC at Broadcom Software:

Automation: Broadcom Software has standardized on proven systems for secure continuous integration (CI) and continuous delivery (CD), minimizing manual interventions and ensuring build control.
Shift-Left Approach: Security checks are conducted early and often through static scans after every code change, uncovering vulnerabilities and identifying potential risks associated with third-party components.
Continuous Audit: Broadcom Software enforces security throughout the software lifecycle with a focus on team education, architectural risk assessment, code analysis, penetration testing, and continuous vulnerability tracking.
Bill of Materials: Unique fingerprints are created to track the source code, bill of materials, and build systems used for every software release, providing transparency and accountability.
Benefits and Culture of Innovation:
Broadcom Software's implementation of DevSecOps enables agility and speed without compromising security and compliance. By incorporating security from the start, the organization fosters a culture of innovation, leveraging the continuous flow of new features and capabilities.

Upgrades and Maintenance:
To combat cyber threats effectively, staying up-to-date with the latest software versions is crucial. Broadcom Software offers regular service packs to DX NetOps customers, ensuring their products align with the latest security guidelines. The company provides support during upgrade weekends, reducing the risk of extended downtime and upgrade failure.



## The Evolution of DevSecOps: A Year in Review

Source: [Top Stories Of 2022 From The World Of DevOps](https://www.linkedin.com/company/razorops/)

The year 2022 has been marked by numerous challenges, from the global impact of COVID-19 and ongoing conflicts to economic uncertainties. Amidst these adversities, however, innovation has thrived. Today, as we bid farewell to 2022, let us reflect on the significant milestones in the world of DevOps. What stands out when we think of DevOps in 2022?

Incorporation of DevSecOps Lifecycle:
One of the prominent trends that gained attention in 2022 was the integration of the DevSecOps lifecycle. This approach embraces the shift-left philosophy, prioritizing security from the beginning rather than treating it as an afterthought. Current DevSecOps trends reveal that approximately 40% of businesses perform DAST tests, 50% perform SAST tests, and 20% scan dependencies and containers. Enterprises have recognized the importance of DevSecOps in enhancing security, streamlining governance, and improving observability.

Serverless Computing and the Bridge between Development and Operations:
The adoption of serverless computing has significantly contributed to the DevOps process. By closing the gap between development and operations, it has enhanced operability. Moreover, serverless computing empowers hosts to develop, test, and deploy DevOps pipeline code efficiently. As a result, more than 50% of enterprises with cloud-based services have integrated serverless computing into their systems. The serverless market is projected to reach a value of $30 billion by 2030.

Microservice Architecture for Holistic Product Quality:
The IT sector extensively embraced microservice architecture in 2022. Breaking down large-scale applications into smaller, manageable pieces has simplified development, testing, and deployment processes. This approach has also facilitated consistent and frequent delivery of software and applications, thereby improving the holistic quality of products.

AIOps and MLOps: Optimizing DevOps Operations:
The significant roles played by AIOps and MLOps in DevOps operations were notable in 2022. These technologies have optimized processes for high-quality and rapid releases. MLOps supports the development of machine learning systems, while AIOps automates IT operations and processes. AIOps allows organizations to easily identify and resolve issues that hinder operational productivity, while MLOps boosts productivity through optimization. It is predicted that by 2026, these technologies will grow into a $40.91 billion industry.

Low-Code DevOps Approach for Enhanced Development and Deployment:
In 2022, many robust enterprises adopted a low-code DevOps approach, reaping benefits for their teams. Businesses and organizations can now build applications using low-code platforms without the need to learn how to code. This trend has accelerated the development and deployment processes, enabling teams to work more efficiently.

GitOps: Automating Infrastructure:
Another popular trend that emerged in DevOps workflows in 2022 was GitOps. It revolutionized the control, monitoring, and automation of infrastructure. By emphasizing increased releases and consistent delivery, GitOps enabled organizations to develop, test, and deploy software rapidly and efficiently.

Kubernetes: A Continuous and Autonomous Container-Based Ecosystem:
Kubernetes, a continuous and autonomous container-based integration ecosystem, has empowered developers to scale resources dynamically. It facilitates cross-functional collaboration and minimizes deployment downtime. Notably, 48% of developers have turned to Kubernetes for container integration, highlighting its significance in the DevOps landscape.

The Future of DevOps:
As DevOps continues to evolve and mature, it has become an indispensable part of the modern software industry. The associated frameworks and technologies will continue to drive faster and better development, maintenance, and management of software and applications. 



## The Evolution of DevSecOps: Advancing Security in the Digital Age

Source: [Epic Failures in DevSecOps by DevSecOps Days Press](https://www.linkedin.com/posts/rajkgrover_epic-failures-in-devsecops-vol-1-activity-7025826736101548032-VoBE/?utm_source=share&utm_medium=member_desktop)

In today's rapidly evolving digital landscape, security has become a critical concern for organizations. The integration of security practices into the DevOps process has given rise to a new approach known as DevSecOps. This article delves into the history of DevSecOps and provides ten actionable ways to advance in this field.

The History of DevSecOps:
DevSecOps emerged as a response to the growing need for incorporating security early in the software development lifecycle. It builds upon the principles of DevOps, emphasizing collaboration, automation, and continuous integration and delivery. By integrating security practices from the beginning, DevSecOps aims to ensure that applications and systems are resilient against potential threats.

10 Ways to Advance in DevSecOps:

See the new world:
Recognize that the digital landscape is constantly changing, with new technologies and threats emerging. Stay updated with the latest trends and challenges to adapt and enhance your security practices.

Recognize your place in the value chain:
Understand your role in the overall value chain of software development and delivery. Recognize that security is not just an isolated function but an integral part of the entire process.

Know Agile and DevOps:
Familiarize yourself with Agile methodologies and DevOps practices. Understanding how these frameworks operate will help you align security practices seamlessly within the development process.

Live out bi-directional empathy:
Develop empathy and foster strong collaboration between security teams and developers. Encourage open communication and mutual understanding to bridge the gap between security and development.

Do security for the developer's benefit:
Shift the focus of security from being a hindrance to becoming an enabler for developers. Provide them with the tools, training, and resources they need to build secure applications without compromising on productivity.

Operationalize DevSecOps:
Integrate security practices into the entire software development lifecycle. Implement automated security testing, code analysis, and vulnerability management tools to ensure continuous security throughout the process.

Make security normal:
Embed security as a core component of the development culture. Promote security awareness, conduct regular training, and establish security checkpoints at each stage of development to make security practices a norm.

Track adversary interest:
Stay vigilant and monitor evolving threats and adversary interests. Understand the tactics and techniques used by potential attackers to proactively address vulnerabilities and protect against emerging threats.

Create security observability:
Implement robust monitoring and logging systems to gain visibility into security events and incidents. Leverage security observability tools and practices to detect and respond to security breaches effectively.

Build the future:
Stay innovative and forward-thinking. Continuously explore emerging technologies, frameworks, and best practices in DevSecOps. Actively contribute to the DevSecOps community and share your knowledge and experiences to drive the field forward.


## True Story of Implementing SecDevOps in FinTech

Source: [Snyk](https://www.youtube.com/watch?v=_d6JJfl9S5g)

In the fast-paced world of FinTech, where technology and finance intersect, security is of paramount importance. The integration of security practices into the DevOps workflow has given rise to a powerful approach known as SecDevOps. In the captivating video "The True Story of Implementing SecDevOps in FinTech" by John Smith, the challenges, successes, and lessons learned from implementing SecDevOps in the FinTech industry are explored. This article will delve into the key insights from the video and shed light on the journey of implementing SecDevOps in the dynamic world of FinTech.

Understanding SecDevOps:
SecDevOps, short for Secure DevOps, is an approach that aims to embed security practices and principles into the DevOps process from the very beginning. It is a collaborative effort between development, operations, and security teams, working together to build secure and reliable software solutions. The implementation of SecDevOps ensures that security is not an afterthought but an integral part of the development lifecycle.

Challenges Faced:
In the video, John Smith discusses the challenges encountered during the implementation of SecDevOps in the FinTech industry. One of the primary challenges was the cultural shift required within the organization. Breaking down silos between teams and fostering collaboration between developers and security professionals was crucial for success. Additionally, balancing the need for speed and agility with stringent security requirements posed a significant challenge. Finding the right balance between these two seemingly opposing forces was key to achieving success in SecDevOps.

Successes and Lessons Learned:
Despite the challenges, the implementation of SecDevOps in the FinTech industry yielded remarkable successes. One notable achievement was the ability to identify and mitigate security vulnerabilities early in the development process. By integrating security practices into every stage of the software development lifecycle, the organization was able to build robust and secure applications. This resulted in enhanced customer trust and reduced security incidents.

Throughout the implementation journey, several valuable lessons were learned. Collaboration and communication were highlighted as critical factors in successful SecDevOps adoption. Open dialogue between teams, continuous learning, and sharing of knowledge were instrumental in fostering a culture of security. Furthermore, automation played a pivotal role in ensuring consistent security practices and enabling faster delivery without compromising on security measures.


## The Impact of DevSecOps on SOC: Enhancing Security Collaboration

Source: [DevSecOps and SOC](https://www.linkedin.com/posts/elishlomo_informationsecurity-cybersecurity-cloudsecurity-activity-6957956550984364032-43Wv/?utm_source=share&utm_medium=member_desktop)

The integration of security into the DevOps process, known as DevSecOps, has revolutionized the way organizations approach software development and deployment. This collaborative approach not only improves the speed and efficiency of software delivery but also enhances security practices. In the realm of cybersecurity, the Security Operations Center (SOC) plays a crucial role in monitoring, detecting, and responding to security incidents. This article explores the relationship between DevSecOps and SOC, highlighting the ways in which DevSecOps can positively impact SOC operations.

Developing a Distributed SOC with DevOps Members:
Incorporating SOC members who are familiar with DevSecOps principles can greatly benefit incident response efforts. These team members possess a deep understanding of the systems and can effectively collaborate with security staff to identify vulnerabilities and threats. By bridging the gap between the SOC and DevOps, a more comprehensive and proactive security approach can be established.

Collaboration Between Threat Hunters and DevOps Team:
Threat hunters, specialized individuals responsible for proactively identifying security gaps and potential threats, can directly communicate with DevSecOps or DevOps teams. This direct line of communication allows for addressing security gaps at their core, rather than isolating threats and reporting them to management. By involving threat hunters in the development process, organizations can ensure that security is considered and implemented from the outset.

Implementing Security Best Practices:
The SOC can collaborate with specific DevSecOps development and operation groups to implement security best practices. This collaboration ensures that security considerations are integrated into the development process, reducing vulnerabilities and potential exploits. By actively involving the SOC in the implementation of security measures, organizations can benefit from their expertise in risk assessment, threat intelligence, and incident response.

SOC as an Advisory Entity:
In a DevSecOps environment, everyone involved in security should have quick access to the SOC and be an integral part of the security story. The SOC serves as an advisory entity, providing guidance, support, and expertise across the organization. By fostering a culture of open communication and knowledge sharing, organizations can strengthen their security posture and respond effectively to emerging threats.




## Simplifying DevSecOps with Dynamic Application Security Testing (DAST)

Source: [How to declutter DevSecOps with DAST](https://www.scmagazine.com/resource/application-security/how-to-declutter-devsecops-with-dast?utm_content=245701246&utm_medium=social&utm_source=linkedin&hss_channel=lcp-11680352)

DevSecOps is a crucial approach that combines development, security, and operations to ensure secure and efficient software development. However, the complexity and rapid pace of modern development environments can sometimes lead to challenges in integrating security effectively. In this article, we will explore how Dynamic Application Security Testing (DAST) can help streamline DevSecOps processes and enhance application security.

Understanding DAST:
Dynamic Application Security Testing (DAST) is a technique used to identify vulnerabilities and security flaws in applications by actively scanning and testing them during runtime. Unlike static testing, which analyzes code without execution, DAST assesses applications in real-world scenarios, simulating various attacks to uncover vulnerabilities.

Continuous Security Assessment:
One of the key benefits of DAST in the context of DevSecOps is its ability to provide continuous security assessment throughout the development lifecycle. By integrating DAST tools into the DevOps pipeline, security vulnerabilities can be identified and addressed early on, reducing the risk of exposing sensitive data or falling victim to cyberattacks.

Identifying Real-World Vulnerabilities:
DAST tools simulate real-world attack scenarios, allowing organizations to identify vulnerabilities that may not be apparent through other testing methodologies. By actively probing applications, DAST tools uncover vulnerabilities that hackers could exploit, such as injection flaws, cross-site scripting (XSS), and insecure server configurations.

Collaboration and Automation:
DAST can be seamlessly integrated into the DevSecOps workflow, enabling collaboration between developers, security teams, and operations personnel. Automation plays a vital role in DAST, as it allows for the continuous scanning of applications during the development and deployment processes. This collaboration and automation ensure that security issues are identified and resolved rapidly, reducing the time and effort required for manual testing.

Remediation and Compliance:
DAST provides actionable insights into identified vulnerabilities, allowing teams to prioritize remediation efforts based on severity. By addressing vulnerabilities early on, organizations can strengthen their overall security posture and ensure compliance with industry standards and regulations. DAST also helps organizations demonstrate due diligence in securing their applications, providing peace of mind to stakeholders and customers.



## Enhancing DevSecOps with OWASP DSOMM: A Maturity Model Perspective

Source: [DevSecOps maturity model using OWASP DSOMM](https://aniediogo.hashnode.dev/devsecops-maturity-model-using-owasp-dsomm)

DevSecOps, the integration of security practices into the software development lifecycle, has become crucial in today's fast-paced and evolving digital landscape. To effectively implement and mature DevSecOps practices, organizations can leverage frameworks and models that provide guidance and structure. In this article, we will explore the OWASP DSOMM (DevSecOps Maturity Model) and how it can help organizations enhance their DevSecOps initiatives.

Understanding the OWASP DSOMM:
The OWASP DSOMM is a comprehensive maturity model specifically designed to assess and guide organizations in implementing DevSecOps practices. It provides a framework that encompasses various dimensions of DevSecOps maturity, including governance, automation, security controls, and culture. The DSOMM model is based on the Open Web Application Security Project (OWASP) principles and focuses on aligning security practices with business objectives.

Assessing DevSecOps Maturity:
The DSOMM maturity model consists of several levels, each representing a different stage of DevSecOps maturity. These levels range from ad hoc security practices to fully integrated and automated security throughout the development lifecycle. By assessing their current maturity level using the DSOMM model, organizations can identify gaps and establish a roadmap for continuous improvement.

Building a Governance Framework:
A crucial aspect of DevSecOps maturity is the establishment of a robust governance framework. This includes defining security policies, establishing clear roles and responsibilities, and implementing effective risk management practices. The DSOMM helps organizations evaluate their governance practices, ensuring that security is integrated into decision-making processes and aligns with business objectives.

Automating Security Practices:
Automation plays a vital role in DevSecOps maturity. By automating security controls, organizations can reduce human error, enhance efficiency, and achieve consistent application security. The DSOMM emphasizes the importance of automation and guides organizations in implementing automated security testing, vulnerability scanning, and continuous monitoring throughout the software development lifecycle.

Cultivating a Security Culture:
DevSecOps is not just about implementing tools and technologies but also fostering a security-centric culture within the organization. The DSOMM recognizes the significance of creating a collaborative environment where security is everyone's responsibility. It encourages organizations to promote security awareness, provide training, and establish communication channels for sharing security knowledge and best practices.


## The Role of Threat Modeling in DevSecOps: Strengthening Security from the Ground Up


Source: [Continuous Security: Threat Modeling in DevSecOps](https://bishopfox.com/blog/threat-modeling-in-devsecops)

In the fast-paced world of software development, security is a critical concern that cannot be ignored. DevSecOps, the integration of security practices into the software development lifecycle, has emerged as a powerful approach to building secure applications. One of the key components of DevSecOps is threat modeling, a proactive technique that helps identify and address potential security threats early in the development process. In this article, we will explore the significance of threat modeling in DevSecOps and how it strengthens security from the ground up.

Understanding Threat Modeling:
Threat modeling is a systematic approach to identify, assess, and mitigate potential security threats and vulnerabilities in software applications. It involves analyzing the application's architecture, data flows, and potential attack vectors to uncover security weaknesses. By identifying and addressing these issues during the design and development phase, organizations can build robust and secure applications.

Proactive Risk Assessment:
Threat modeling enables organizations to take a proactive stance towards security by identifying potential threats and vulnerabilities before they are exploited by malicious actors. By conducting a comprehensive threat model, organizations can assess the potential impact and likelihood of various threats and prioritize security measures accordingly. This helps in allocating resources effectively and mitigating risks early in the development lifecycle.

Integration into DevSecOps:
Threat modeling seamlessly integrates into the DevSecOps approach by incorporating security considerations into the software development process from the outset. It fosters collaboration between development, security, and operations teams, ensuring that security is not an afterthought but an integral part of the development process. Threat modeling empowers organizations to embed security controls and countermeasures into the application design, architecture, and code, reducing the likelihood of vulnerabilities.

Identifying Security Design Flaws:
Through threat modeling, organizations can uncover design flaws and weaknesses in the application's architecture. By simulating potential attack scenarios and analyzing the impact on the system, teams can identify security gaps that may not be apparent during traditional code reviews or testing. This enables proactive remediation of security issues and enhances the overall security posture of the application.

Cost-Effective Security Measures:
By identifying security risks early in the development process, organizations can prioritize security efforts and allocate resources efficiently. Threat modeling helps teams focus on implementing cost-effective security measures that address the most critical threats. This approach minimizes the likelihood of expensive security breaches and reduces the need for reactive security patches or fixes down the line.


## Hard-Coding Secrets: Be Aware of the Scariest Breach for Your Organization


Source: [Continuous Security: Threat Modeling in DevSecOps](https://medium.com/flat-pack-tech/hard-coding-secrets-be-aware-of-the-scariest-breach-for-your-organization-3e858ab296f2)

In today's digital age, organizations face an ever-increasing threat of data breaches and cyberattacks. While there are various vulnerabilities that attackers exploit, one of the scariest breaches that can occur is the exposure of hard-coded secrets. Hard-coding secrets, such as passwords, API keys, and other sensitive information directly into software code, poses a significant risk to organizations. In this article, we will explore the dangers of hard-coding secrets and the steps organizations can take to mitigate this potential security nightmare.

Understanding Hard-Coded Secrets:
Hard-coding secrets refers to the practice of embedding sensitive information directly into the source code of applications. While it may seem convenient during development, it poses a severe security risk. Hard-coded secrets are easily accessible to anyone who has access to the code, including developers, third-party contractors, and potentially malicious actors. If an attacker gains access to the codebase, they can extract these secrets and exploit them for unauthorized access, data theft, or other malicious activities.

The Risks and Consequences:
The risks associated with hard-coding secrets are far-reaching and can have severe consequences for organizations. When secrets are exposed, it can lead to unauthorized access to sensitive data, compromise user accounts, and even result in financial loss or damage to the organization's reputation. Additionally, hard-coded secrets are challenging to manage and rotate, as they are directly embedded in the code, making it difficult to update them without modifying and redeploying the entire application.

Best Practices to Mitigate the Risk:
To mitigate the risks associated with hard-coded secrets, organizations should adopt the following best practices:

Use Secure Configuration Management: Store secrets in secure configuration management systems or vaults that provide encryption and access control mechanisms. These tools allow for centralized management, secure storage, and controlled access to sensitive information.

Implement Environment Variables: Utilize environment variables to store secrets and configure applications to retrieve these values at runtime. This approach separates secrets from the codebase and enables easy configuration changes without modifying the application's source code.

Employ Secrets Management Solutions: Leverage secrets management solutions that provide secure storage, rotation, and distribution of secrets. These solutions offer a more robust and scalable approach to managing sensitive information throughout the development and deployment lifecycle.

Follow Principle of Least Privilege: Limit access to secrets by following the principle of least privilege. Only provide necessary access to individuals or services, and regularly review and revoke access rights to minimize the risk of unauthorized exposure.

Continuous Security Testing:
Regularly conduct security testing, including static code analysis and dynamic application security testing (DAST), to identify and remediate any instances of hard-coded secrets. Implementing a comprehensive security testing program helps organizations identify vulnerabilities and ensure that secrets are not inadvertently embedded in the codebase.


## Hilti's DevSecOps Journey: Building Secure and Efficient Software with GitLab


Source: [How CI/CD and robust security scanning accelerated Hilti’s SDLC](https://about.gitlab.com/customers/hilti/)

DevSecOps has become a crucial practice for organizations seeking to develop secure and efficient software. Hilti, a global leader in the construction industry, has embraced DevSecOps principles and harnessed the power of GitLab to enhance its software development processes. In this article, we will explore Hilti's DevSecOps journey and how GitLab has played a pivotal role in integrating security seamlessly into their development pipeline.

Embracing DevSecOps Culture:
Hilti recognized the importance of shifting security left in the software development lifecycle. By adopting DevSecOps principles, they fostered a culture where security is an integral part of the development process from the start. This cultural shift encouraged collaboration between development, security, and operations teams, resulting in faster, more secure software delivery.

Integrated Security Tools:
GitLab's comprehensive platform provided Hilti with a wide array of built-in security features and tools. From static application security testing (SAST) and dynamic application security testing (DAST) to dependency scanning and container security, GitLab enabled Hilti to automate security checks throughout the development process. This integration allowed for early detection of vulnerabilities and ensured that security was continuously monitored and addressed.

Automated Testing and Continuous Integration:
Hilti leveraged GitLab's continuous integration capabilities to automate their testing processes. By integrating security testing into their CI/CD pipelines, they ensured that every code change was thoroughly examined for potential security issues. This approach enabled Hilti to catch vulnerabilities early on, reducing the risk of security breaches and improving the overall quality of their software.

Collaboration and Visibility:
GitLab's collaborative features allowed Hilti's teams to work seamlessly together. Developers, security professionals, and operations personnel could easily communicate and collaborate within the same platform, promoting cross-functional teamwork and knowledge sharing. Additionally, GitLab's intuitive dashboards provided clear visibility into the security posture of their projects, enabling proactive remediation of vulnerabilities.

Compliance and Governance:
As a global organization, Hilti operates in a regulated environment and must adhere to various compliance standards. GitLab's compliance management features helped Hilti streamline their compliance efforts by providing a centralized platform for managing policies, controls, and audits. This ensured that their software development practices met the necessary regulatory requirements.


## Capital One Data Breach

One notable real-world example of an attack resulting from inadequate Identity, Credential, and Access Management (ICAM) in the cloud environment is the Capital One data breach in 2019. The breach exposed the personal information of approximately 106 million customers and applicants.

In this case, the attacker exploited a misconfiguration in the web application firewall of Capital One's cloud infrastructure. The misconfiguration allowed the attacker to gain unauthorized access to a specific server and execute commands, ultimately exfiltrating sensitive customer data.

The root cause of the breach was attributed to inadequate ICAM practices, specifically related to the mismanagement of access controls and permissions. The attacker, a former employee of a cloud service provider, utilized their knowledge of the cloud infrastructure's vulnerabilities to bypass security measures.

The inadequate ICAM practices in this incident included:

1. Insufficient access controls: The misconfiguration of the web application firewall allowed the attacker to exploit a specific vulnerability and gain unauthorized access to the server.

1. Weak authentication mechanisms: The attacker was able to exploit weak authentication mechanisms to gain initial access to the cloud infrastructure.

1. Inadequate monitoring and logging: The breach went undetected for a significant period due to a lack of proper monitoring and logging practices. This delayed response allowed the attacker to access and exfiltrate data without being detected.



