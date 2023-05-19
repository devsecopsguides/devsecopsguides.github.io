---
layout: default
title: Monitoring
parent: Operate
---

# Monitoring
{: .no_toc }

Monitoring in DevSecOps refers to the practice of continuously observing and analyzing an organization's IT systems, applications, and infrastructure to identify potential security issues, detect and respond to security incidents, and ensure compliance with security policies and regulations.

In DevSecOps, monitoring is a critical component of a comprehensive security strategy, allowing organizations to identify and respond to security threats quickly and effectively. Some of the key benefits of monitoring in DevSecOps include:

1. Early detection of security incidents: By continuously monitoring systems and applications, organizations can detect security incidents early on and take immediate action to remediate them.

2. Improved incident response: With real-time monitoring and analysis, organizations can respond to security incidents quickly and effectively, minimizing the impact of a potential breach.

3. Improved compliance: By monitoring systems and applications for compliance with security policies and regulations, organizations can ensure that they are meeting their security obligations.

4. Improved visibility: Monitoring provides organizations with greater visibility into their IT systems and applications, allowing them to identify potential security risks and take proactive steps to address them.

There are a variety of monitoring tools and technologies available that can be used in DevSecOps, including log analysis tools, network monitoring tools, and security information and event management (SIEM) solutions. These tools can be integrated with other DevSecOps practices, such as continuous integration and continuous deployment, to ensure that security is built into the application development lifecycle.




## Prometheus

Start the Prometheus server:

```
$ ./prometheus --config.file=prometheus.yml
```

Check Prometheus server status:


```
$ curl http://localhost:9090/-/healthy
```

Query data using PromQL:


```
http://localhost:9090/graph?g0.range_input=1h&g0.expr=up&g0.tab=0
```

## Grafana

Add Prometheus data source:


```
http://localhost:3000/datasources/new?gettingstarted
```


## Nagios

Configure Nagios server:


```
/etc/nagios3/conf.d/
```

Verify Nagios server configuration:


```
$ sudo /usr/sbin/nagios3 -v /etc/nagios3/nagios.cfg
```

## Zabbix

Configure Zabbix agent on the server: Edit the Zabbix agent configuration file /etc/zabbix/zabbix_agentd.conf to specify the Zabbix server IP address and hostname, and to enable monitoring of system resources such as CPU, memory, disk usage, and network interface. Example configuration:

```
Server=192.168.1.100
ServerActive=192.168.1.100
Hostname=web-server
EnableRemoteCommands=1
UnsafeUserParameters=1
# Monitor system resources
UserParameter=cpu.usage[*],/usr/bin/mpstat 1 1 | awk '/Average:/ {print 100-$NF}'
UserParameter=memory.usage,free | awk '/Mem:/ {print $3/$2 * 100.0}'
UserParameter=disk.usage[*],df -h | awk '$1 == $1 {print int($5)}'
UserParameter=network.in[*],cat /proc/net/dev | grep $1 | awk '{print $2}'
UserParameter=network.out[*],cat /proc/net/dev | grep $1 | awk '{print $10}'
```

Configure Zabbix server: Login to the Zabbix web interface and navigate to the "Configuration" tab. Create a new host with the same hostname as the server being monitored, and specify the IP address and Zabbix agent port. Add items to the host to monitor the system resources specified in the Zabbix agent configuration file. Example items:

* CPU usage: `system.cpu.util[,idle]`
* Memory usage: `vm.memory.size[available]`
* Disk usage: `vfs.fs.size[/,pfree]`
* Network inbound traffic: `net.if.in[eth0]`
* Network outbound traffic: `net.if.out[eth0]`

Configure triggers: Set up triggers to alert when any monitored item exceeds a certain threshold. For example, set a trigger on the CPU usage item to alert when the usage exceeds 80%.

Configure actions: Create actions to notify relevant stakeholders when a trigger is fired. For example, send an email to the web application team and the system administrators.


## Datadog

Edit the Datadog agent configuration file `/etc/datadog-agent/datadog.yaml` and add the following lines:

```
# Collect CPU metrics
procfs_path: /proc
cpu_acct: true

# Collect memory metrics
meminfo_path: /proc/meminfo
```

To view CPU and memory metrics, go to the Datadog Metrics Explorer and search for the metrics `system.cpu.usage` and `system.mem.used`.



Here are some sample commands you can use to collect CPU and memory metrics with Datadog:

To collect CPU metrics:


```
curl -X POST -H "Content-type: application/json" -d '{
    "series": [
        {
            "metric": "system.cpu.usage",
            "points": [
                [
                    '"$(date +%s)"',
                    "$(top -bn1 | grep '%Cpu(s)' | awk '{print $2 + $4}')"
                ]
            ],
            "host": "my-host.example.com",
            "tags": ["environment:production"]
        }
    ]
}' "https://api.datadoghq.com/api/v1/series?api_key=<YOUR_API_KEY>"
```


To collect memory metrics:


```
curl -X POST -H "Content-type: application/json" -d '{
    "series": [
        {
            "metric": "system.mem.used",
            "points": [
                [
                    '"$(date +%s)"',
                    "$(free -m | awk '/Mem:/ {print $3}')"
                ]
            ],
            "host": "my-host.example.com",
            "tags": ["environment:production"]
        }
    ]
}' "https://api.datadoghq.com/api/v1/series?api_key=<YOUR_API_KEY>"
```

Note that these commands assume that you have the necessary tools (`top`, `free`) installed on your system to collect CPU and memory metrics. You can customize the `metric`, `host`, and `tags` fields as needed to match your setup.




## New Relic

To install the New Relic Infrastructure agent on a Ubuntu server:


```
curl -Ls https://download.newrelic.com/infrastructure_agent/linux/apt | sudo bash
sudo apt-get install newrelic-infra
sudo systemctl start newrelic-infra
```

To install the New Relic Infrastructure agent on a CentOS/RHEL server:


```
curl -Ls https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo | sudo tee /etc/yum.repos.d/newrelic-infra.repo
sudo yum -y install newrelic-infra
sudo systemctl start newrelic-infra
```

To view CPU and memory metrics for a specific server using the New Relic API:

```
curl -X GET 'https://api.newrelic.com/v2/servers/{SERVER_ID}/metrics/data.json' \
     -H 'X-Api-Key:{API_KEY}' \
     -i \
     -d 'names[]=System/CPU/Utilization&values[]=average_percentage' \
     -d 'names[]=System/Memory/Used/Bytes&values[]=average_value' \
     -d 'from=2022-05-01T00:00:00+00:00&to=2022-05-10T00:00:00+00:00'
```




## AWS CloudWatch


1- To install the CloudWatch agent on Linux, you can use the following commands:

```
curl https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm -O
sudo rpm -i amazon-cloudwatch-agent.rpm
```

2- Configure the CloudWatch Agent to Collect Metrics


On Linux, you can create a configuration file at `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json` with the following content:


```
{
    "metrics": {
        "namespace": "CWAgent",
        "metricInterval": 60,
        "append_dimensions": {
            "InstanceId": "${aws:InstanceId}"
        },
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60,
                "totalcpu": false
            },
            "memory": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
```


On Windows, you can use the CloudWatch Agent Configuration Wizard to create a configuration file with the following settings:


```
- Choose "AWS::EC2::Instance" as the resource type to monitor
- Choose "Performance counters" as the log type
- Select the following counters to monitor:
  - Processor Information -> % Processor Time
  - Memory -> % Committed Bytes In Use
- Set the metric granularity to 1 minute
- Choose "CWAgent" as the metric namespace
- Choose "InstanceId" as the metric dimension
```

3- Start the CloudWatch Agent
Once you've configured the CloudWatch agent, you can start it on the EC2 instance using the following commands:

```
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sudo service amazon-cloudwatch-agent start
```

4- View the Metrics in CloudWatch

After a few minutes, the CloudWatch agent will start collecting CPU and memory metrics from the EC2 instance. You can view these metrics in the CloudWatch console by following these steps:

* Go to the CloudWatch console and select "Metrics" from the left-hand menu
* Under "AWS Namespaces", select "CWAgent"
* You should see a list of metrics for the EC2 instance you are monitoring, including CPU and memory usage. You can select individual metrics to view graphs and set up alarms based on these metrics.


## Azure Monitor


1- Configure the agent to collect CPU and memory metrics by adding the following settings to the agent's configuration file:


```
    {
      "metrics": {
        "performance": {
          "collectionFrequencyInSeconds": 60,
          "metrics": [
            {
              "name": "\\Processor(_Total)\\% Processor Time",
              "category": "Processor",
              "counter": "% Processor Time",
              "instance": "_Total"
            },
            {
              "name": "\\Memory\\Available Bytes",
              "category": "Memory",
              "counter": "Available Bytes",
              "instance": null
            }
          ]
        }
      }
    }
```

2- Restart the Azure Monitor agent to apply the new configuration.

3- Select the virtual machine or server that you want to view metrics for.
4- Select the CPU and memory metrics that you want to view.
5- Configure any alerts or notifications that you want to receive based on these metrics.

To collect CPU and memory metrics using Azure Monitor, you can also use the Azure Monitor REST API or the Azure CLI. Here's an example Azure CLI command to collect CPU and memory metrics:



```
az monitor metrics list --resource {resource_id} --metric-names "\Processor(_Total)\% Processor Time" "Memory\Available Bytes" --interval PT1M --start-time 2022-05-20T00:00:00Z --end-time 2022-05-21T00:00:00Z
```

This command retrieves CPU and memory metrics for a specific resource (identified by `{resource_id}`) over a one-day period (from May 20, 2022 to May 21, 2022), with a one-minute interval. You can modify the parameters to retrieve different metrics or time ranges as needed.





## Google Cloud Monitoring

1- Install the Stackdriver agent on the GCE instance. You can do this using the following command:

```
curl -sSO https://dl.google.com/cloudagents/install-monitoring-agent.sh
sudo bash install-monitoring-agent.sh
```

2- Verify that the Monitoring Agent is running by checking its service status:


```
sudo service stackdriver-agent status
```

3- In the Google Cloud Console, go to Monitoring > Metrics Explorer and select the `CPU usage` metric under the `Compute Engine VM Instance` resource type. Set the aggregation to `mean` and select the GCE instance that you created and `Click Create` chart to view the CPU usage metric for your instance.


4- To collect memory metrics, repeat step 5 but select the `Memory usage` metric instead of `CPU usage`.


## Netdata

1- In the Netdata web interface, go to the "Dashboard" section and select the "system.cpu" chart to view CPU usage metrics. You can also select the "system.ram" chart to view memory usage metrics.

2- To reduce failover using machine learning, you can configure Netdata's anomaly detection feature. In the Netdata web interface, go to the "Anomaly Detection" section and select "Add alarm".

3- For the "Detect" field, select "cpu.system". This will detect anomalies in the system CPU usage.

4- For the "Severity" field, select "Warning". This will trigger a warning when an anomaly is detected.

5- For the "Action" field, select "Notify". This will send a notification when an anomaly is detected.

6- You can also configure Netdata's predictive analytics feature to predict when a system will fail. In the Netdata web interface, go to the "Predict" section and select "Add algorithm".

7- For the "Algorithm" field, select "Autoregression". This will use autoregression to predict system behavior.

8- For the "Target" field, select "cpu.system". This will predict CPU usage.

9- For the "Window" field, select "30 minutes". This will use a 30-minute window to make predictions.

10-Finally, click "Create" to create the algorithm.

