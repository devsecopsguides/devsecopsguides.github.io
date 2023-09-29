---
layout: default
title: eBPF
parent: Checklists
---

# eBPF Security Checklist for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to eBPF for DevSecOps




### Enable eBPF hardening 

```
echo 1 > /proc/sys/net/core/bpf_jit_harden
```


### Limit eBPF program load 

```
setcap cap_bpf=e /path/to/program
```

### Restrict eBPF tracepoints access      

```
echo 0 > /proc/sys/kernel/perf_event_paranoid
```


### Use eBPF to monitor system calls 

```
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```

### Enable eBPF-based security monitoring    

```
bpftool prog load secmon.bpf /sys/fs/bpf/
```

### Limit eBPF map operations 

```
bpftool map create /sys/fs/bpf/my_map type hash key 4 value 4 entries 1024
```

### Regularly update eBPF tools and libraries

```
apt-get update && apt-get upgrade libbpf-tools
```
