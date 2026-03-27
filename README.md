# Multi-Tenant RHOCP Side-Channel Detector

A lightweight, container-native telemetry and detection system designed to intercept Last-Level Cache (LLC) Prime+Probe side-channel attacks (leveraging vulnerabilities like Spectre V1) on Red Hat OpenShift Container Platform (RHOCP).

The system uses Linux `perf` to scrape hardware Performance Monitoring Unit (PMU) metrics at the application/pod level and analyzes them using Multivariate Linear Regression without intercepting tenant data.

---

## System Architecture

The system consists of two primary components deployed within a single administration namespace named 'collector':

1. **Perf-Collector/Detector (Python):** - Scans target namespaces using the `crictl` interface.
   - Aggregates hardware metrics (`perf stat`) per container PID.
   - Exposes metrics via a Prometheus `/metrics` HTTP endpoint.
   - Constantly trains a local linear regression model and runs standard deviation checks to isolate anomalies.
2. **Prometheus Database:** - Scrapes metrics from the collector every 1 second.
   - Provides PromQL historical lookbacks for standard deviation thresholds and regression training.

---

## Deployment & Execution Run-Book
Install OpenShift Local v4.19.8 (from https://console.redhat.com/openshift/create/local), start the cluster and login as an admin

Create the two following namespaces:
```bash
# detector and collector namespace
oc new-project collector

# victim namespace
oc new-project spectre-victim
```

### 0. Build Victim and Detector images
Build the images below and add them to the Red Hat OpenShift Image registry

Build Images:
```bash
# build detector image
podman build detector/Dockerfile --tag perf-collector

# build victim image
podman build victim-service/Dockerfile --tag victim
```
Add to RHOCP Image Registry:
```bash
# store login token to env var
TOKEN=$(oc whoami -t)

# copy detector image into RHOCP registry
podman unshare skopeo copy \
  containers-storage:localhost/perf-collector:latest \
  docker://default-route-openshift-image-registry.apps-crc.testing/collector/perf-collector:latest \
  --dest-creds developer:$TOKEN\
  --dest-tls-verify=false

# copy victim image into RHOCP registry
podman unshare skopeo copy \
  containers-storage:localhost/victim:latest \
  docker://default-route-openshift-image-registry.apps-crc.testing/spectre-victim/victim:latest \
  --dest-creds developer:$TOKEN\
  --dest-tls-verify=false
```

### 1. Cluster & Defensive Setup
Set up the monitoring namespace, Prometheus time-series DB, and the Python collector/detector.

```bash
# 1. Create Service Account and bind Privileged SCC (Required for hardware perf metrics)
oc create sa collector-sa -n collector
oc adm policy add-scc-to-user privileged -z collector-sa -n collector

# 2. Create ConfigMaps
oc create cm prom-config --from-file=detector/config-files/prometheus.yml -n collector
oc create cm perf-config --from-file=detector/config-files/perf-config -n collector

# 3. Create Deployments
oc create -f detector/config-files/collector.yaml -n collector
oc create -f detector/config-files/prom-deployment.yaml -n collector

# 4. Expose internal services
oc expose deployment/perf-collector --port 8000 --name perf-collector-svc -n collector
oc expose deployment/prometheus --port 9090 -n collector
```

### 2. Deploying the Spectre-Victim Workload
Deploy the vulnerable HTTP session-token server.

```bash
# 1. Create Service Account and bind Privileged SCC
oc create sa spectre-victim-sa -n spectre-victim
oc adm policy add-scc-to-user privileged -z spectre-victim-sa -n spectre-victim

# 2. Allocate Hugepages on the CRC bare-metal node (Required for cache probes)
oc debug node/crc -- chroot /host sh -c "sudo sysctl -w vm.nr_hugepages=6 && sudo systemctl restart kubelet"

# 3. Deploy the victim server
oc create -f spectre-victim.yaml -n spectre-victim

# 4. Port-forward the victim pod to your local loopback to execute the HTTP attack
# (Find your pod name using: oc get pods -n spectre-victim)
oc port-forward pod/<victim-pod-name> 8080:8080 -n spectre-victim
```

### 3. Cross-Tenant Attack on Cluster Services (via HTTP)
Ensure the spectre-victim deployment is running and port forwarded to 8080
```bash
# 1. Compile binaries
make all

# 2. Execute Prime+Probe attack using isolated Core 8 and FIFO real-time scheduler
sudo chrt -f 99 taskset -c 8 ./cloud-attacker <ATTACK_ID> <TARGET_BYTE>
```

### 4. Native Attack on Server (Local Bare-Metal Isolation)
It is recommended to isolate two cores to maximize Prime+Probe signal stability. In this example, Core 2 and Core 8 are used.
```bash 
# 1. Compile binaries
make all

# 2. Run the server pinned to Core 2
sudo taskset -c 2 ./victim-service

# 3. Run the attack pinned to Core 8
sudo chrt -f 99 taskset -c 8 ./llc-attacker <ATTACK_ID> <TARGET_BYTE>
```

### Viewing Detector Logs
Detector logs can be viewed by using the following commands within the RHOCP cluster
```bash
# find the collector deployment's pod name 
oc get pods -n collector

# get the pods live log output
oc logs -f <POD_NAME> -n collector
```

### Viewing Prometheus Metrics  
To view prometheus' UI we need to expose the internal service as a route

```bash
# create route
oc expose svc prometheus -n collector

# find the route's host path
oc get routes -n collector
```

It will look something like 'prometheus-collector.apps-crc.testing', enter this into your browser to access the prometheus web app and view live metrics

