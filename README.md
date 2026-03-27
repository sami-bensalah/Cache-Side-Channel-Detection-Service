# A Detector for Cache Side-Channel Attacks in Multi-tenant OpenShift Environments

A lightweight, container-native telemetry and detection system designed to intercept Last-Level Cache (LLC) Prime+Probe side-channel attacks (leveraging vulnerabilities like Spectre V1) on Red Hat OpenShift Container Platform (RHOCP).

The system uses Linux `perf` to scrape hardware Performance Monitoring Unit (PMU) metrics at the application/pod level and analyses them using a Multivariate Linear Regression model.

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

### Understanding Detector Logs
In all logs the associated [PID XXXX] is printed alongside the log title to identify the process/container that the action was carried out on.

All metric measurements for a process are signalled by [CACHE INFO] and the measured LLC Misses and References are printed
```bash 
# standard measurement log example
[CACHE INFO][PID 9206] Misses: 31985 | References: 127475
```

If an anomaly is detected by the PID's regression model the [ANOMALY DETECTED] log is printed immediately following the metric measurement [CACHE INFO] log. The pod in which the container process is running is also printed.
```bash
# anomalous measurement detected example
[ANOMALY DETECTED][PID 9206] Possibly Dangerous Cache Behaviour | POD: example-pod
```

If 20 anomalies are collected, the threshold comparison check is run and the anomalies' standard deviation is outputted:
```bash
# output of calculated StDev example
[INFO][PID 9206] Anomolous measurements\' standard deviation: 0.007073511906022402 | POD: example-pod
```

If an anomaly is cleared from attack suspection, the [CLEARED] log is printed
```bash
# attack clearance example
[CLEARED][PID 9206] Investigated signal was not an attack | POD: example-pod-b558774fc-6x4lg
```

If an attack is detected by the system the 
```bash
# attack detected example
[ATTACK DETECTED][PID 9206] Severe Cache Side Channel Attack Detected | POD: example-pod
```

When a model is rebuilt on new data the [MODEL INFO] log is outputted. It details the standard deviation of the models training set, model fit and the pod
associated with the process the model was calculated for.
```bash
# Model refresh example
[MODEL INFO][PID 9206] Model Accuracy: 0.8229 | StdDev: 11075.128347416454 | POD: example-pod
```

Full Log Example (when attack is occurring):
```bash
[MODEL INFO][PID 9206] Model Accuracy: 0.9519 | StdDev: 3869.0171826087867 | POD: hello-node-b558774fc-6x4lg
[MODEL INFO][PID 15273] Model Accuracy: 0.7618 | StdDev: 12953.516504821306 | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 80674 | References: 237072
[CACHE INFO][PID 15273] Misses: 70073 | References: 210826
[CACHE INFO][PID 15273] Misses: 99637 | References: 239306
[CACHE INFO][PID 15273] Misses: 98897 | References: 252873
[CACHE INFO][PID 15273] Misses: 86253 | References: 217084
[CACHE INFO][PID 9206] Misses: 12207 | References: 36287
[CACHE INFO][PID 15273] Misses: 88592 | References: 233882
[CACHE INFO][PID 15273] Misses: 84682 | References: 221858
[CACHE INFO][PID 15273] Misses: 83866 | References: 245035
[CACHE INFO][PID 9206] Misses: 97732 | References: 190456
[ANOMALY DETECTED][PID 9206] Possibly Dangerous Cache Behaviour | POD: hello-node-b558774fc-6x4lg
[CACHE INFO][PID 15273] Misses: 97596 | References: 257854
[CACHE INFO][PID 15273] Misses: 78393 | References: 211660
[CACHE INFO][PID 15273] Misses: 113836 | References: 280298
[CACHE INFO][PID 15273] Misses: 84918 | References: 223387
[CACHE INFO][PID 15273] Misses: 101252 | References: 245762
[CACHE INFO][PID 9206] Misses: 9410 | References: 27704
[CACHE INFO][PID 15273] Misses: 77572 | References: 217707
[CACHE INFO][PID 15273] Misses: 108434 | References: 302606
[CACHE INFO][PID 15273] Misses: 116691 | References: 307956
[CACHE INFO][PID 15273] Misses: 67114 | References: 1159656
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 9206] Misses: 7653 | References: 35132
[CACHE INFO][PID 15273] Misses: 665112 | References: 11911512
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 827077 | References: 12396528
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 687236 | References: 12183071
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 685162 | References: 11802241
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 667296 | References: 10701446
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 755567 | References: 12593628
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 603404 | References: 11427704
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 9206] Misses: 4058 | References: 14705
[CACHE INFO][PID 15273] Misses: 746156 | References: 13291393
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 747106 | References: 12305698
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 637539 | References: 11071819
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 656214 | References: 12301267
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 9206] Misses: 9818 | References: 35091
[CACHE INFO][PID 15273] Misses: 773444 | References: 12992755
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 729840 | References: 12895807
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 780864 | References: 12705857
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 817381 | References: 12452761
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 780220 | References: 11817141
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 781485 | References: 12009119
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 15273] Misses: 834653 | References: 9761723
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[CACHE INFO][PID 9206] Misses: 9546 | References: 28169
[CACHE INFO][PID 15273] Misses: 735982 | References: 12396467
[ANOMALY DETECTED][PID 15273] Possibly Dangerous Cache Behaviour | POD: spectre-victim-68d48f9c-55hkp
[INFO][PID 15273] Anomolous measurements' standard deviation: 0.007073511906022402 | POD: spectre-victim-68d48f9c-55hkp
[ATTACK DETECTED][PID 15273] Severe Cache Side Channel Attack Detected | POD: spectre-victim-68d48f9c-55hkp
```