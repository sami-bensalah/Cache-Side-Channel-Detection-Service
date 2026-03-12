import subprocess
import re
import json
import time
from prometheus_client import start_http_server, Gauge

import detector

def get_llc_misses(pid):
    cmd = ["perf", "stat", "-e", "cache-misses,cache-references", "-p",str(pid), "sleep", "1"]
    output = subprocess.run(cmd, capture_output=True, text=True).stderr
    
    if "<not counted>" in output:
        print(f"[PID {pid}] Warning: no metrics collected (<not counted>)")
        return -1
    
    miss_match = re.search(r'([\d,]+)\s+cache-misses', output)
    ref_match = re.search(r'([\d,]+)\s+cache-references', output)

    if miss_match and ref_match:
        misses = int(miss_match.group(1).replace(',', ''))
        refs = int(ref_match.group(1).replace(',', ''))
        
        print(f"[PID {pid}] Misses: {misses}, References: {refs}")
        return [misses, refs]
    else:
        print(f"[PID {pid}] Error: error in fetching cache metrics for pid {pid}")
        return -1


def get_pids(namespaces):
    all_pids  = []
    try:
        for n in namespaces:
            print("CHECKING NAMESPACE: "+n)
            # gets pod ids
            pod_cmd = ["crictl", "pods", "-q", "--namespace", n] # gets all pod ids in a namespace
            cmd_output = subprocess.run(pod_cmd, capture_output=True, text=True).stdout
            pod_ids = cmd_output.splitlines()
            if(len(pod_ids) == 0):
                print("NO RUNNING PODS FOUND")
                continue
            for pod_id in pod_ids:
                #print("POD ID:"+pod_id)
                # gets container ids in pod
                cntr_cmd = ["crictl", "ps", "--pod", pod_id, "-q"]
                cntr_output = subprocess.run(cntr_cmd, capture_output=True, text=True).stdout
                container_ids = cntr_output.strip().splitlines()
                for container_id in container_ids:
                    # gets pid of each container
                    #print("CONTAINER ID:"+container_id)
                    pid_cmd = ["crictl", "inspect", container_id]
                    pids = subprocess.run(pid_cmd, capture_output=True, text=True).stdout
                    js = json.loads(pids)
                    pid = js["info"]["pid"]
                    print("PID:"+str(pid))
                    all_pids.append(str(pid))

        return all_pids
    except Exception as e:
        error = "ERROR: "+str(e)
        print(error)
        return -1
    

# prom metrics - metric name, description, label
LLC_MISSES = Gauge('llc_cache_misses', 'LLC misses per PID', ['pid'])
LLC_REFS = Gauge('llc_cache_references', 'LLC references per PID', ['pid'])

start_http_server(8000) # start metric server
print("prometheus client started on port 8000")

monitored_namespaces = ["test-space", "spectre-victim"] # namespaces to monitor

while(1):
    pids = get_pids(monitored_namespaces)
    if pids == -1:
        break
    if pids == []:
        print("no pods to track in the targeted namespace")
    for pid in pids:
        metrics = get_llc_misses(pid)
        if metrics != -1:
            misses = metrics[0]
            references = metrics[1]
            
            pid_miss_avg = detector.get_prometheus_baseline(pid)
            if pid_miss_avg is not None:
                if pid_miss_avg < misses:
                    print(f"[PID {pid}] HIGHER CACHE MISS MEASUREMENT THAN AVG: {pid_miss_avg} < {misses}")
            else:
                print(f"Waiting for baseline data for PID {pid}...")

            LLC_MISSES.labels(pid=pid).set(misses)
            LLC_REFS.labels(pid=pid).set(references)

