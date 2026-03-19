import subprocess
import re
import json
import time
import os
from prometheus_client import start_http_server, Gauge
from sklearn.linear_model import LinearRegression # type: ignore
import statistics
import collections
from concurrent.futures import ThreadPoolExecutor

import detector


POD_START_TIME = time.time()

def get_llc_metrics(pid):
    cmd = ["perf", "stat", "-e", "cache-misses,cache-references,branch-loads,branch-misses,cycles,instructions", "-p",str(pid), "sleep", "1"]
    output = subprocess.run(cmd, capture_output=True, text=True).stderr
    
    if "<not counted>" in output:
        #print(f"[PID {pid}] Warning: no metrics collected (<not counted>)", flush=True)
        return -1
    
    # gets llc miss / refs
    miss_match = re.search(r'([\d,]+)\s+cache-misses', output)
    ref_match = re.search(r'([\d,]+)\s+cache-references', output)

    # gets branch misses / loads
    b_miss_match = re.search(r'([\d,]+)\s+branch-misses', output)
    b_loads_match = re.search(r'([\d,]+)\s+branch-loads', output)

    # gets cpu cycles / instructions
    instructions_match = re.search(r'([\d,]+)\s+instructions', output)
    cycles_match = re.search(r'([\d,]+)\s+cycles', output)

    # parses and gets val
    if miss_match and ref_match and b_miss_match and b_loads_match:
        misses = int(miss_match.group(1).replace(',', ''))
        refs = int(ref_match.group(1).replace(',', ''))
        
        b_misses = int(b_miss_match.group(1).replace(',', ''))
        b_loads = int(b_loads_match.group(1).replace(',', ''))

        instructions = int(instructions_match.group(1).replace(',', ''))
        cycles = int(cycles_match.group(1).replace(',', ''))

        print(f"[PID {pid}] Misses: {misses}, References: {refs}", flush=True)
        return [misses, refs, b_misses, b_loads, instructions, cycles]
    else:
        print(f"[PID {pid}] Error: error in fetching cache metrics for pid {pid}", flush=True)
        return -1


def get_pids(namespaces):
    all_pids  = []
    try:
        for n in namespaces:
            #print("CHECKING NAMESPACE: "+n)
            # gets pod ids
            pod_cmd = ["crictl", "pods", "-q", "--namespace", n] # gets all pod ids in a namespace
            cmd_output = subprocess.run(pod_cmd, capture_output=True, text=True).stdout
            pod_ids = cmd_output.splitlines()
            if(len(pod_ids) == 0):
                #print("NO RUNNING PODS FOUND")
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
                    #print("PID:"+str(pid))
                    all_pids.append(str(pid))

        return all_pids
    except Exception as e:
        error = "ERROR: "+str(e)
        print(error)
        return -1
    

def collect_detect(pid, minute):
    metrics = get_llc_metrics(pid) # get metrics
    if metrics != -1:
        misses = metrics[0]
        references = metrics[1]
        b_misses = metrics[2]
        b_loads = metrics[3]
        instructions = metrics[4]
        cycles = metrics[5]
        
        cache_ratio = misses/references
        branch_ratio = b_misses/b_loads
        i_per_c = instructions/cycles

        # if pid has model and collector is older than 1 min
        if minute > 0 and pid in curr_models:
            vals = [references, i_per_c, branch_ratio]

            # check if current metrics readings are anomalous
            if detector.is_anomaly(vals, curr_models[pid], curr_stdevs[pid], misses):
                print(f"[PID {pid}][ANOMALY DETECTED] Possibly Dangerous Cache Behaviour", flush=True)
                pid_anomalies[pid].append(cache_ratio)
                remodel_status[pid] = False # block new model from being generated
                pid_anomaly_count[pid] += 1
                pid_non_anomaly_count[pid] = 0
            elif remodel_status[pid] == False:
                # if readings are normal add to counter to free current model block
                pid_non_anomaly_count[pid] += 1

            if pid_non_anomaly_count[pid] > 10:
                # if 10 normal readings recorded in a row continue as normal 
                print(f"[PID {pid}][CLEARED] Investigated signal was not an attack", flush=True)
                remodel_status[pid] = True
                pid_anomalies[pid] = []
                pid_non_anomaly_count[pid] = 0
                pid_anomaly_count[pid] = 0
            
            if pid_anomaly_count[pid] >= 20:
                # if more than 20 anomalous recordings calc stdev and check consistency
                stdev = statistics.stdev(pid_anomalies[pid])
                print(f"[PID {pid}] Anomolous measurements's standard deviation: {stdev}")
                if float(stdev) < 0.01:
                    print(f"[PID {pid}][ATTACK DETECTED] Severe Cache Side Channel Attack Detected", flush=True)
                    os._exit(1)
                else:
                    # anomalous readings were not caused by side channel attack
                    print(f"[PID {pid}][CLEARED] Investigated signal was not an attack", flush=True)
                    remodel_status[pid] = True
                    pid_anomalies[pid] = []
                    pid_non_anomaly_count[pid] = 0
                    pid_anomaly_count[pid] = 0

                    curr_models[pid], curr_stdevs[pid] = detector.build_model(pid)
        else:
            print(f"[PID {pid}] No Model Available Yet", flush=True)

        # push readings into prom
        LLC_MISSES.labels(pid=pid).set(misses)
        LLC_REFS.labels(pid=pid).set(references)
        LLC_RATIO.labels(pid=pid).set(cache_ratio)

        LLC_B_MISSES.labels(pid=pid).set(b_misses)
        LLC_B_LOADS.labels(pid=pid).set(b_loads)
        LLC_B_RATIO.labels(pid=pid).set(branch_ratio)

        I_COUNT.labels(pid=pid).set(instructions)
        CYCLES.labels(pid=pid).set(cycles)
        I_PER_C.labels(pid=pid).set(i_per_c)


# prom metrics - metric name, description, label
LLC_MISSES = Gauge('llc_cache_misses', 'LLC misses per PID', ['pid'])
LLC_REFS = Gauge('llc_cache_references', 'LLC references per PID', ['pid'])
LLC_RATIO =  Gauge('llc_ratio', 'ratio of misses:refs per PID', ['pid'])

LLC_B_MISSES = Gauge('llc_branch_misses', 'LLC branch misses per PID', ['pid'])
LLC_B_LOADS = Gauge('llc_branch_loads', 'LLC branch loads per PID', ['pid'])
LLC_B_RATIO =  Gauge('llc_branch_ratio', 'ratio of branch-misses:branch-loads per PID', ['pid'])

I_COUNT = Gauge('intruction_count', 'number of instructions executed for PID', ['pid'])
CYCLES = Gauge('cycle_count', 'number of cpu cycles executed', ['pid'])
I_PER_C = Gauge('instructions_per_cycle', 'ratio of instructions:cycles for pid', ['pid'])

start_http_server(8000) # start metric server
print("prometheus client started on port 8000")

# fetches config from file mounted to container
with open('collector-config/perf-config', 'r') as file:
    monitored_namespaces = [line.strip() for line in file]
print(f"Namespaces Monitored: {monitored_namespaces}") # namespaces to monitor

prev_min = 0
curr_models = {}
curr_stdevs = {}

remodel_status = collections.defaultdict(lambda: True)

pid_anomalies = collections.defaultdict(list)

pid_anomaly_count = collections.defaultdict(int)
pid_non_anomaly_count = collections.defaultdict(int)


while(1):
    pids = get_pids(monitored_namespaces)
    if pids == -1:
        break
    if pids == []:
        print("no pods to track in the targeted namespace")
    else:
        # runs model rebuild every 60s
        uptime = time.time() - POD_START_TIME
        minute = uptime // 60

        # builds new models
        for pid in pids:
            if minute > prev_min and remodel_status[pid] == True:
                curr_models[pid], curr_stdevs[pid] = detector.build_model(pid)
        prev_min = minute

        # run thread for each pid
        with ThreadPoolExecutor(max_workers=(len(pids))) as executor:
            executor.map(lambda p: collect_detect(p, minute), pids)