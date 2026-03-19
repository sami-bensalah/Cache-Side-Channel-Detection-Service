import subprocess
import re
import json
import time
from prometheus_client import start_http_server, Gauge
from sklearn.linear_model import LinearRegression # type: ignore
import statistics

import detector

POD_START_TIME = time.time()


def get_llc_misses(pid):
    cmd = ["perf", "stat", "-e", "cache-misses,cache-references,branch-loads,branch-misses,cycles,instructions", "-p",str(pid), "sleep", "1"]
    output = subprocess.run(cmd, capture_output=True, text=True).stderr
    
    if "<not counted>" in output:
        print(f"[PID {pid}] Warning: no metrics collected (<not counted>)")
        return -1
    
    miss_match = re.search(r'([\d,]+)\s+cache-misses', output)
    ref_match = re.search(r'([\d,]+)\s+cache-references', output)

    b_miss_match = re.search(r'([\d,]+)\s+branch-misses', output)
    b_loads_match = re.search(r'([\d,]+)\s+branch-loads', output)

    instructions_match = re.search(r'([\d,]+)\s+instructions', output)
    cycles_match = re.search(r'([\d,]+)\s+cycles', output)

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
        print(f"[PID {pid}] Error: error in fetching cache metrics for pid {pid}")
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

monitored_namespaces = ["test-space", "spectre-victim"] # namespaces to monitor

prev_min = 0
curr_model = None
curr_stdev = 0

remodel = True
anomaly_ratios = []
anomaly_count = 0
non_anomaly = 0
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
            b_misses = metrics[2]
            b_loads = metrics[3]
            instructions = metrics[4]
            cycles = metrics[5]
            
            cache_ratio = misses/references
            branch_ratio = b_misses/b_loads
            i_per_c = instructions/cycles

            # runs model rebuild every 60s
            uptime = time.time() - POD_START_TIME
            minute = uptime // 60
            if minute > prev_min and remodel == True:
                curr_model, curr_stdev = detector.build_model(pid)
                prev_min = minute
            
            if minute > 0:
                vals = [references, i_per_c, branch_ratio]
                if detector.is_anomaly(vals, curr_model, curr_stdev, misses):
                    print("[ANOMALY DETECTED] Possibly Dangerous Cache Behaviour", flush=True)
                    anomaly_ratios.append(cache_ratio)
                    remodel = False
                    anomaly_count += 1
                    non_anomaly = 0
                elif remodel == False:
                    non_anomaly += 1

                if non_anomaly > 10:
                    print("[CLEARED] Investigated signal was not an attack", flush=True)
                    remodel = True
                    non_anomaly = 0
                    anomaly_ratios = []
                    anomaly_count = 0
                
                if anomaly_count == 20:
                    stdev = statistics.stdev(anomaly_ratios)
                    print(f"Anomolous measuremnnts standard deviation: {stdev}")
                    if float(stdev) < 0.01:
                        print("[ATTACK DETECTED] Severe Cache Side Channel Attack Detected", flush=True)
                        exit(1)
                    else:
                        print("[CLEARED] Investigated signal was not an attack", flush=True)
                        remodel = True
                        non_anomaly = 0
                        anomaly_ratios = []
                        anomaly_count = 0

            LLC_MISSES.labels(pid=pid).set(misses)
            LLC_REFS.labels(pid=pid).set(references)
            LLC_RATIO.labels(pid=pid).set(cache_ratio)

            LLC_B_MISSES.labels(pid=pid).set(b_misses)
            LLC_B_LOADS.labels(pid=pid).set(b_loads)
            LLC_B_RATIO.labels(pid=pid).set(branch_ratio)

            I_COUNT.labels(pid=pid).set(instructions)
            CYCLES.labels(pid=pid).set(cycles)
            I_PER_C.labels(pid=pid).set(i_per_c)