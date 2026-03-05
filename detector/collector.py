import subprocess
import re
import json
import time

def get_llc_misses(pid):
    cmd = ["perf", "stat", "-e", "LLC-load-misses", "-p",str(pid), "sleep", "0.1"]
    output = subprocess.run(cmd, capture_output=True, text=True).stderr

    match = re.search(r'([\d,]+)\s+LLC-load-misses', output)
    count = int(match.group(1).replace(',', ''))
    print(count)


def get_pids(namespaces):
    all_pids  = []
    f = open("out.txt", "w")
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
                print("POD ID:"+pod_id)
                # gets container ids in pod
                cntr_cmd = ["crictl", "ps", "--pod", pod_id, "-q"]
                cntr_output = subprocess.run(cntr_cmd, capture_output=True, text=True).stdout
                container_ids = cntr_output.strip().splitlines()
                for container_id in container_ids:
                    # gets pid of each container
                    print("CONTAINER ID:"+container_id)
                    pid_cmd = ["crictl", "inspect", container_id]
                    pids = subprocess.run(pid_cmd, capture_output=True, text=True).stdout
                    js = json.loads(pids)
                    pid = js["info"]["pid"]
                    print("PID:"+str(pid))
                    all_pids.append(str(pid))

        f.write("\n".join(all_pids)+"\n")
        f.close()
    except Exception as e:
        error = "ERROR: "+str(e)
        print(error)
        f.close()


monitored_namespaces = ["test-space"] # namespaces to monitor

get_pids(monitored_namespaces)
