import requests
import statistics

# prom service internal cluster URL
PROM_URL = "http://prometheus.collector.svc.cluster.local:9090/api/v1/query"

def get_prometheus_baseline(pid):
    # gets avg for past 30 seconds
    field = "llc_cache_misses"
    query = f'avg_over_time({field}{{pid="{pid}"}}[30s])'
    try:
        response = requests.get(PROM_URL, params={'query': query}, timeout=2)
        result = response.json()['data']['result']
        if result:
            return float(result[0]['value'][1]) # returns 30s avg
    except Exception as e:
        print(f"Baseline fetch failed: {e}")
    return None

def get_model_data(pid):
    # samples 60s worth of prometheus metrics 
    sample_time = 60
    metrics = ["llc_cache_references", "llc_cache_misses", "instructions_per_cycle", "llc_branch_ratio"]

    metric_data = {}
    for metric in metrics:
        query = f'{metric}{{pid="{pid}"}}[{sample_time}s:1s]'
        response = requests.get(PROM_URL, params={'query': query}, timeout=2)

        result = response.json()['data']['result']

        raw_data = [float(val[1]) for val in result[0]['values']]
        metric_data[metric] = raw_data
    print(metric_data)

    return metric_data

