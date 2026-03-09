import requests
import statistics

# prom service internal cluster URL
PROM_URL = "http://prometheus.collector.svc.cluster.local:9090/api/v1/query"

def get_prometheus_baseline(pid):
    # gets avg for past 30 seconds
    query = f'avg_over_time(llc_cache_misses{{pid="{pid}"}}[30s])'
    try:
        response = requests.get(PROM_URL, params={'query': query}, timeout=2)
        result = response.json()['data']['result']
        if result:
            return float(result[0]['value'][1]) # returns 30s avg
    except Exception as e:
        print(f"Baseline fetch failed: {e}")
    return None


