import requests
from sklearn.linear_model import LinearRegression

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
    
    return metric_data

def build_model(pid):
    metric_data = get_model_data(pid)

    # zip metrics together to create points [a, b, c] -> [refs, ipc, branch_ratio]
    X = list(zip(metric_data["llc_cache_references"], metric_data["instructions_per_cycle"], metric_data["llc_branch_ratio"]))
    y = metric_data["llc_cache_misses"] 
    
    model = LinearRegression().fit(X, y)
    print(f"Model Accuracy (R^2): {model.score(X, y):.4f}")

    return model
