FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    linux-tools-common \
    linux-tools-generic \
    curl \
    jq \
    && apt-get clean

ENV CRICTL_VERSION="v1.32.0"
RUN curl -L https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz | tar -xz -C /usr/local/bin

RUN pip install prometheus-client
RUN pip install requests

# skips binary with kernel checks throwing errors
RUN ln -sf /usr/lib/linux-tools/*/perf /usr/bin/perf 

COPY collector.py /app/collector.py
COPY crictl.yaml /etc/crictl.yaml
COPY detector.py /app/detector.py
WORKDIR /app


CMD ["python3", "collector.py"]