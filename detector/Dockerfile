FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    linux-tools-common \
    linux-tools-generic \
    curl \
    jq

ENV CRICTL_VERSION="v1.32.0"
RUN curl -L https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz | tar -xz -C /usr/local/bin

COPY collector.py /app/collector.py
COPY crictl.yaml /etc/crictl.yaml
WORKDIR /app

RUN mkdir -p /app/output

# fixes permission issues in cluster
RUN chgrp -R 0 /app/output && \
    chmod -R g=u /app/output 

CMD ["python3", "collector.py"]