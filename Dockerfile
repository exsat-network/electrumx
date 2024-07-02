# Use the specified Python base image
FROM python:3.9.19-slim-bullseye
# Set environment variables
ENV COIN=Bitcoin \
    REQUEST_TIMEOUT=25 \
    DB_ENGINE=leveldb \
    SERVICES=tcp://0.0.0.0:50011,ws://:50021,rpc://:8001,http://:8081 \
    HOST="" \
    ALLOW_ROOT=true \
    CACHE_MB=400 \
    MAX_SEND=3000000 \
    COST_SOFT_LIMIT=100000 \
    COST_HARD_LIMIT=1000000 \
    REQUEST_SLEEP=100 \
    INITIAL_CONCURRENT=10 \
    ENABLE_RATE_LIMIT=false \
    END_BLOCK=839999 \
    DB_DIRECTORY=/electrumx_db

# Install necessary build tools and libraries
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    cmake \
    libsnappy-dev \
    libleveldb-dev \
    bash \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the project files into the container

COPY . /electrumx

# Change working directory
WORKDIR /electrumx

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir /electrumx_db

# Expose necessary ports
EXPOSE 50011 50021 8001 8081

# Start the ElectrumX server
CMD ["./electrumx_server"]

