FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies and tools
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    libffi-dev \
    python3-dev \
    nmap \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for many recon tools)
COPY --from=golang:1.21 /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Recon Tools via Go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/gf@latest

# Install ffuf
RUN go install github.com/ffuf/ffuf/v2@latest

# Install theHarvester (via pip as it is Python-based, but often requires global install)
# Note: theHarvester can be complex, for now installing via pip if available or git
RUN pip install theHarvester

# Setup GF patterns
RUN mkdir -p /root/.gf
RUN git clone https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns && \
    cp /root/Gf-Patterns/*.json /root/.gf/

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
