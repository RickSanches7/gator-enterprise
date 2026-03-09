FROM python:3.11-slim-bookworm
LABEL maintainer="GATOR CyberSec Solutions <GatorSupport@ya.ru>"
LABEL version="2.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap whois dnsutils iputils-ping netcat-openbsd curl wget unzip \
    openssl gcc g++ libpq-dev libffi-dev libssl-dev git procps \
    perl libnet-ssleay-perl && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

RUN pip install --no-cache-dir sqlmap

RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    && tar -xzf gobuster_Linux_x86_64.tar.gz gobuster \
    && mv gobuster /usr/local/bin/ \
    && rm -f gobuster_Linux_x86_64.tar.gz

RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz ffuf \
    && mv ffuf /usr/local/bin/ \
    && rm -f ffuf_2.1.0_linux_amd64.tar.gz

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.4/nuclei_3.1.4_linux_amd64.zip \
    && unzip -o -j nuclei_3.1.4_linux_amd64.zip nuclei -d /usr/local/bin \
    && rm -f nuclei_3.1.4_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip -o -j subfinder_2.6.6_linux_amd64.zip subfinder -d /usr/local/bin \
    && rm -f subfinder_2.6.6_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip \
    && unzip -o -j httpx_1.3.7_linux_amd64.zip httpx -d /usr/local/bin \
    && rm -f httpx_1.3.7_linux_amd64.zip

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports/output /app/logs /app/tmp

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --loop uvloop"]
