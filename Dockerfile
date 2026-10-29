FROM python:3.12-slim
WORKDIR /app
COPY server.py .
RUN apt-get update && apt-get install -y iproute2 curl dnsutils net-tools && rm -rf /var/lib/apt/lists/*
ARG CACHEBUST=2
EXPOSE 8080
CMD ["python3", "-u", "server.py"]
