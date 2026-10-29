FROM python:3.12-slim
WORKDIR /app
COPY server.py .
RUN apt-get update && apt-get install -y iproute2 curl && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
CMD ["python3", "-u", "server.py"]
