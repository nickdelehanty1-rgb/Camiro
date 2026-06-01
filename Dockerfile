FROM python:3.11-slim
# cache-bust: 2026-05-29
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x start.sh
EXPOSE 8080
CMD ["./start.sh"]
