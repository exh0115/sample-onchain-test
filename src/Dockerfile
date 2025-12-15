FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY tdx_onchain_demo.py .

CMD ["python3", "tdx_onchain_demo.py"]
