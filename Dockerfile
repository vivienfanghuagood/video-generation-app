FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -i https://pypi.org/simple -r requirements.txt && apt update &&  apt install -y --no-install-recommends git curl gcc python3-dev libffi-dev libssl-dev
COPY main.py .
COPY templates ./templates
ENV PYTHONUNBUFFERED=1
EXPOSE 8088
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]
