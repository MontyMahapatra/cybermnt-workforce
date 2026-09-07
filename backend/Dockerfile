# NOTE: written but not runnable in the sandbox this was built in (no
# Docker available there). Build and run this yourself before trusting
# it -- see the honesty note in docker-compose.yml.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
