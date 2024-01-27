FROM python:3.8.18-alpine3.19


WORKDIR /app

COPY requirements.txt .
RUN apk add --no-cache build-base libffi-dev && \
    pip install -r requirements.txt --no-cache-dir && \
    apk del build-base libffi-dev

COPY . .

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0"]
