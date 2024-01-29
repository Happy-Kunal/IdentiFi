FROM python:3.12.1-alpine3.19

WORKDIR /app

# event loop for cassandra-driver
RUN apk --no-cache add libev

# installing cassandra-driver from source
RUN apk --no-cache add build-base libffi-dev python3-dev libev-dev curl \
    && curl -sL https://github.com/datastax/python-driver/archive/refs/tags/3.29.0.tar.gz | tar xz \
    && pip install ./python-driver* \
    && rm -rf ./python-driver* \    
    && apk del build-base libffi-dev python3-dev libev-dev curl

COPY requirements.txt .

RUN pip --no-cache-dir install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0"]
