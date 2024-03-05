# The builder image, used to build the virtual environment
FROM python:3.12.2-bookworm AS builder

RUN pip install poetry==1.8.1

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN touch README.md

RUN apt-get update \
    && apt-get install -y libev-dev \
    && apt-get clean \
    && poetry install --without dev --no-root --no-cache


# The runtime image, used to just run the code provided its virtual environment
FROM python:3.12.2-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PORT=8000

RUN apt-get update \
    && apt-get install -y libev4 \
    && apt-get clean

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY src ./src

EXPOSE ${PORT}

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0"]
