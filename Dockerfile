FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
ARG INSTALL_TARGET=.
RUN pip install --no-cache-dir "$INSTALL_TARGET" \
    && useradd --create-home recallguard \
    && mkdir -p /home/recallguard/.cache/fastembed \
    && chown -R recallguard:recallguard /home/recallguard/.cache
USER recallguard
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "recallguard.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
