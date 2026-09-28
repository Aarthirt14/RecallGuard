FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home recallguard
USER recallguard
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "recallguard.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
