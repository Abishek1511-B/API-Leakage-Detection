FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8501 8000
# By default run Streamlit; use CMD override to run API
CMD ["streamlit", "run", "app/leakrd_model_full.py", "--server.port", "8501", "--server.headless", "true"]
