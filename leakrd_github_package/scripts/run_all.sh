#!/bin/bash
# Run FastAPI and Streamlit locally (for development).
uvicorn api.leakrd_api:app --port 8000 --reload &
uvicorn_pid=$!
echo "Started FastAPI (pid $uvicorn_pid)"
streamlit run app/leakrd_model_full.py --server.headless true
# Cleanup
kill $uvicorn_pid || true
