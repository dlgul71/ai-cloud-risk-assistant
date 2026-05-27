#!/bin/bash

cd ~/ai-cloud-risk-assistant

docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v "$(pwd)/scan_snapshots:/app/scan_snapshots" \
  -v "$(pwd)/dgs_sentinel_ai.db:/app/dgs_sentinel_ai.db" \
  -p 8501:8501 \
  dgs-sentinel-ai
