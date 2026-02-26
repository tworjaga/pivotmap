# PivotMap - Attack Path Intelligence Engine
# Docker image for containerized deployment

FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIVOTMAP_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Install pivotmap
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 pivotmap && chown -R pivotmap:pivotmap /app
USER pivotmap

# Expose API port
EXPOSE 8000

# Default command
CMD ["uvicorn", "pivotmap.api:app", "--host", "0.0.0.0", "--port", "8000"]
