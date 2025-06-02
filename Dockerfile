# Use official Python slim image with Python 3.12
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Install build dependencies (gcc, python3-dev) needed to build some Python packages
RUN apt-get update && apt-get install -y build-essential python3-dev && rm -rf /var/lib/apt/lists/*

# Copy requirements file first (for efficient caching)
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy all your project files into the container
COPY . .

# Expose UDP port 1700 (default Semtech UDP port)
EXPOSE 1700/udp

# Run your Python server
CMD ["python", "main.py"]
