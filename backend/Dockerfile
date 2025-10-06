FROM python:3.11-slim-bullseye

# Install git and wkhtmltopdf runtime dependencies so pdfkit can generate PDFs
# Note: wkhtmltopdf may require several X/font libraries in slim images
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	   git \
	   wkhtmltopdf \
	   libxrender1 \
	   libxext6 \
	   libfontconfig1 \
	   libxcb1 \
	   xfonts-75dpi \
	   xfonts-base \
	&& rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Set Python path
ENV PYTHONPATH=/app

# Default command (will be overridden by docker-compose for celery worker)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]