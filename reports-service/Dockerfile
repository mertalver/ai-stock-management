# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy shared utilities first, if they exist
COPY shared/ /app/shared/
COPY utils/ /app/utils/

# Copy the requirements file and install dependencies
COPY reports-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application's code from its specific directory
COPY reports-service/ .

# Make port 5004 available to the world outside this container
EXPOSE 5004

# Run app.py when the container launches
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5004", "app:app"] 