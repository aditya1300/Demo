# Use the official Python image as the base image
FROM python:3.11.4

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the contents of the Python_project directory into the container at /app
COPY . . 

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app