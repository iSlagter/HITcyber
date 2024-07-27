# Use an official Python runtime as a parent image
FROM python:3.11

WORKDIR /app

COPY . /app


RUN pip install --no-cache-dir -r requirements.txt


EXPOSE 80


# Run app.py when the container launches
CMD ["python", "app.py"]
