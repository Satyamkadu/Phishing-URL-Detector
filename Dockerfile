# Step 1: Start with an official Python base image
FROM python:3.10.13

# Step 2: Set the "working directory" inside the container
WORKDIR /app

# Step 3: Copy the requirements file into the container
COPY requirements.txt .

# Step 4: Install all the Python libraries
RUN pip install -r requirements.txt

# Step 5: Copy all your project files into the container
# (app.py, model file, templates/, static/, etc.)
COPY . .

# Step 6: Tell Docker that your app runs on port 5000
EXPOSE 5000

# Step 7: The command to run your app when the container starts
CMD ["flask", "run", "--host=0.0.0.0"]