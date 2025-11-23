# Step 1: Start with our secure, patched base image
FROM python:3.10.16

# Step 2: Set the working directory
WORKDIR /app

# Step 3: (NEW) Install system-level build tools needed by numpy/scikit-learn
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

# Step 4: Copy the requirements file
COPY requirements.txt .

# Step 5: Install all the Python libraries (this will work now)
RUN pip install -r requirements.txt

# Step 6: Copy all your project files
COPY . .

# Step 7: Tell Docker your app runs on port 5000
EXPOSE 5000

# Step 8: The command to run your app
CMD ["flask", "run", "--host=0.0.0.0"]