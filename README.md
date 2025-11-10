# Phishing URL Detector API

This project is a complete, end-to-end machine learning application that detects phishing URLs. It consists of a Python backend API (built with Flask) that serves a trained Random Forest model.

This API is the "brain" for the [Phishing Detector Chrome Extension](https://github.com/Satyamkadu/phishing-url-extension) (<- *Link to your other repo here!*).



---

## Features

* **ML Model:** A Random Forest classifier trained on 10,000+ URLs with 95%+ accuracy.
* **API Server:** A Flask app that serves the model and returns predictions in JSON format.
* **Web Interface:** A simple HTML/CSS frontend for direct URL testing.
* **Containerized:** Fully containerized with Docker for easy deployment and scalability.

---

## Technologies Used

* **Backend:** Python, Flask, Flask-CORS
* **Data Science:** Pandas, Scikit-learn, Joblib
* **Deployment:** Docker

---

## How to Run This Project

You can run this project in two ways: locally with Python or as a Docker container.

### 1. Running with Docker (Recommended)

This is the simplest way to run the application.

1.  **Build the Docker image:**
    ```bash
    docker build -t phishing-detector .
    ```

2.  **Run the container:**
    ```bash
    docker run -d -p 5000:5000 --name phishing-app phishing-detector
    ```

The app will be running at `http://127.0.0.1:5000`.

### 2. Running Locally with Python

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Satyamkadu/Phishing-URL-Detector.git](https://github.com/Satyamkadu/Phishing-URL-Detector.git)
    cd PRO-PHISHING
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv proPhish
    .\proPhish\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the app:**
    ```bash
    flask run
    ```

The app will be running at `http://127.0.0.1:5000`.