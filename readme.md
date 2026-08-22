# FastAPI Auth & CI/CD Pipeline

A robust, production-ready FastAPI authentication microservice featuring JWT-based access/refresh token rotation and a fully automated Continuous Integration/Continuous Deployment (CI/CD) pipeline.

## 🚀 Features
*   **Secure Authentication:** Login, registration, and logout flows using `OAuth2PasswordBearer`.
*   **Token Management:** Short-lived access tokens (15 min) and long-lived refresh tokens (7 days) via PyJWT.
*   **Session Revocation:** In-memory fallback (simulating Redis) to blocklist revoked tokens upon logout.
*   **Automated Testing:** Comprehensive Pytest suite with mocked dependencies for isolated CI testing.
*   **Dockerized:** Multi-stage Dockerfile optimized for caching and lightweight production deployment.
*   **CI/CD Pipeline:** GitHub Actions workflow that automates linting (flake8), testing, Docker builds, and zero-downtime deployment to Render.

## 🛠️ Tech Stack
*   **Backend:** FastAPI, Python 3.10+, PyJWT, bcrypt
*   **DevOps:** Docker, GitHub Actions, Render
*   **Testing:** Pytest

## 💻 Local Setup
1. Clone the repository: `git clone <your-repo-url>`
2. Create a virtual environment: `python -m venv venv` and activate it.
3. Install dependencies: `pip install -r requirements.txt`
4. Run the server: `uvicorn main:app --reload`
5. Visit the interactive API docs at `http://localhost:8000/docs`