# Stock Management Microservices

A **Stock Management System** built with **Python Microservices
Architecture**.
The project implements modular services for user management, product
inventory, admin control, reporting, and an API gateway.
Each service runs independently and communicates over REST APIs.
The system also integrates **LLM-powered stock operations** (Gemini API)
and supports CSV-based data generation.

------------------------------------------------------------------------

## ✨ Features

-   👥 **User & Admin Management**: Registration, login, profile
    management with JWT authentication.
-   📦 **Product Management**: Add, update, delete, and monitor stock
    levels.
-   🚨 **Critical Stock Alerts**: Detect and flag products below
    threshold.
-   📊 **Reports Service**: Track stock movements per user/admin,
    statistics, and monthly trends.
-   🤖 **LLM Integration**: Natural language commands (e.g., “Add 10 pens”) are processed 
    via Gemini API and automatically applied to the database (add/update/delete).
-   📝 **Logging Service**: System, activity, and stock movement
    logs.
-   🗄 **Database**: SQLite (with shared module for
    connections).
-   🐳 **Dockerized Deployment**: Each microservice has its own
    Dockerfile.
-   📂 **CSV Export/Import**: Generate initial stock lists with random
    values.
-   🔑 **Security**: SHA-256 password hashing, JWT-based sessions.

------------------------------------------------------------------------

## 🛠 System Architecture

-   **API Gateway** → Routes requests to underlying
    services.
-   **Users Service** → Handles authentication, registration, profile,
    and LLM integration.
-   **Products Service** → Manages inventory operations.
-   **Admin Service** → Admin-level actions and monitoring.
-   **Reports Service** → Provides detailed reports, statistics, and
    summaries.
-   **Shared Modules** → Database connection & logging
    utilities.

------------------------------------------------------------------------

## 📂 Project Structure

    ├── api-gateway/
    |   └── static               # JS and CSS codes
    |   └── templates            # HTML Templates
    │   └── app.py               # Routes to other services
    |   └── Dockerfile
    ├── users-service/
    │   └── app.py               # User auth, profiles, LLM integration
    |   └── Dockerfile
    ├── products-service/
    │   └── app.py               # Product CRUD and stock management
    |   └── Dockerfile
    ├── admin-service/
    │   └── app.py               # Admin operations
    |   └── Dockerfile
    ├── reports-service/
    │   └── app.py               # Reporting APIs
    |   └── Dockerfile
    ├── shared/
    │   ├── database.py          # SQLite connection helper
    │   └── logger.py            # Logging functions
    ├── data_to_csv.py           # Generate stock
    ├── run_services.py          # Start all services at once
    ├── docker-compose.yml       # Multi-service orchestration

------------------------------------------------------------------------

## ⚙️ Installation & Usage

### Prerequisites

-   Python 3.9+
-   Docker & Docker Compose
-   Gemini API key for natural language features

### Local Setup (Without Docker)

1.  Create and activate virtual environment:

    ``` bash
    python -m venv venv
    source venv/bin/activate   # Linux/Mac
    venvScriptsactivate    # Windows
    ```

2.  Install dependencies:

    ``` bash
    pip install -r requirements.txt
    ```

3.  Start all services at once:

    ``` bash
    python run_services.py
    ```

### Docker Setup

1.  Build and run with Docker Compose:

    ``` bash
    docker-compose up --build
    ```

2.  Access system at:

    -   API Gateway: `http://localhost:5000`
    -   Users Service: `http://localhost:5001`
    -   Products Service: `http://localhost:5002`
    -   Admin Service: `http://localhost:5003`
    -   Reports Service: `http://localhost:5004`

------------------------------------------------------------------------

## 🎮 Example API Usage

### Register User

``` http
POST /register
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "secure123"
}
```

### LLM Prompt for Stock Operation

``` http
POST /llm-process-prompt
{
  "user_id": 1,
  "prompt": "Add 20 pens and set critical level to 5"
}
```

### Get Reports (Admin)

``` http
GET /reports/stock-movements/admin?start_date=2025-01-01&end_date=2025-01-31
```

------------------------------------------------------------------------
