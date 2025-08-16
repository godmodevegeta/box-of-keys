# KeyHaven Pro

Secure API Key Management Platform with client-side encryption, automated monitoring, and AI-powered insights.

## Features

- 🔐 Client-side AES-256 encryption
- 👥 Team collaboration with role-based access control
- 📊 Real-time monitoring and analytics
- 🤖 AI-powered security insights
- 🔄 Automated key rotation
- 🌐 Browser extension for seamless integration
- 📱 Responsive web interface

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- PostgreSQL (if running locally)
- Redis (if running locally)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd keyhaven-pro
   ```

2. **Run the setup script**
   ```bash
   ./scripts/setup.sh
   ```

3. **Start the development server**
   ```bash
   make dev
   ```

4. **Visit the application**
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

### Using Docker

1. **Start all services**
   ```bash
   make docker-up
   ```

2. **View logs**
   ```bash
   make docker-logs
   ```

3. **Stop services**
   ```bash
   make docker-down
   ```

## Development Commands

```bash
make help          # Show all available commands
make setup         # Set up development environment
make test          # Run tests
make lint          # Run linting
make format        # Format code
make migrate       # Run database migrations
make init-db       # Initialize database
```

## Project Structure

```
keyhaven-pro/
├── app/                    # Application code
│   ├── api/               # API routes
│   ├── core/              # Core functionality
│   ├── models/            # Database models
│   ├── services/          # Business logic
│   └── main.py            # FastAPI application
├── tests/                 # Test files
├── migrations/            # Database migrations
├── scripts/               # Utility scripts
├── docker-compose.yml     # Docker configuration
├── Dockerfile            # Docker image
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Configuration

Copy `.env.example` to `.env` and update the configuration:

```bash
cp .env.example .env
```

Key configuration options:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: Application secret key
- `JWT_SECRET_KEY`: JWT signing key

## Testing

Run the test suite:

```bash
make test
```

Run tests with coverage:

```bash
pytest --cov=app --cov-report=html
```

## API Documentation

When running in development mode, API documentation is available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.