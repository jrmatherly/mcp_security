# Getting Started with MCP Security

A comprehensive guide to setting up and working with the MCP Security project, which demonstrates secure HTTP-based AI integrations using the Model Context Protocol.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.12.11** (managed via pyenv recommended)
- **uv** - Modern Python package installer and resolver
- **Poetry** - Python dependency management 
- **Go Task** - Build automation tool
- **Git** - Version control

### Installing Prerequisites

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install Task (macOS with Homebrew)
brew install go-task/tap/go-task

# Install pyenv (macOS with Homebrew) - optional but recommended
brew install pyenv
```

## Quick Setup

### 1. Clone and Navigate
```bash
git clone <repository-url>
cd mcp_security
```

### 2. Set Up Virtual Environment (Hybrid uv + Poetry approach)
```bash
# Create virtual environment with uv (fast)
uv venv .venv --python 3.12.11

# Tell Poetry to use the .venv we created
poetry env use .venv/bin/python

# Install all dependencies with Poetry
poetry install
```

### 3. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
# - Add API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY)
# - Configure custom OpenAI endpoint (OPENAI_BASE_URL) if needed
# - Configure OAuth settings
# - Set other environment variables as needed
```

### 4. Generate Security Keys
```bash
# Generate RSA keys for JWT signing
task generate-keys

# Generate TLS certificates for development
task generate-certs
```

## Development Workflow

### Virtual Environment Activation

You have several options to work with the virtual environment:

```bash
# Option 1: Use Poetry commands (recommended)
poetry run python src/main.py
poetry run pytest

# Option 2: Activate the shell
poetry shell
# Now you can run commands directly: python src/main.py

# Option 3: Manual activation
source .venv/bin/activate
# Now you can run commands directly: python src/main.py
```

### Running the Application

#### Development Mode (HTTP - No TLS)
```bash
# Terminal 1: Start OAuth server
task run-oauth              # Runs on http://localhost:8080

# Terminal 2: Start MCP server  
task run-server             # Runs on stdio transport

# Terminal 3: Test with AI clients
task run-openai-client      # Test OpenAI integration
task run-anthropic-client   # Test Anthropic integration
task run-langchain-client   # Test LangChain integration
task run-dspy-client        # Test DSPy integration
task run-litellm-client     # Test LiteLLM integration
```

#### Production Mode (HTTPS with Docker)
```bash
# Start all services with TLS
task docker-up

# View logs
task docker-logs

# Test with secure clients (same client commands work)
task run-openai-client      # Now uses HTTPS endpoints

# Stop all services
task docker-down
```

## Code Quality and Linting

### Formatting and Linting Commands

```bash
# Format code with Black and fix linting issues with Ruff
task format

# Manual formatting and linting
poetry run black src/ tests/
poetry run ruff check --fix src/ tests/

# Check for linting issues only (no fixes)
poetry run ruff check src/ tests/

# Check specific file
poetry run ruff check src/main.py
```

### Testing

```bash
# Run all tests
task test

# Run tests manually
poetry run pytest tests/ -v

# Run specific test file
poetry run pytest tests/test_security.py -v

# Run tests with coverage
poetry run pytest tests/ --cov=src --cov-report=html
```

### Type Checking

```bash
# Type checking is handled by the IDE, but you can also run:
poetry run mypy src/ --ignore-missing-imports
```

## Configuration Files

### Key Configuration Files

- **`pyproject.toml`** - Python project configuration, dependencies, and tool settings
- **`.env`** - Environment variables (copy from `.env.example`)
- **`Taskfile.yml`** - Task automation definitions
- **`.venv/`** - Virtual environment created by uv
- **`poetry.lock`** - Locked dependency versions

### Ruff Configuration

The project uses Ruff for linting with the following configuration in `pyproject.toml`:

```toml
[tool.ruff]
line-length = 88
select = ["E", "F", "I", "N", "W"]
ignore = ["E501"]

[tool.ruff.isort]
known-first-party = ["config", "security"]
force-sort-within-sections = true
```

### Black Configuration

Code formatting with Black:

```toml
[tool.black]
line-length = 88
target-version = ['py312']
```

## Available Tasks

### Core Development Tasks
```bash
task setup              # Set up Python environment (alternative to manual setup)
task generate-keys      # Generate RSA key pair for OAuth JWT signing
task generate-certs     # Generate self-signed certificates
task test               # Run all pytest tests
task format             # Format code with Black and Ruff
task clean              # Clean up generated files and caches
```

### Server Tasks
```bash
task run-oauth          # Run OAuth authorization server
task run-server         # Run MCP server (stdio transport)
```

### Client Testing Tasks
```bash
task run-openai-client     # Test OpenAI GPT-4 integration
task run-anthropic-client  # Test Anthropic Claude integration  
task run-langchain-client  # Test LangChain ReAct agent
task run-dspy-client       # Test DSPy ReAct agent
task run-litellm-client    # Test LiteLLM multi-provider
```

### Docker Tasks
```bash
task docker-build       # Build Docker images
task docker-up          # Start all services with TLS
task docker-down        # Stop all services
task docker-logs        # View service logs
task docker-restart     # Restart services
task docker-clean       # Clean up containers and volumes
task docker-shell-oauth # Debug OAuth container
task docker-shell-mcp   # Debug MCP container
```

## Project Structure

```
mcp_security/
├── .venv/                  # Virtual environment (created by uv)
├── src/                    # Main source code
│   ├── config.py          # Configuration management
│   ├── main.py            # MCP server implementation
│   ├── oauth_server.py    # OAuth 2.1 authorization server
│   ├── generate_keys.py   # RSA key generation utility
│   ├── security/          # Security components
│   └── secure_clients/    # AI platform client implementations
├── tests/                 # Test suite
├── certificates/          # TLS certificates (generated)
├── keys/                  # RSA keys (generated)
├── claudedocs/           # Claude-generated documentation
├── .env.example          # Environment template
├── pyproject.toml        # Poetry configuration
├── Taskfile.yml          # Task definitions
└── GETTING_STARTED.md    # This file
```

## Common Workflows

### Adding a New Dependency

```bash
# Add a runtime dependency
poetry add <package-name>

# Add a development dependency
poetry add --group dev <package-name>

# Update dependencies
poetry update
```

### Making Code Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** using your preferred editor

3. **Format and lint**:
   ```bash
   task format
   ```

4. **Run tests**:
   ```bash
   task test
   ```

5. **Commit changes**:
   ```bash
   git add .
   git commit -m "feat: your descriptive commit message"
   ```

### Troubleshooting

#### Virtual Environment Issues
```bash
# If you need to recreate the virtual environment
rm -rf .venv
uv venv .venv --python 3.12.11
poetry env use .venv/bin/python
poetry install
```

#### Import Errors
- Make sure you're running commands through Poetry: `poetry run python ...`
- Or activate the shell first: `poetry shell`

#### Linting Conflicts
- The project is configured to use both Black and Ruff
- Run `task format` to apply both tools consistently
- Import sorting is handled by Ruff with custom configuration

#### Permission Errors
```bash
# Fix certificate permissions if needed
chmod 600 certificates/server.key
chmod 644 certificates/server.crt
```

## Environment Variables

Key environment variables to configure in `.env`:

```bash
# API Keys
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://your-openai-compatible-endpoint.com/v1  # Optional custom endpoint
ANTHROPIC_API_KEY=sk-ant-...

# OAuth Configuration  
OAUTH_CLIENT_ID=mcp-secure-client
OAUTH_CLIENT_SECRET=your-secure-secret
JWT_SECRET_KEY=your-jwt-secret

# Server Configuration
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
OAUTH_SERVER_HOST=localhost
OAUTH_SERVER_PORT=8080

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Development vs Production URLs
# Development (HTTP):
OAUTH_TOKEN_URL=http://localhost:8080/token
MCP_SERVER_URL=http://localhost:8000/mcp

# Production (HTTPS):
OAUTH_TOKEN_URL=https://localhost:8443/token
MCP_SERVER_URL=https://localhost:8001/mcp
```

## Next Steps

1. **Configure your API keys** in the `.env` file
2. **Run the quick setup** commands above
3. **Start with development mode** to test the setup
4. **Explore the client examples** to understand the OAuth flow
5. **Review the security features** documented in `README.md`
6. **Check out the analysis report** in `claudedocs/security_analysis_report.md`

For detailed information about the project architecture and security features, see the main [README.md](README.md).