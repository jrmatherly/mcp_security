# AGENTS.md
This file provides guidance to AI coding assistants working in this repository.

**Note:** CLAUDE.md, .clinerules, .cursorrules, .windsurfrules, .replit.md, GEMINI.md, and other AI config files are symlinks to AGENTS.md in this project.

# MCP Security: From Vulnerable to Fortified

**MCP Security** is a comprehensive demonstration project for building secure HTTP-based AI integrations using the Model Context Protocol (MCP) with enterprise-grade security measures. This project showcases authentication, encryption, input validation, rate limiting, and security monitoring patterns for AI platform integrations.

## Build & Commands

**CRITICAL**: This project uses Go Task (Taskfile.yml) for build automation, not npm. All commands use the `task` prefix.

### Essential Setup Commands
```bash
task setup              # Install Python dependencies with Poetry
task generate-certs     # Generate self-signed certificates for HTTPS
# Note: generate-keys deprecated - OAuth Proxy uses Azure JWKS
```

### Development Mode Commands
```bash
# Configure Azure credentials in .env first
task run-server         # Start MCP server with Azure OAuth Proxy (HTTP transport)

# Test AI client integrations
task run-openai-client     # Test secure OpenAI GPT-4 integration
task run-anthropic-client  # Test secure Anthropic Claude integration  
task run-langchain-client  # Test secure LangChain ReAct agent
task run-dspy-client       # Test secure DSPy ReAct agent
task run-litellm-client    # Test secure LiteLLM multi-provider
```

### Docker/Production Commands
```bash
task docker-build       # Build Docker images
task docker-up          # Start all services with TLS (https://localhost:8443)
task docker-down        # Stop all Docker services
task docker-logs        # View service logs
task docker-restart     # Restart services
task docker-clean       # Clean up containers and volumes

# Debugging containers
task docker-shell-mcp   # Debug MCP container
```

### Code Quality Commands
```bash
task test               # Run pytest test suite
task format             # Format code with Black and Ruff
task clean              # Clean up generated files and artifacts
```

### Script Command Consistency
**Important**: When modifying task commands in Taskfile.yml, ensure all references are updated:
- README.md documentation  
- GETTING_STARTED.md setup guides
- Docker configuration files
- GitHub workflows (if added)
- Contributing guides

Common places that reference task commands:
- Setup commands → Check: README, GETTING_STARTED, Docker
- Test commands → Check: workflows, contributing docs
- Format commands → Check: pre-commit hooks, workflows
- Run commands → Check: README, deployment docs

## Code Style

### Python Code Standards (Python 3.12.11)
- **Line Length**: 88 characters (Black standard)
- **Formatting**: Black for code formatting, Ruff for linting
- **Type Hints**: Required for function signatures and Pydantic models
- **Docstrings**: Triple quotes with descriptive module/class/function documentation

### Naming Conventions
- **Class Names**: PascalCase (e.g., `SecurityConfig`, `OAuthClient`)
- **Function Names**: snake_case (e.g., `get_customer_info`, `load_public_key`)  
- **Constants**: UPPER_SNAKE_CASE (e.g., `JWT_SECRET_KEY`, `OAUTH_CLIENT_ID`)
- **Private Functions**: Prefix with underscore (e.g., `_get_required_scopes`)

### Import Conventions
```python
# Standard library imports first
import os
from typing import Optional

# Third-party imports second  
import fastapi
from pydantic import BaseModel

# Local imports last
from config import Config
from security.auth import authenticate_user
```

### Error Handling Patterns
- Use proper exception handling with specific exception types
- Log errors with appropriate logging levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Security events logged separately with detailed context
- Graceful degradation where possible (fallback to safe defaults)

### Configuration Management
- Environment variables loaded via python-dotenv
- Configuration centralized in `Config` class with Pydantic validation
- Secrets stored in `.env` file (never committed to version control)
- Default values provided for development environment

### Code Quality Configuration (pyproject.toml)
```toml
[tool.black]
line-length = 88
target-version = ['py312']

[tool.ruff]
line-length = 88

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]
ignore = ["E501"]  # Allow long lines (handled by Black)

[tool.ruff.lint.isort]
known-first-party = ["config", "security"]
force-sort-within-sections = true
```

## Testing

### Testing Framework & Patterns
- **Framework**: pytest with pytest-asyncio for async tests
- **Test File Pattern**: `test_*.py` in `/tests` directory
- **Test Class Pattern**: Classes start with `Test` (e.g., `TestInputValidation`)
- **Test Method Pattern**: Methods start with `test_` (e.g., `test_validate_customer_input`)

### Testing Conventions
```python
# Example test structure
class TestSecurityAuth:
    def test_jwt_token_validation(self):
        # Test JWT token validation logic
        pass
        
    async def test_oauth_flow(self):
        # Test OAuth 2.1 PKCE flow
        pass
```

### Coverage Requirements  
- Focus on security-critical code paths
- Test both positive and negative scenarios
- Validate input sanitization and authentication flows
- Test rate limiting and security monitoring

### Testing Philosophy
**When tests fail, fix the code, not the test.**

Key principles:
- **Tests should be meaningful** - Avoid tests that always pass regardless of behavior
- **Test actual functionality** - Call the functions being tested, don't just check side effects
- **Failing tests are valuable** - They reveal bugs or missing security vulnerabilities
- **Fix the root cause** - When a test fails, fix the underlying security issue
- **Test edge cases** - Security tests that reveal attack vectors help improve defenses
- **Document test purpose** - Each test should include a comment explaining the security concern it validates

## Security

### Security-First Approach
This project demonstrates enterprise-grade security patterns. **Never compromise security for convenience**.

### Authentication & Authorization
- **Azure OAuth Proxy** - FastMCP OAuth Proxy with Azure Entra ID integration
- **Enterprise Authentication** - Direct Azure OAuth 2.1 with JWKS validation
- **JWT Token Validation** - RS256 signatures via Azure JWKS endpoint
- **Scope-based Authorization** - Microsoft Graph API scopes

### Data Protection & Validation
- **Input Validation** - Pydantic models with dangerous pattern blocking
- **Output Sanitization** - Bleach library for HTML/script sanitization
- **TLS Encryption** - End-to-end encryption with certificate management
- **Security Headers** - HSTS, CSP, and other protective headers

### Rate Limiting & Monitoring
- **Multi-tier Rate Limiting** - Request and AI token usage limits via Redis
- **Security Monitoring** - Real-time threat detection and incident logging
- **Audit Trail** - Comprehensive logging of authentication and authorization events

### Environment Security
- **Secret Management** - Never commit API keys, use .env files with .env.example templates
- **Certificate Management** - Proper TLS certificate generation and rotation
- **Container Security** - Non-root users, minimal attack surface in Docker images

## Directory Structure & File Organization

### Project Structure
```
mcp_security/
├── src/                          # Main source code
│   ├── config.py                # Security & LLM configuration
│   ├── main.py                  # Secure MCP server implementation
│   ├── oauth_server.py          # OAuth 2.1 authorization server
│   ├── security/                # Security components
│   │   ├── auth.py             # Authentication middleware
│   │   ├── validation.py       # Input validation
│   │   ├── rate_limiting.py    # Rate limiting implementation
│   │   └── monitoring.py       # Security monitoring
│   └── secure_clients/         # AI platform client implementations
├── tests/                       # Test suite
│   ├── test_security.py        # Security validation tests
│   └── test_clients.py         # Client integration tests
├── reports/                     # All project reports and documentation
├── temp/                        # Temporary files and debugging
├── certificates/                # TLS certificates (generated)
├── scripts/                     # Utility scripts
├── claudedocs/                  # AI-generated documentation
└── nginx/                       # Nginx TLS configuration
```

### Reports Directory
ALL project reports and documentation should be saved to the `reports/` directory:

**Implementation Reports:**
- Phase validation: `PHASE_X_VALIDATION_REPORT.md`
- Security assessments: `SECURITY_ASSESSMENT_[DATE].md`
- Integration testing: `INTEGRATION_TEST_[CLIENT]_[DATE].md`

**Testing & Analysis Reports:**
- Test results: `TEST_RESULTS_[DATE].md`
- Security scan results: `SECURITY_SCAN_[DATE].md`
- Performance analysis: `PERFORMANCE_ANALYSIS_[SCENARIO].md`

**Quality & Validation:**
- Code quality: `CODE_QUALITY_REPORT.md`
- Dependency analysis: `DEPENDENCY_REPORT.md`
- Vulnerability assessment: `VULNERABILITY_ASSESSMENT_[DATE].md`

### Temporary Files & Debugging
All temporary files, debugging scripts, and test artifacts should be organized in a `/temp` folder:

**Temporary File Organization:**
- **Debug scripts**: `temp/debug-*.py`, `temp/analyze-*.sh`
- **Test artifacts**: `temp/test-results/`, `temp/coverage/`  
- **Generated certificates**: `temp/certs/` (for testing only)
- **Logs**: `temp/logs/debug.log`, `temp/logs/security.log`

### .gitignore Patterns
```
# Temporary files and debugging
/temp/
temp/
**/temp/
debug-*.py
test-*.py
analyze-*.sh
*-debug.*
*.debug

# Security files
.env
*.key
*.pem
certificates/
ssl-certs/

# Python
.venv/
__pycache__/
*.pyc

# Don't ignore reports directory
!reports/
!reports/**
```

## Configuration

### Environment Setup
```bash
# Required Python version
pyenv local 3.12.11

# Poetry virtual environment  
poetry install
poetry shell

# Environment variables (copy and customize)
cp .env.example .env
# Edit .env with your API keys and configuration
```

### Required Environment Variables (.env)
```bash
# AI Platform API Keys
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENAI_BASE_URL=https://api.openai.com/v1  # Optional: custom OpenAI endpoint

# Azure OAuth Proxy Configuration (REQUIRED)
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret

# Server Configuration  
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000

# MCP Base URL Configuration
# This sets the base URL for OAuth and API endpoints
# Development: http://localhost:8000
# Docker/nginx: https://localhost:8443  
# Production: https://api.yourdomain.com
MCP_BASE_URL=http://localhost:8000

# Redis Configuration (for rate limiting)
REDIS_URL=redis://localhost:6379

# TLS Configuration
TLS_CERT_PATH=./certificates/cert.pem
TLS_KEY_PATH=./certificates/key.pem
```

### Development vs Production
- **Development**: HTTP MCP server (localhost:8000) with Azure OAuth Proxy
- **Production**: HTTPS via nginx (localhost:8001) with Azure OAuth Proxy and certificate management

### Dependencies Management
- **Poetry**: Primary dependency management (`pyproject.toml`)
- **Python 3.12.11**: Required Python version
- **Virtual Environment**: Poetry manages `.venv/` automatically
- **Lock File**: `poetry.lock` ensures reproducible builds

### Current Package Versions (Post-OAuth Proxy Migration September 2025)
- **fastmcp**: 2.12.2 (Latest - with OAuth Proxy support)
- **uvicorn**: 0.35.0 (Latest - with WebSocketsSansIOProtocol support)
- **mcp**: 1.13.1 (Latest MCP SDK)
- **fastapi**: 0.115.13+ (Web framework)
- **Authentication**: OAuth Proxy with Azure Entra ID (Local OAuth server deprecated)

### Hybrid uv + Poetry Setup (Optional)
If you encounter environment issues:
```bash
# Recreate virtual environment with uv + poetry
rm -rf .venv && uv venv .venv --python 3.12.11 && poetry env use .venv/bin/python && poetry install
```

## Agent Delegation & Tool Execution

### ⚠️ MANDATORY: Always Delegate to Specialists & Execute in Parallel

**When specialized agents are available, you MUST use them instead of attempting tasks yourself.**

**When performing multiple operations, send all tool calls (including Task calls for agent delegation) in a single message to execute them concurrently for optimal performance.**

#### Why Agent Delegation Matters
- Specialists have deeper security knowledge and awareness of attack vectors
- They understand subtle security bugs and enterprise patterns  
- They follow established security frameworks and compliance requirements
- They can provide more comprehensive threat modeling

#### Key Principles
- **Security-First Delegation**: Always use security experts for authentication, validation, and threat analysis
- **Complex Security Problems**: Delegate to security specialists, use diagnostic agents for vulnerability assessment
- **Multiple Security Domains**: Send multiple Task tool calls in a single message to security specialists in parallel
- **DEFAULT TO PARALLEL**: Unless you have a specific reason why operations MUST be sequential, always execute multiple tools simultaneously
- **Security Assessment Planning**: Think "What security concerns need evaluation?" Then execute all assessments together

#### Critical: Always Use Parallel Tool Calls

**Err on the side of maximizing parallel tool calls for security analysis.**

**IMPORTANT: Send all security-related tool calls in a single message to execute them in parallel.**

**These security cases MUST use parallel tool calls:**
- Searching for different security patterns (auth flows, input validation, encryption)
- Multiple vulnerability scans with different attack vectors
- Reading multiple security configuration files
- Combining authentication analysis with authorization checks
- Searching for multiple independent security concerns
- Agent delegations with multiple Task calls to security specialists

**Sequential calls ONLY when:**
You genuinely REQUIRE the output of one security analysis to determine the next vulnerability assessment.

**Security Analysis Approach:**
1. Before making tool calls, think: "What security domains need evaluation?"
2. Send all security assessment tool calls in a single message to execute them in parallel
3. Execute all security searches together rather than waiting for each result
4. Most security analysis can be parallelized rather than sequential

**Performance Impact:** Parallel security analysis is 3-5x faster than sequential assessments, crucial for rapid threat detection.

**Remember:** Security analysis parallelization is not just an optimization—it's the expected behavior for comprehensive threat assessment.