# Package Update Analysis for Deprecation Remediation
**MCP Security Project - Package Version Assessment**

*Generated: September 8, 2025*

## Executive Summary

Analysis of `pyproject.toml` dependencies to identify package updates that could resolve remaining deprecation warnings. The focus is on websockets-related deprecations since the BearerAuthProvider issue has been resolved.

## Current Package Status

### Core Dependencies Analysis

| Package | Current Version | Latest Available | Update Recommended | Deprecation Impact |
|---------|-----------------|------------------|---------------------|-------------------|
| **fastmcp** | 2.12.2 | 2.12.2 | ✅ **Up to Date** | None - Latest version |
| **uvicorn** | 0.24.0.post1 | 0.35.0 | 🔄 **Major Update Available** | May resolve websockets warnings |
| **websockets** | (indirect) | 15.x | N/A (indirect) | Inherited from uvicorn/fastmcp |
| **mcp** | 1.12.4 | 1.13.1 | 🔄 **Minor Update Available** | May improve compatibility |

## Key Findings

### 1. Uvicorn Major Update Available (0.24 → 0.35)

**Current Issue**: 
- Uvicorn 0.24.0.post1 uses older websockets interfaces
- Causing `WebSocketServerProtocol` deprecation warnings

**Update Benefits**:
- **Uvicorn 0.35.0** (latest) released with improved websockets compatibility
- WebSocketsSansIOProtocol support added
- Better handling of websockets library versions
- Enhanced WebSocket protocol implementations

**Risk Assessment**: **LOW**
- Well-established upgrade path
- FastMCP 2.12.2 compatible with uvicorn 0.35.0
- Backward compatible changes

### 2. MCP SDK Update (1.12.4 → 1.13.1)

**Update Benefits**:
- Latest protocol implementation
- Improved compatibility with newer server implementations
- Bug fixes and stability improvements

**Risk Assessment**: **VERY LOW**
- Minor version update
- FastMCP explicitly supports this version range

### 3. Other Significant Updates Available

| Package | Current | Latest | Impact | Priority |
|---------|---------|---------|---------|----------|
| **anthropic** | 0.54.0 | 0.66.0 | New features, API improvements | Medium |
| **dspy-ai** | 2.6.27 | 3.0.3 | Major version - breaking changes | Low |
| **langgraph** | 0.4.10 | 0.6.7 | Enhanced capabilities | Medium |
| **langsmith** | 0.3.45 | 0.4.26 | Monitoring improvements | Low |
| **redis** | 5.3.1 | 6.4.0 | Performance improvements | Low |

## Recommended Actions

### Phase 1: WebSocket Deprecation Resolution (High Priority)

**Update uvicorn to resolve websockets deprecation warnings:**

```toml
# Current
uvicorn = { extras = ["standard"], version = "^0.24.0" }

# Recommended  
uvicorn = { extras = ["standard"], version = "^0.35.0" }
```

**Update MCP SDK for compatibility:**

```toml
# Current - Indirect dependency
# Recommended - Ensure latest
mcp = "^1.13.1"  # Add if not automatically updated
```

### Phase 2: Security and Stability Updates (Medium Priority)

**Update security-relevant packages:**

```toml
# Enhanced API capabilities
anthropic = "^0.66.0"

# Latest cryptography
cryptography = "^45.0.0"  # Security improvements
```

### Phase 3: Development Tools (Low Priority)

**Update development tools for better experience:**

```toml
# Development dependencies
pytest = "^8.4.0"
pytest-asyncio = "^1.1.0"
black = "^25.1.0"
ruff = "^0.12.0"
```

## Implementation Plan

### Step 1: Critical WebSocket Fix
```bash
# Update uvicorn to resolve websockets warnings
poetry update uvicorn

# Verify compatibility
task run-server  # Should show fewer/no websockets warnings
```

### Step 2: Validate Changes
```bash
# Run full test suite
task test

# Test all client integrations
task run-openai-client
task run-anthropic-client
# ... other clients
```

### Step 3: Selective Updates
```bash
# Update security-relevant packages
poetry update anthropic cryptography

# Update core dependencies
poetry update mcp
```

## Risk Assessment

### LOW RISK Updates (Recommended)
- **uvicorn 0.35.0** - Direct fix for websockets deprecation
- **mcp 1.13.1** - Minor version with compatibility improvements
- **anthropic 0.66.0** - Regular API client updates

### MEDIUM RISK Updates (Consider)
- **langgraph 0.6.7** - Significant feature additions
- **redis 6.4.0** - Major version jump

### HIGH RISK Updates (Avoid for Now)
- **dspy-ai 3.0.3** - Major version with breaking changes

## Expected Outcomes

### After Uvicorn Update (0.35.0)
✅ **WebSocketServerProtocol deprecation** likely resolved  
✅ **Improved WebSocket protocol handling**  
✅ **Better websockets library compatibility**  
⚠️ **websockets.legacy warning** may persist (library-level)

### After MCP Update (1.13.1)
✅ **Enhanced protocol compatibility**  
✅ **Latest MCP features support**  
✅ **Improved stability**

## Validation Checklist

Post-update validation steps:

- [ ] Server starts without WebSocketServerProtocol warnings
- [ ] OAuth authentication flow works correctly
- [ ] All client integrations functional
- [ ] Security monitoring operational  
- [ ] Rate limiting effective
- [ ] TLS/HTTPS working properly
- [ ] Docker deployment successful

## Conclusion

**Primary Recommendation**: Update uvicorn to 0.35.0 to resolve the major websockets deprecation warnings. This is a low-risk, high-impact change that directly addresses the remaining deprecation issues.

**Secondary Recommendations**: Update mcp and anthropic packages for improved compatibility and security.

The websockets.legacy warning will likely persist as it's a library-level deprecation that will be resolved when the websockets library maintainers complete their migration in upstream dependencies.

---

**Next Steps**: Execute Phase 1 updates (uvicorn and mcp) and validate functionality.