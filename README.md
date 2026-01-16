# Cloudflare Mini WAF

A lightweight, edge-based Web Application Firewall (WAF) built with Cloudflare Workers that demonstrates how to implement enterprise-grade security at the edge.

**Written in vanilla JavaScript for easy reading and quick understanding** - no TypeScript compilation needed!

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Geographic Restrictions](#1-geographic-restrictions)
  - [Rate Limiting](#2-rate-limiting)
  - [IP Filtering - Blocklist](#3-ip-filtering---blocklist)
  - [IP Filtering - Allowlist](#4-ip-filtering---allowlist)
  - [HTTP Method Filtering](#5-http-method-filtering)
  - [Request Size Limits](#6-request-size-limits)
  - [Malicious Pattern Detection](#7-malicious-pattern-detection)
  - [Payload Validation](#8-payload-validation-api-schema-validation)
  - [Configuration Examples by Use Case](#configuration-examples-by-use-case)
- [Usage](#usage)
  - [Development](#development)
  - [Testing](#testing)
  - [Deployment](#deployment)
- [Code Examples](#code-examples)
  - [Block by Country](#example-block-by-country)
  - [Rate Limiting Setup](#example-rate-limiting-setup)
  - [IP Allowlist for Admin Panel](#example-ip-allowlist-for-admin-panel)
  - [Validate API Payloads](#example-validate-api-payloads)
  - [Custom Pattern Detection](#example-custom-pattern-detection)
- [Adding to an Existing Application](#adding-to-an-existing-application)
- [Advanced Features](#advanced-features)
- [Performance](#performance)
- [Security Considerations](#security-considerations)
- [Cloudflare-Specific Features](#cloudflare-specific-features-leveraged)
- [Troubleshooting](#troubleshooting)
- [Resources](#resources)
- [Contributing](#contributing)

## Overview

This project showcases the power of Cloudflare Workers for implementing security controls before requests reach your origin infrastructure. By running at Cloudflare's edge network (300+ locations worldwide), you can block malicious traffic milliseconds after it enters Cloudflare's network, reducing load on your origin and improving security posture.

## Features

### 🌍 Geographic Blocking
- Block or allow traffic based on country codes (ISO 3166-1 alpha-2)
- Implement geo-fencing for region-specific services
- Comply with data residency requirements

### 🚦 Rate Limiting
- Distributed rate limiting to prevent brute force attacks
- Configurable request limits per time window
- Per-IP tracking with automatic expiration
- Returns proper `429 Too Many Requests` with `Retry-After` headers

### 🔒 IP Filtering
- Block specific IP addresses or CIDR ranges
- Whitelist trusted IPs (bypasses all other checks)
- Support for both individual IPs and network ranges

### 🛡️ Attack Pattern Detection
- **SQL Injection**: Detects common SQL injection patterns
- **XSS (Cross-Site Scripting)**: Blocks script injection attempts
- **Path Traversal**: Prevents directory traversal attacks
- **Command Injection**: Detects shell command injection attempts
- Scans both URLs and request bodies

### 📏 Request Validation
- HTTP method whitelisting (block TRACE, TRACK, etc.)
- Request size limits to prevent resource exhaustion
- User-Agent validation to block known malicious tools
- Content-Type validation
- **JSON payload validation** with schema definitions (types, lengths, patterns, enums)

### 🔐 Security Headers
Automatically adds security headers to all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────┐
│  Cloudflare Edge (300+ locations)    │
│  ┌────────────────────────────────┐  │
│  │   Mini WAF Worker              │  │
│  │  ┌──────────────────────────┐  │  │
│  │  │ 1. Geographic Check      │  │  │
│  │  │ 2. IP Filtering          │  │  │
│  │  │ 3. Rate Limiting         │  │  │
│  │  │ 4. Method Validation     │  │  │
│  │  │ 5. Size Check            │  │  │
│  │  │ 6. User-Agent Check      │  │  │
│  │  │ 7. Pattern Detection     │  │  │
│  │  └──────────────────────────┘  │  │
│  └────────────────────────────────┘  │
└──────────────┬───────────────────────┘
               │
               ▼ (if passed)
        ┌──────────────┐
        │ Origin Server│
        └──────────────┘
```

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cloudflare-mini-waf
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure Wrangler**
   - Make sure you're logged in to Cloudflare:
     ```bash
     npx wrangler login
     ```

4. **(Optional) Set up KV for Rate Limiting**
   
   To enable full rate limiting functionality:
   
   ```bash
   # Create a KV namespace
   npx wrangler kv:namespace create RATE_LIMIT
   ```
   
   Then add the binding to `wrangler.jsonc`:
   ```json
   {
     "name": "cloudflare-mini-waf",
     "main": "src/index.js",
     "compatibility_date": "2025-09-27",
     "kv_namespaces": [
       {
         "binding": "RATE_LIMIT",
         "id": "your-kv-namespace-id"
       }
     ]
   }
   ```
   
   Finally, uncomment the rate limiting code in `src/index.js` (lines marked with KV comments).

## Configuration

Edit the `config` object in `src/index.js` to customize the WAF behavior. All configuration is at the top of the file for easy access.

### Configuration Options

#### 1. **Geographic Restrictions**

```javascript
blockedCountries: ['CN', 'RU']  // Array of ISO 3166-1 alpha-2 country codes
```

**What it does**: Blocks all requests from specified countries based on the `CF-IPCountry` header that Cloudflare automatically provides.

**Use cases**:
- Block high-risk regions with frequent attack traffic
- Comply with data residency requirements (GDPR, etc.)
- Restrict services to specific geographic markets
- Reduce exposure to state-sponsored threats

**Example values**:
```javascript
// Block multiple countries
blockedCountries: ['CN', 'RU', 'KP', 'IR']

// Block no countries (allow all)
blockedCountries: []
```

**Country codes**: [ISO 3166-1 alpha-2 codes](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) - US, CA, GB, FR, DE, JP, etc.

---

```javascript
allowedCountries: ['US', 'CA', 'GB']  // Optional: Whitelist only specific countries
```

**What it does**: If set, **ONLY** allows traffic from specified countries. All other countries are blocked. This takes precedence over `blockedCountries`.

**Use cases**:
- Strictly limit service to specific regions
- Enforce geographic licensing restrictions
- Create region-locked content or services
- Comply with export control regulations

**Example values**:
```javascript
// Only allow North America
allowedCountries: ['US', 'CA', 'MX']

// Only allow EU countries
allowedCountries: ['DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'PL']

// Don't use allowlist (comment out or set to undefined)
// allowedCountries: undefined
```

**⚠️ Important**: If `allowedCountries` is set, `blockedCountries` is ignored. Choose one strategy or the other.

---

#### 2. **Rate Limiting**

```javascript
rateLimit: {
  enabled: true,           // Enable/disable rate limiting
  maxRequests: 100,        // Maximum requests allowed per IP
  windowSeconds: 60,       // Time window in seconds
}
```

**What it does**: Limits the number of requests a single IP address can make within a time window. Requires KV namespace setup for full functionality.

**Use cases**:
- Prevent brute force attacks on login endpoints
- Mitigate DDoS attempts
- Enforce API rate limits
- Protect against credential stuffing
- Prevent web scraping

**Example configurations**:

```javascript
// Strict rate limiting (API protection)
rateLimit: {
  enabled: true,
  maxRequests: 10,
  windowSeconds: 60,  // 10 requests per minute
}

// Moderate rate limiting (web application)
rateLimit: {
  enabled: true,
  maxRequests: 100,
  windowSeconds: 60,  // 100 requests per minute
}

// Loose rate limiting (high-traffic site)
rateLimit: {
  enabled: true,
  maxRequests: 1000,
  windowSeconds: 60,  // 1000 requests per minute
}

// Hourly rate limit
rateLimit: {
  enabled: true,
  maxRequests: 1000,
  windowSeconds: 3600,  // 1000 requests per hour
}

// Disabled
rateLimit: {
  enabled: false,
  maxRequests: 100,
  windowSeconds: 60,
}
```

**Setup required**: To make rate limiting fully functional:
1. Create KV namespace: `npx wrangler kv:namespace create RATE_LIMIT`
2. Add binding to `wrangler.jsonc`
3. Uncomment KV code in `src/index.js` (search for "RATE_LIMIT")

**Response**: Returns `429 Too Many Requests` with `Retry-After` header when limit exceeded.

---

#### 3. **IP Filtering - Blocklist**

```javascript
blockedIPs: ['192.0.2.1', '198.51.100.0/24']  // Array of IPs or CIDR ranges
```

**What it does**: Blocks specific IP addresses or entire IP ranges (CIDR notation). Uses the `CF-Connecting-IP` header for real client IP.

**Use cases**:
- Block known malicious IPs from threat intelligence
- Block specific attackers after incident response
- Block bot networks and VPN exit nodes
- Block competitor scraping IPs
- Block IPs from abuse reports

**Example values**:
```javascript
// Block individual IPs
blockedIPs: ['203.0.113.45', '198.51.100.123', '192.0.2.99']

// Block IP ranges (CIDR notation)
blockedIPs: [
  '192.0.2.0/24',      // Blocks 192.0.2.0 - 192.0.2.255
  '198.51.100.0/22',   // Blocks 198.51.100.0 - 198.51.103.255
  '10.0.0.0/8',        // Blocks entire 10.x.x.x range
]

// Mix of individual IPs and ranges
blockedIPs: [
  '203.0.113.45',
  '198.51.100.0/24',
  '192.0.2.1',
]

// No blocked IPs
blockedIPs: []
```

**CIDR notation quick reference**:
- `/32` = Single IP (e.g., `192.0.2.1/32`)
- `/24` = 256 IPs (e.g., `192.0.2.0/24` = 192.0.2.0-255)
- `/16` = 65,536 IPs (e.g., `192.0.0.0/16`)
- `/8` = 16,777,216 IPs (e.g., `10.0.0.0/8`)

**Note**: The current implementation uses simplified CIDR matching. For production use with many IPs, consider using Cloudflare's [IP Lists](https://developers.cloudflare.com/waf/tools/lists/custom-lists/).

---

#### 4. **IP Filtering - Allowlist**

```javascript
allowedIPs: ['203.0.113.0/24']  // Optional: Whitelist specific IPs
```

**What it does**: If set, **ONLY** these IPs can access the site and they bypass **ALL** security checks (including rate limiting, pattern detection, etc.). This is the ultimate bypass.

**Use cases**:
- Whitelist office/corporate IP ranges for admin panels
- Allow monitoring services and health checkers
- Permit trusted API clients
- Allow CI/CD pipelines
- Create IP-based access control for sensitive endpoints

**Example values**:
```javascript
// Allow office network
allowedIPs: ['203.0.113.0/24']

// Allow multiple trusted sources
allowedIPs: [
  '203.0.113.0/24',    // Office network
  '198.51.100.50',     // Monitoring service
  '192.0.2.100/30',    // VPN gateway
]

// Don't use allowlist (comment out)
// allowedIPs: undefined
```

**⚠️ Important**: 
- If an IP matches `allowedIPs`, **all other security checks are skipped**
- This takes precedence over `blockedIPs`
- Use carefully - these IPs are completely trusted
- Choose either allowlist or blocklist strategy based on your threat model

---

#### 5. **HTTP Method Filtering**

```javascript
allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
```

**What it does**: Only allows specified HTTP methods. Blocks all others with `405 Method Not Allowed`.

**Use cases**:
- Block dangerous methods like TRACE/TRACK (XST attacks)
- Restrict methods for specific application types
- Enforce RESTful API contracts
- Reduce attack surface
- Block uncommon methods used in reconnaissance

**Example configurations**:
```javascript
// Read-only site (blog, documentation)
allowedMethods: ['GET', 'HEAD', 'OPTIONS']

// Standard web application
allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

// API-only (no browser-specific methods)
allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

// Maximum security (block TRACE, TRACK, CONNECT)
allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

// GraphQL endpoint (only POST)
allowedMethods: ['POST', 'OPTIONS']
```

**Common HTTP methods**:
- `GET` - Retrieve data
- `POST` - Submit data
- `PUT` - Replace resource
- `PATCH` - Partial update
- `DELETE` - Remove resource
- `HEAD` - Get headers only
- `OPTIONS` - Check allowed methods (CORS)
- `TRACE` - Debug (security risk - usually blocked)
- `CONNECT` - Tunnel (rarely needed)

**Response**: Returns `405 Method Not Allowed` with `Allow` header listing permitted methods.

---

#### 6. **Request Size Limits**

```javascript
maxRequestSizeBytes: 10 * 1024 * 1024  // 10MB in bytes
```

**What it does**: Limits the maximum size of request bodies by checking the `Content-Length` header. Blocks oversized requests with `413 Payload Too Large`.

**Use cases**:
- Prevent memory exhaustion attacks
- Enforce file upload limits
- Protect downstream services with size constraints
- Prevent storage abuse
- Reduce bandwidth costs

**Example values**:
```javascript
// Tiny payloads (form submissions only)
maxRequestSizeBytes: 1024  // 1KB

// Small payloads (JSON API)
maxRequestSizeBytes: 100 * 1024  // 100KB

// Medium payloads (small file uploads)
maxRequestSizeBytes: 5 * 1024 * 1024  // 5MB

// Large payloads (image uploads)
maxRequestSizeBytes: 10 * 1024 * 1024  // 10MB

// Very large payloads (video uploads)
maxRequestSizeBytes: 100 * 1024 * 1024  // 100MB

// No limit (not recommended)
maxRequestSizeBytes: Infinity
```

**Size reference**:
- `1024` = 1KB
- `1024 * 1024` = 1MB
- `10 * 1024 * 1024` = 10MB
- `100 * 1024 * 1024` = 100MB
- `1024 * 1024 * 1024` = 1GB

**Note**: Cloudflare Workers have a [request body size limit of 100MB](https://developers.cloudflare.com/workers/platform/limits/) for paid plans (500MB for Enterprise).

---

#### 7. **Malicious Pattern Detection**

```javascript
blockSuspiciousPatterns: true  // Enable/disable attack pattern detection
```

**What it does**: Scans URLs and request bodies for common attack patterns including:
- **SQL Injection** - `' OR '1'='1`, `UNION SELECT`, `exec`, etc.
- **XSS** - `<script>`, `javascript:`, `onerror=`, etc.
- **Path Traversal** - `../`, `..\\`, URL-encoded variants
- **Command Injection** - `; ls`, `| cat`, backticks, command substitution

**Use cases**:
- Block common web application attacks
- Protect legacy applications without built-in WAF
- Add defense-in-depth security layer
- Reduce false sense of security from other controls
- Log attack attempts for threat intelligence

**Example values**:
```javascript
// Enable all pattern detection (recommended)
blockSuspiciousPatterns: true

// Disable pattern detection (only use if causing false positives)
blockSuspiciousPatterns: false
```

**What gets checked**:
- ✅ URL path (`/api/users/1`)
- ✅ Query string (`?id=1&name=test`)
- ✅ Request body (for POST/PUT/PATCH with text-based content types)
- ❌ Binary uploads (images, PDFs, etc. are skipped)

**Response**: Returns `403 Forbidden` with error details when attack detected.

**Customization**: To adjust patterns or add custom rules, edit the regex patterns in the `checkMaliciousPatterns()` function in `src/index.js` (lines ~320-380).

**⚠️ False Positives**: 
- Some legitimate content may trigger patterns (e.g., code tutorials about SQL)
- Test thoroughly with your application
- Consider adding exceptions for specific paths or content types
- Monitor logs for false positives and adjust patterns

---

#### 8. **Payload Validation (API Schema Validation)**

```javascript
payloadValidation: {
  enabled: true,
  schemas: {
    '/api/users': {
      POST: {
        required: ['email', 'name'],
        properties: {
          email: { type: 'string', pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
          name: { type: 'string', minLength: 2, maxLength: 100 },
          age: { type: 'number', min: 0, max: 150 },
          role: { type: 'string', enum: ['user', 'admin', 'moderator'] },
        },
      },
    },
  },
}
```

**What it does**: Validates JSON request bodies against defined schemas for specific API endpoints. Checks data types, required fields, string lengths, number ranges, enum values, and regex patterns **before requests reach your origin**.

**Use cases**:
- Validate API request payloads at the edge
- Enforce data contracts and API specifications
- Block malformed or invalid data early
- Reduce load on origin servers from invalid requests
- Provide immediate, clear validation errors to API consumers
- Prevent injection of unexpected fields
- Enforce business rules (e.g., age ranges, valid email formats)

**Schema properties supported**:

```javascript
properties: {
  fieldName: {
    type: 'string' | 'number' | 'boolean' | 'array' | 'object',
    
    // String validations
    minLength: 2,                    // Minimum string length
    maxLength: 100,                  // Maximum string length
    pattern: /^[a-z]+$/,            // Regex pattern match
    enum: ['value1', 'value2'],      // Allowed values only
    
    // Number validations
    min: 0,                          // Minimum value
    max: 150,                        // Maximum value
  }
}
```

**Example schemas**:

```javascript
// User registration endpoint
'/api/users': {
  POST: {
    required: ['email', 'password', 'name'],
    properties: {
      email: { 
        type: 'string', 
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        maxLength: 255,
      },
      password: { 
        type: 'string', 
        minLength: 8,
        maxLength: 128,
      },
      name: { 
        type: 'string', 
        minLength: 2,
        maxLength: 100,
      },
      age: { 
        type: 'number', 
        min: 13,    // COPPA compliance
        max: 120,
      },
      role: {
        type: 'string',
        enum: ['user', 'admin', 'moderator'],
      },
    },
  },
  PUT: {
    required: ['name'],
    properties: {
      name: { type: 'string', minLength: 2, maxLength: 100 },
      bio: { type: 'string', maxLength: 500 },
    },
  },
},

// Login endpoint
'/api/login': {
  POST: {
    required: ['email', 'password'],
    properties: {
      email: { 
        type: 'string', 
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      },
      password: { 
        type: 'string', 
        minLength: 1,
      },
      rememberMe: { 
        type: 'boolean',
      },
    },
  },
},

// Product creation endpoint
'/api/products': {
  POST: {
    required: ['name', 'price', 'category'],
    properties: {
      name: { 
        type: 'string', 
        minLength: 3,
        maxLength: 200,
      },
      description: { 
        type: 'string', 
        maxLength: 2000,
      },
      price: { 
        type: 'number', 
        min: 0,
        max: 999999.99,
      },
      category: {
        type: 'string',
        enum: ['electronics', 'clothing', 'books', 'food'],
      },
      inStock: {
        type: 'boolean',
      },
      quantity: {
        type: 'number',
        min: 0,
        max: 10000,
      },
    },
  },
},
```

**How it works**:
1. Request arrives for a configured endpoint (e.g., `POST /api/users`)
2. WAF checks if a schema is defined for that path + method
3. Validates JSON body against the schema rules
4. Returns `400 Bad Request` with detailed error if validation fails
5. Passes request to origin if validation succeeds

**Validation errors returned**:
```json
{
  "error": "Validation Error",
  "message": "Field 'email' has invalid format",
  "field": "email"
}
```

**Response codes**:
- `400 Bad Request` - Validation failed
- `200 OK` - Validation passed (request forwarded to origin)

**Configuration examples**:

```javascript
// Enable validation for specific endpoints only
payloadValidation: {
  enabled: true,
  schemas: {
    '/api/users': { /* schema */ },
    '/api/login': { /* schema */ },
  },
}

// Disable validation (skip all checks)
payloadValidation: {
  enabled: false,
  schemas: {},
}

// Different schemas for different methods
payloadValidation: {
  enabled: true,
  schemas: {
    '/api/users': {
      POST: {
        required: ['email', 'name', 'password'],
        properties: { /* creation fields */ },
      },
      PUT: {
        required: ['name'],
        properties: { /* update fields (no password) */ },
      },
      PATCH: {
        properties: { /* optional partial updates */ },
      },
    },
  },
}
```

**⚠️ Important notes**:
- Only validates JSON payloads (`Content-Type: application/json`)
- Only validates POST, PUT, and PATCH requests
- Endpoints without schemas are not validated (pass through)
- Validation happens **before** malicious pattern detection
- Unknown fields are allowed (only defined fields are validated)
- Use this for business logic validation, not security validation

**Performance**: < 2ms overhead for typical API payloads

---

### Configuration Examples by Use Case

#### Public Blog/Content Site
```javascript
const config = {
  blockedCountries: [],  // Allow all countries
  rateLimit: {
    enabled: true,
    maxRequests: 200,
    windowSeconds: 60,
  },
  blockedIPs: [],
  allowedMethods: ['GET', 'HEAD', 'OPTIONS'],  // Read-only
  maxRequestSizeBytes: 1024,  // No uploads
  blockSuspiciousPatterns: true,
};
```

#### REST API
```javascript
const config = {
  blockedCountries: ['CN', 'RU', 'KP'],  // Block high-risk regions
  rateLimit: {
    enabled: true,
    maxRequests: 60,
    windowSeconds: 60,  // 1 request per second
  },
  blockedIPs: [],
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  maxRequestSizeBytes: 1 * 1024 * 1024,  // 1MB JSON payloads
  blockSuspiciousPatterns: true,
};
```

#### Admin Panel
```javascript
const config = {
  blockedCountries: [],
  allowedIPs: ['203.0.113.0/24'],  // Only office network
  rateLimit: {
    enabled: false,  // Not needed with IP allowlist
  },
  blockedIPs: [],
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  maxRequestSizeBytes: 10 * 1024 * 1024,
  blockSuspiciousPatterns: false,  // Trusted users
};
```

#### File Upload Service
```javascript
const config = {
  blockedCountries: [],
  rateLimit: {
    enabled: true,
    maxRequests: 10,
    windowSeconds: 3600,  // 10 uploads per hour
  },
  blockedIPs: [],
  allowedMethods: ['GET', 'POST', 'OPTIONS'],
  maxRequestSizeBytes: 50 * 1024 * 1024,  // 50MB files
  blockSuspiciousPatterns: true,
};
```

#### Maximum Security (Paranoid Mode)
```javascript
const config = {
  blockedCountries: ['CN', 'RU', 'KP', 'IR', 'SY'],
  allowedCountries: ['US', 'CA', 'GB', 'FR', 'DE'],  // Strict allowlist
  rateLimit: {
    enabled: true,
    maxRequests: 30,
    windowSeconds: 60,
  },
  blockedIPs: [],  // Populated from threat feeds
  allowedMethods: ['GET', 'POST', 'OPTIONS'],
  maxRequestSizeBytes: 100 * 1024,  // 100KB max
  blockSuspiciousPatterns: true,
};
```

## Usage

### Development

Start the local development server:

```bash
npm run dev
```

The worker will be available at `http://localhost:8787`

### Testing

Test different scenarios:

```bash
# Normal request (should pass)
curl http://localhost:8787/

# Test SQL injection detection
curl "http://localhost:8787/api?id=1' OR '1'='1"

# Test XSS detection
curl "http://localhost:8787/search?q=<script>alert('xss')</script>"

# Test path traversal
curl "http://localhost:8787/../../etc/passwd"

# Test rate limiting (send many requests quickly)
for i in {1..150}; do curl http://localhost:8787/; done

# Test with blocked User-Agent
curl -A "sqlmap/1.0" http://localhost:8787/

# Test payload validation (valid)
curl -X POST http://localhost:8787/api/users \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","name":"John Doe"}'

# Test payload validation (invalid email)
curl -X POST http://localhost:8787/api/users \
  -H "Content-Type: application/json" \
  -d '{"email":"not-an-email","name":"John Doe"}'

# Test payload validation (missing required field)
curl -X POST http://localhost:8787/api/users \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

### Deployment

Deploy to Cloudflare's global network:

```bash
npm run deploy
```

After deployment, your Worker will be available at:
- `https://cloudflare-mini-waf.<your-subdomain>.workers.dev`
- Or on your custom domain (if configured)

## Code Examples

This section shows practical code examples for implementing common WAF scenarios.

### Example: Block by Country

Block all traffic from specific countries while allowing others:

```javascript
// src/index.js - Configuration
const config = {
  blockedCountries: ['CN', 'RU', 'KP', 'IR'],  // Block China, Russia, North Korea, Iran
  // ... other config
};
```

**Test it:**
```bash
# This will show your current country
curl http://localhost:8787/ | jq '.requestInfo.country'

# To test country blocking, the Worker reads the CF-IPCountry header
# In production, Cloudflare automatically adds this header
```

**Response when blocked:**
```json
{
  "error": "Access Denied",
  "reason": "Geographic restriction",
  "country": "CN"
}
```

**Alternative - Allowlist only specific countries:**
```javascript
const config = {
  allowedCountries: ['US', 'CA', 'GB', 'DE', 'FR'],  // Only allow these
  // blockedCountries is ignored when allowedCountries is set
};
```

---

### Example: Rate Limiting Setup

Protect your API from brute force attacks with distributed rate limiting:

**Step 1: Create KV Namespace**
```bash
# Create the namespace
npx wrangler kv:namespace create RATE_LIMIT

# Output will show: 
# { binding = "RATE_LIMIT", id = "abc123..." }
```

**Step 2: Configure wrangler.jsonc**
```json
{
  "name": "cloudflare-mini-waf",
  "main": "src/index.js",
  "kv_namespaces": [
    {
      "binding": "RATE_LIMIT",
      "id": "abc123..."  // Use your ID from step 1
    }
  ]
}
```

**Step 3: Enable in config**
```javascript
const config = {
  rateLimit: {
    enabled: true,
    maxRequests: 10,      // Only 10 requests
    windowSeconds: 60,    // Per minute
  },
};
```

**Step 4: Uncomment KV code in src/index.js**
```javascript
// Find this section around line 200 in src/index.js
// Remove the /* and */ comment markers

if (env.RATE_LIMIT) {
  const currentCount = await env.RATE_LIMIT.get(rateLimitKey);
  const count = currentCount ? parseInt(currentCount) : 0;
  
  if (count >= config.rateLimit.maxRequests) {
    return new Response(/* ... 429 response ... */);
  }
  
  await env.RATE_LIMIT.put(
    rateLimitKey,
    (count + 1).toString(),
    { expirationTtl: config.rateLimit.windowSeconds }
  );
}
```

**Test it:**
```bash
# Send 15 requests quickly
for i in {1..15}; do 
  curl -s http://localhost:8787/ | jq '.error // .success'
done

# First 10 show: true
# Last 5 show: "Rate Limit Exceeded"
```

**Response when rate limited:**
```json
{
  "error": "Rate Limit Exceeded",
  "reason": "Maximum 10 requests per 60 seconds",
  "retryAfter": 60
}
```

**Headers returned:**
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1737036000000
```

---

### Example: IP Allowlist for Admin Panel

Restrict admin panel access to office IP addresses only:

```javascript
// src/index.js
const config = {
  allowedIPs: [
    '203.0.113.0/24',      // Office network
    '198.51.100.50',       // VPN gateway
    '192.0.2.10',          // CEO's home IP
  ],
  // When allowedIPs is set, these IPs bypass ALL security checks
  // and all other IPs are blocked
};
```

**Test it:**
```bash
# Check what IP the Worker sees
curl http://localhost:8787/ | jq '.requestInfo.ip'

# In local dev, you'll see: "::1" (localhost)
# In production, Cloudflare adds CF-Connecting-IP header
```

**Response when blocked:**
```json
{
  "error": "Access Denied",
  "reason": "IP not in allowlist"
}
```

**Combine with path-based routing:**
```javascript
// In handleOriginRequest function
async function handleOriginRequest(request) {
  const url = new URL(request.url);
  
  // Only apply IP allowlist to admin paths
  if (url.pathname.startsWith('/admin')) {
    const clientIP = request.headers.get('CF-Connecting-IP');
    const allowed = ['203.0.113.0/24', '192.0.2.10'];
    
    if (!allowed.some(ip => matchIPOrCIDR(clientIP, ip))) {
      return new Response('Forbidden', { status: 403 });
    }
  }
  
  // Forward to origin
  return fetch(request);
}
```

---

### Example: Validate API Payloads

Validate incoming API requests before they reach your origin:

**Scenario: User Registration API**

```javascript
// src/index.js - Configuration
const config = {
  payloadValidation: {
    enabled: true,
    schemas: {
      '/api/register': {
        POST: {
          required: ['email', 'password', 'name'],
          properties: {
            email: { 
              type: 'string', 
              pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
              maxLength: 255,
            },
            password: { 
              type: 'string', 
              minLength: 8,
              maxLength: 128,
            },
            name: { 
              type: 'string', 
              minLength: 2,
              maxLength: 100,
            },
            age: { 
              type: 'number', 
              min: 13,
              max: 120,
            },
          },
        },
      },
    },
  },
};
```

**Test valid payload:**
```bash
curl -X POST http://localhost:8787/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePass123",
    "name": "John Doe",
    "age": 25
  }'
```

**Response (passes validation):**
```json
{
  "success": true,
  "message": "Request passed all WAF checks!"
}
```

**Test invalid payload (missing required field):**
```bash
curl -X POST http://localhost:8787/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePass123"
  }'
```

**Response:**
```json
{
  "error": "Validation Error",
  "message": "Missing required field: name",
  "field": "name"
}
```

**Test invalid payload (email format):**
```bash
curl -X POST http://localhost:8787/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "not-an-email",
    "password": "securePass123",
    "name": "John Doe"
  }'
```

**Response:**
```json
{
  "error": "Validation Error",
  "message": "Field 'email' has invalid format",
  "field": "email"
}
```

**Test invalid payload (age range):**
```bash
curl -X POST http://localhost:8787/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePass123",
    "name": "John Doe",
    "age": 200
  }'
```

**Response:**
```json
{
  "error": "Validation Error",
  "message": "Field 'age' must be at most 120",
  "field": "age"
}
```

**More complex example - E-commerce API:**
```javascript
'/api/products': {
  POST: {
    required: ['name', 'price', 'category'],
    properties: {
      name: { type: 'string', minLength: 3, maxLength: 200 },
      price: { type: 'number', min: 0.01, max: 999999.99 },
      category: {
        type: 'string',
        enum: ['electronics', 'clothing', 'books', 'food', 'toys'],
      },
      sku: { 
        type: 'string', 
        pattern: /^[A-Z]{3}-\d{6}$/,  // Format: ABC-123456
      },
      inStock: { type: 'boolean' },
      quantity: { type: 'number', min: 0, max: 10000 },
    },
  },
},
```

---

### Example: Custom Pattern Detection

Add custom security patterns for your specific application:

```javascript
// src/index.js - Find checkMaliciousPatterns function (around line 380)
// Add custom patterns

async function checkMaliciousPatterns(request) {
  // ... existing code ...
  
  // Add your custom patterns
  const customPatterns = [
    // Block requests with specific keywords
    /admin123/gi,
    /test_user/gi,
    
    // Block common exploit attempts
    /\$\{jndi:/gi,  // Log4Shell
    /%00/gi,         // Null byte injection
    
    // Block credential stuffing patterns
    /password.*:\s*["'].*["']/gi,
    
    // Block common bot signatures in URLs
    /wp-admin/gi,
    /phpmyadmin/gi,
  ];
  
  const fullURL = path + queryString;
  
  for (const pattern of customPatterns) {
    if (pattern.test(fullURL)) {
      return new Response(
        JSON.stringify({
          error: 'Security Violation',
          reason: 'Blocked by custom security rule',
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }
  
  // ... rest of function ...
}
```

**Test custom patterns:**
```bash
# Should be blocked
curl "http://localhost:8787/wp-admin/login.php"
curl "http://localhost:8787/api?user=admin123"

# Should pass
curl "http://localhost:8787/api?user=john_doe"
```

---

### Example: Path-Based Rules

Apply different security rules to different paths:

```javascript
// In the main fetch handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Strict rules for API endpoints
    if (url.pathname.startsWith('/api/')) {
      config.rateLimit.maxRequests = 30;  // Stricter rate limit
      config.allowedMethods = ['GET', 'POST', 'PUT', 'DELETE'];
      config.blockSuspiciousPatterns = true;
    }
    
    // Relaxed rules for static assets
    else if (url.pathname.startsWith('/assets/')) {
      config.rateLimit.maxRequests = 1000;
      config.allowedMethods = ['GET', 'HEAD'];
      config.blockSuspiciousPatterns = false;
    }
    
    // Admin panel - IP allowlist only
    else if (url.pathname.startsWith('/admin/')) {
      config.allowedIPs = ['203.0.113.0/24'];
    }
    
    // ... run security checks ...
  }
};
```

---

## Adding to an Existing Application

You can use this WAF in front of any application:

### Option 1: Custom Domain Route

1. Deploy the WAF Worker
2. Add a route in the Cloudflare dashboard:
   - Go to Workers & Pages > Your Worker > Settings > Triggers
   - Add a Custom Domain or Route
   - Example: `api.example.com/*`

### Option 2: Service Binding

Forward requests to another Worker after WAF checks:

```javascript
// src/index.js - Replace handleOriginRequest function
async function handleOriginRequest(request) {
  // Forward to another Worker via Service Binding
  return env.YOUR_APP_WORKER.fetch(request);
}
```

Configure the binding in `wrangler.jsonc`:
```json
{
  "services": [
    {
      "binding": "YOUR_APP_WORKER",
      "service": "your-app-worker-name"
    }
  ]
}
```

### Option 3: Proxy to Origin

Forward requests to your origin server:

```javascript
// src/index.js - Replace handleOriginRequest function
async function handleOriginRequest(request) {
  const url = new URL(request.url);
  const originURL = 'https://your-origin.example.com';
  const originRequest = new Request(
    originURL + url.pathname + url.search,
    request
  );
  return fetch(originRequest);
}
```

## Advanced Features

### 1. Logging and Monitoring

Add logging to track blocked requests:

```typescript
// Add to any check function
console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  action: 'blocked',
  reason: 'SQL injection detected',
  ip: request.headers.get('CF-Connecting-IP'),
  country: request.headers.get('CF-IPCountry'),
  url: request.url,
}));
```

Use Cloudflare's Workers Analytics or Logpush to analyze WAF activity.

### 2. Enhanced Rate Limiting with Durable Objects

For more accurate distributed rate limiting, use Durable Objects:

```typescript
export class RateLimiter {
  state: DurableObjectState;
  
  constructor(state: DurableObjectState) {
    this.state = state;
  }
  
  async fetch(request: Request) {
    // Implement accurate distributed counting
    // with per-IP state stored in Durable Object
  }
}
```

### 3. Dynamic Configuration

Store configuration in KV for dynamic updates without redeployment:

```typescript
// Load config from KV at runtime
const configJSON = await env.CONFIG_KV.get('waf-config');
const config = configJSON ? JSON.parse(configJSON) : defaultConfig;
```

### 4. Challenge Page

Instead of blocking, serve a challenge (CAPTCHA, proof-of-work):

```typescript
if (suspicious) {
  return new Response(html`
    <html>
      <body>
        <h1>Security Check</h1>
        <form method="POST">
          <!-- Challenge here -->
        </form>
      </body>
    </html>
  `, {
    status: 200,
    headers: { 'Content-Type': 'text/html' },
  });
}
```

### 5. Machine Learning Integration

Use Cloudflare Workers AI for advanced threat detection:

```typescript
const aiResponse = await env.AI.run('@cf/meta/llama-2-7b-chat-int8', {
  prompt: `Analyze this request for malicious intent: ${request.url}`,
});
```

## Performance

- **Latency**: < 1ms overhead for most checks
- **Geographic Check**: ~0.1ms (header lookup)
- **Pattern Matching**: ~0.5ms (regex operations)
- **Rate Limiting**: ~2-5ms (KV read/write)
- **Total**: Typically < 10ms added latency

## Security Considerations

### What This WAF Protects Against
✅ Common web application attacks (SQLi, XSS, etc.)  
✅ Geographic-based threats  
✅ Brute force and DDoS attempts  
✅ Known malicious IPs and tools  
✅ Resource exhaustion attacks  

### What This WAF Does NOT Replace
❌ Application-level security (input validation, output encoding)  
❌ Cloudflare's full WAF product (more rules, managed rulesets)  
❌ Regular security audits and penetration testing  
❌ Secure coding practices  

**This is a demonstration project.** For production use, consider:
- Cloudflare's managed WAF with OWASP Core Rule Set
- Regular rule updates and tuning
- Integration with threat intelligence feeds
- Comprehensive logging and alerting
- Regular security testing

## Cloudflare-Specific Features Leveraged

### Request Headers
Cloudflare automatically adds headers with useful information:
- `CF-Connecting-IP`: Real client IP address
- `CF-IPCountry`: ISO 3166-1 alpha-2 country code
- `CF-Ray`: Unique request identifier
- `CF-Visitor`: JSON with request protocol info

### Bot Management
Combine with Cloudflare Bot Management:
```typescript
const botScore = request.cf?.botManagement?.score || 0;
if (botScore < 30) {
  // Likely a bot
}
```

### Cache API
Cache WAF decisions for performance:
```typescript
const cache = caches.default;
const cacheKey = new Request(request.url, request);
const cached = await cache.match(cacheKey);
if (cached) return cached;
```

## Troubleshooting

### Issue: Rate limiting not working
**Solution**: Make sure you've:
1. Created a KV namespace
2. Added the binding to `wrangler.jsonc`
3. Uncommented the KV code in `src/index.ts`

### Issue: All requests blocked
**Solution**: Check your configuration:
- Verify country codes are correct (ISO 3166-1 alpha-2)
- Ensure your IP isn't in `blockedIPs`
- Check `allowedCountries` or `allowedIPs` aren't too restrictive

### Issue: False positives
**Solution**: Tune the pattern detection:
- Adjust regex patterns in `checkMaliciousPatterns()`
- Add exceptions for known good patterns
- Consider implementing a learning mode that logs but doesn't block

## Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Workers KV Docs](https://developers.cloudflare.com/kv/)
- [Durable Objects Docs](https://developers.cloudflare.com/durable-objects/)
- [Cloudflare WAF Docs](https://developers.cloudflare.com/waf/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## License

MIT License - Feel free to use and modify for your needs.

## Contributing

Contributions are welcome! Areas for improvement:
- [ ] More sophisticated pattern detection
- [ ] Machine learning integration
- [ ] Challenge page implementation
- [ ] Better CIDR matching
- [ ] Integration with threat intelligence feeds
- [ ] Customizable block pages
- [ ] Webhook notifications for blocked requests

## Author

Built to showcase Cloudflare Workers capabilities for edge security.
