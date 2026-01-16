/**
 * Cloudflare Mini WAF (Web Application Firewall)
 * 
 * This Worker demonstrates various security capabilities that can be implemented
 * at the edge using Cloudflare Workers. It acts as a protective layer in front of
 * your origin server, blocking malicious requests before they reach your infrastructure.
 * 
 * Features demonstrated:
 * - Geographic blocking/allowing by country
 * - Rate limiting with distributed counting
 * - Request method validation
 * - Path traversal attack prevention
 * - SQL injection detection
 * - XSS (Cross-Site Scripting) detection
 * - Request size validation
 * - Custom security headers
 * - IP allowlist/blocklist
 * - User-Agent validation
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
	// Example: Block requests from specific countries
	// ISO 3166-1 alpha-2 country codes
	blockedCountries: ['CN', 'RU'], // China, Russia
	// allowedCountries: ['US', 'CA', 'GB'], // Uncomment to whitelist only specific countries
	
	// Rate limiting configuration
	rateLimit: {
		enabled: true,
		maxRequests: 100, // Maximum requests per IP
		windowSeconds: 60, // Time window in seconds
	},
	
	// IP-based filtering
	blockedIPs: [
		'192.0.2.1', // Example blocked IP
		'198.51.100.0/24', // Example blocked CIDR range
	],
	// allowedIPs: ['203.0.113.0/24'], // Trusted IPs that bypass all checks
	
	// HTTP method restrictions
	allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
	
	// Maximum request body size (10MB)
	maxRequestSizeBytes: 10 * 1024 * 1024,
	
	// Enable/disable pattern-based attack detection
	blockSuspiciousPatterns: true,
};

// ============================================================================
// SECURITY FUNCTIONS
// ============================================================================

/**
 * GEOGRAPHIC BLOCKING
 * 
 * Cloudflare automatically provides the country code in the request headers.
 * This allows you to block or allow traffic based on geographic location.
 * 
 * Use cases:
 * - Comply with data residency requirements
 * - Block traffic from high-risk regions
 * - Implement geo-fencing for region-specific services
 */
function checkGeographicRestrictions(request) {
	// Cloudflare adds the 'CF-IPCountry' header with ISO 3166-1 alpha-2 country code
	const country = request.headers.get('CF-IPCountry') || 'XX';
	
	// Check if country is blocked
	if (config.blockedCountries.includes(country)) {
		return new Response(
			JSON.stringify({
				error: 'Access Denied',
				reason: 'Geographic restriction',
				country: country,
			}),
			{
				status: 403,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	}
	
	// If allowedCountries is set, only allow those countries
	if (config.allowedCountries && !config.allowedCountries.includes(country)) {
		return new Response(
			JSON.stringify({
				error: 'Access Denied',
				reason: 'Country not in allowlist',
				country: country,
			}),
			{
				status: 403,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	}
	
	return null; // Pass the check
}

/**
 * IP ADDRESS FILTERING
 * 
 * Block or allow specific IP addresses or CIDR ranges.
 * Cloudflare provides the real client IP even behind proxies.
 * 
 * Use cases:
 * - Block known malicious IPs
 * - Whitelist office IPs for admin panels
 * - Implement IP-based access control
 */
function checkIPRestrictions(request) {
	// Cloudflare provides the real client IP in the 'CF-Connecting-IP' header
	const clientIP = request.headers.get('CF-Connecting-IP') || '';
	
	// If allowlist is defined, only allow those IPs (skip all other checks)
	if (config.allowedIPs) {
		const isAllowed = config.allowedIPs.some(ip => matchIPOrCIDR(clientIP, ip));
		if (!isAllowed) {
			return new Response(
				JSON.stringify({
					error: 'Access Denied',
					reason: 'IP not in allowlist',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
		return null; // IP is allowed, skip other checks
	}
	
	// Check if IP is blocked
	const isBlocked = config.blockedIPs.some(ip => matchIPOrCIDR(clientIP, ip));
	if (isBlocked) {
		return new Response(
			JSON.stringify({
				error: 'Access Denied',
				reason: 'IP address blocked',
			}),
			{
				status: 403,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	}
	
	return null; // Pass the check
}

/**
 * Simple IP/CIDR matcher (basic implementation)
 * In production, use a proper CIDR library or Cloudflare's IP Lists
 */
function matchIPOrCIDR(clientIP, pattern) {
	// Exact match
	if (pattern === clientIP) return true;
	
	// CIDR range check (simplified - for demo purposes)
	if (pattern.includes('/')) {
		const [network, bits] = pattern.split('/');
		// This is a simplified check - in production use a proper CIDR library
		return clientIP.startsWith(network.split('.').slice(0, Math.floor(parseInt(bits) / 8)).join('.'));
	}
	
	return false;
}

/**
 * RATE LIMITING
 * 
 * Implement distributed rate limiting using Cloudflare Workers KV or Durable Objects.
 * This example shows the logic flow - in production you would use KV or Durable Objects
 * to maintain state across edge locations.
 * 
 * Use cases:
 * - Prevent brute force attacks
 * - Mitigate DDoS attempts
 * - Enforce API usage limits
 * - Protect against credential stuffing
 * 
 * IMPLEMENTATION NOTE:
 * To make this fully functional, you need to:
 * 1. Add a KV namespace binding in wrangler.jsonc:
 *    "kv_namespaces": [{ "binding": "RATE_LIMIT", "id": "your-kv-id" }]
 * 2. Or use Durable Objects for more accurate distributed counting
 * 3. Or use the Cloudflare Rate Limiting API
 */
async function checkRateLimit(request, env) {
	if (!config.rateLimit.enabled) return null;
	
	const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
	const rateLimitKey = `ratelimit:${clientIP}`;
	
	// NOTE: This requires a KV namespace binding named 'RATE_LIMIT'
	// Uncomment and configure KV in wrangler.jsonc to use this
	/*
	if (env.RATE_LIMIT) {
		// Get current request count for this IP
		const currentCount = await env.RATE_LIMIT.get(rateLimitKey);
		const count = currentCount ? parseInt(currentCount) : 0;
		
		if (count >= config.rateLimit.maxRequests) {
			// Get TTL to inform user when they can retry
			const metadata = await env.RATE_LIMIT.getWithMetadata(rateLimitKey);
			
			return new Response(
				JSON.stringify({
					error: 'Rate Limit Exceeded',
					reason: `Maximum ${config.rateLimit.maxRequests} requests per ${config.rateLimit.windowSeconds} seconds`,
					retryAfter: config.rateLimit.windowSeconds,
				}),
				{
					status: 429,
					headers: {
						'Content-Type': 'application/json',
						'Retry-After': config.rateLimit.windowSeconds.toString(),
						'X-RateLimit-Limit': config.rateLimit.maxRequests.toString(),
						'X-RateLimit-Remaining': '0',
						'X-RateLimit-Reset': (Date.now() + config.rateLimit.windowSeconds * 1000).toString(),
					},
				}
			);
		}
		
		// Increment counter with expiration
		await env.RATE_LIMIT.put(
			rateLimitKey,
			(count + 1).toString(),
			{ expirationTtl: config.rateLimit.windowSeconds }
		);
	}
	*/
	
	// For demo purposes, we'll just log that rate limiting would happen here
	console.log(`Rate limit check for ${clientIP} - would track against KV namespace`);
	
	return null; // Pass the check
}

/**
 * HTTP METHOD VALIDATION
 * 
 * Restrict which HTTP methods are allowed.
 * Prevents attackers from using uncommon HTTP methods.
 * 
 * Use cases:
 * - Block TRACE/TRACK methods to prevent XST attacks
 * - Restrict methods for specific endpoints
 * - Enforce RESTful API contracts
 */
function checkHTTPMethod(request) {
	const method = request.method.toUpperCase();
	
	if (!config.allowedMethods.includes(method)) {
		return new Response(
			JSON.stringify({
				error: 'Method Not Allowed',
				method: method,
				allowedMethods: config.allowedMethods,
			}),
			{
				status: 405,
				headers: {
					'Content-Type': 'application/json',
					'Allow': config.allowedMethods.join(', '),
				},
			}
		);
	}
	
	return null; // Pass the check
}

/**
 * REQUEST SIZE VALIDATION
 * 
 * Limit the size of incoming requests to prevent resource exhaustion.
 * 
 * Use cases:
 * - Prevent memory exhaustion attacks
 * - Enforce upload size limits
 * - Protect downstream services with size constraints
 */
function checkRequestSize(request) {
	const contentLength = request.headers.get('Content-Length');
	
	if (contentLength) {
		const size = parseInt(contentLength);
		
		if (size > config.maxRequestSizeBytes) {
			return new Response(
				JSON.stringify({
					error: 'Payload Too Large',
					maxSize: config.maxRequestSizeBytes,
					requestedSize: size,
				}),
				{
					status: 413,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	return null; // Pass the check
}

/**
 * MALICIOUS PATTERN DETECTION
 * 
 * Detect common attack patterns in URLs and request bodies.
 * Includes checks for:
 * - SQL Injection attempts
 * - Cross-Site Scripting (XSS)
 * - Path traversal attacks
 * - Command injection attempts
 * 
 * Use cases:
 * - Block common web application attacks
 * - Protect legacy applications without WAF
 * - Add defense-in-depth security layer
 */
async function checkMaliciousPatterns(request) {
	if (!config.blockSuspiciousPatterns) return null;
	
	const url = new URL(request.url);
	const path = url.pathname;
	const queryString = url.search;
	
	// SQL Injection patterns
	const sqlPatterns = [
		/(\%27)|(\')|(\-\-)|(\%23)|(#)/i, // SQL comments and quotes
		/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i, // SQL operators
		/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i, // ' OR
		/((\%27)|(\'))union/i, // UNION attacks
		/exec(\s|\+)+(s|x)p\w+/i, // SQL Server exec
	];
	
	// XSS patterns
	const xssPatterns = [
		/<script[^>]*>[\s\S]*?<\/script>/gi, // Script tags
		/javascript:/gi, // JavaScript protocol
		/on\w+\s*=/gi, // Event handlers (onclick, onerror, etc.)
		/<iframe/gi, // iFrame injection
		/eval\(/gi, // eval function
		/<object/gi, // Object tags
		/<embed/gi, // Embed tags
	];
	
	// Path traversal patterns
	const pathTraversalPatterns = [
		/\.\.\//g, // ../ sequences
		/\.\.\\/g, // ..\ sequences
		/%2e%2e%2f/gi, // URL encoded ../
		/%252e%252e%252f/gi, // Double URL encoded ../
		/\.\.\%2f/gi, // Mixed encoding
	];
	
	// Command injection patterns
	const commandInjectionPatterns = [
		/;\s*(ls|cat|wget|curl|bash|sh|cmd|powershell)/gi,
		/\|\s*(ls|cat|wget|curl|bash|sh|cmd|powershell)/gi,
		/`.*`/g, // Backtick command execution
		/\$\(.*\)/g, // Command substitution
	];
	
	// Check URL path and query string
	const fullURL = path + queryString;
	
	// Check for SQL injection
	for (const pattern of sqlPatterns) {
		if (pattern.test(fullURL)) {
			return new Response(
				JSON.stringify({
					error: 'Security Violation',
					reason: 'Potential SQL injection detected',
					blockedPattern: 'SQL injection pattern',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	// Check for XSS
	for (const pattern of xssPatterns) {
		if (pattern.test(fullURL)) {
			return new Response(
				JSON.stringify({
					error: 'Security Violation',
					reason: 'Potential XSS attack detected',
					blockedPattern: 'XSS pattern',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	// Check for path traversal
	for (const pattern of pathTraversalPatterns) {
		if (pattern.test(fullURL)) {
			return new Response(
				JSON.stringify({
					error: 'Security Violation',
					reason: 'Path traversal attack detected',
					blockedPattern: 'Path traversal pattern',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	// Check for command injection
	for (const pattern of commandInjectionPatterns) {
		if (pattern.test(fullURL)) {
			return new Response(
				JSON.stringify({
					error: 'Security Violation',
					reason: 'Command injection attempt detected',
					blockedPattern: 'Command injection pattern',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	// Check request body for POST/PUT/PATCH requests
	if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
		try {
			// Clone the request so we can read the body
			const clonedRequest = request.clone();
			const contentType = request.headers.get('Content-Type') || '';
			
			// Only check text-based content types
			if (contentType.includes('application/json') || 
				contentType.includes('application/x-www-form-urlencoded') ||
				contentType.includes('text/')) {
				
				const body = await clonedRequest.text();
				
				// Check body against all patterns
				const allPatterns = [
					...sqlPatterns,
					...xssPatterns,
					...commandInjectionPatterns,
				];
				
				for (const pattern of allPatterns) {
					if (pattern.test(body)) {
						return new Response(
							JSON.stringify({
								error: 'Security Violation',
								reason: 'Malicious pattern detected in request body',
							}),
							{
								status: 403,
								headers: { 'Content-Type': 'application/json' },
							}
						);
					}
				}
			}
		} catch (e) {
			// If we can't read the body, let it pass (might be streaming or binary)
			console.error('Error reading request body:', e);
		}
	}
	
	return null; // Pass the check
}

/**
 * USER-AGENT VALIDATION
 * 
 * Block suspicious or missing User-Agent headers.
 * Many bots and automated attacks have distinctive User-Agents.
 * 
 * Use cases:
 * - Block known malicious bot signatures
 * - Require valid User-Agent headers
 * - Block headless browser signatures
 */
function checkUserAgent(request) {
	const userAgent = request.headers.get('User-Agent') || '';
	
	// Block requests with no User-Agent (optional - can be strict)
	// Uncomment to enforce User-Agent presence
	/*
	if (!userAgent) {
		return new Response(
			JSON.stringify({
				error: 'Bad Request',
				reason: 'User-Agent header required',
			}),
			{
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	}
	*/
	
	// Block known malicious bot patterns
	const blockedUserAgents = [
		/sqlmap/i, // SQL injection tool
		/nikto/i, // Web server scanner
		/masscan/i, // Port scanner
		/nmap/i, // Network scanner
		/acunetix/i, // Vulnerability scanner
		/burpsuite/i, // Penetration testing tool
	];
	
	for (const pattern of blockedUserAgents) {
		if (pattern.test(userAgent)) {
			return new Response(
				JSON.stringify({
					error: 'Access Denied',
					reason: 'Blocked User-Agent',
				}),
				{
					status: 403,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	}
	
	return null; // Pass the check
}

/**
 * ADD SECURITY HEADERS
 * 
 * Add security-related headers to all responses.
 * These headers help protect against various attacks.
 * 
 * Headers added:
 * - X-Content-Type-Options: Prevent MIME sniffing
 * - X-Frame-Options: Prevent clickjacking
 * - X-XSS-Protection: Enable XSS filter in older browsers
 * - Strict-Transport-Security: Enforce HTTPS
 * - Content-Security-Policy: Control resource loading
 * - Referrer-Policy: Control referrer information
 * - Permissions-Policy: Control browser features
 */
function addSecurityHeaders(response) {
	const newResponse = new Response(response.body, response);
	
	// Prevent MIME sniffing
	newResponse.headers.set('X-Content-Type-Options', 'nosniff');
	
	// Prevent clickjacking
	newResponse.headers.set('X-Frame-Options', 'SAMEORIGIN');
	
	// XSS protection for older browsers
	newResponse.headers.set('X-XSS-Protection', '1; mode=block');
	
	// Enforce HTTPS (HSTS) - 1 year max-age
	newResponse.headers.set(
		'Strict-Transport-Security',
		'max-age=31536000; includeSubDomains; preload'
	);
	
	// Content Security Policy (adjust based on your needs)
	newResponse.headers.set(
		'Content-Security-Policy',
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
	);
	
	// Referrer policy
	newResponse.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
	
	// Permissions policy (formerly Feature-Policy)
	newResponse.headers.set(
		'Permissions-Policy',
		'geolocation=(), microphone=(), camera=()'
	);
	
	// Add custom WAF header
	newResponse.headers.set('X-WAF-Protected', 'Cloudflare-Mini-WAF');
	
	return newResponse;
}

// ============================================================================
// MAIN WORKER HANDLER
// ============================================================================

export default {
	async fetch(request, env, ctx) {
		try {
			// Check if IP is in allowlist (bypasses all checks)
			if (config.allowedIPs) {
				const clientIP = request.headers.get('CF-Connecting-IP') || '';
				const isAllowlisted = config.allowedIPs.some(ip => matchIPOrCIDR(clientIP, ip));
				if (isAllowlisted) {
					// Skip all security checks for allowlisted IPs
					return handleOriginRequest(request);
				}
			}
			
			// Run security checks in order
			// Each function returns Response | null
			// If Response is returned, the request is blocked
			
			// 1. Geographic restrictions
			const geoCheck = checkGeographicRestrictions(request);
			if (geoCheck) return addSecurityHeaders(geoCheck);
			
			// 2. IP-based filtering
			const ipCheck = checkIPRestrictions(request);
			if (ipCheck) return addSecurityHeaders(ipCheck);
			
			// 3. Rate limiting
			const rateLimitCheck = await checkRateLimit(request, env);
			if (rateLimitCheck) return addSecurityHeaders(rateLimitCheck);
			
			// 4. HTTP method validation
			const methodCheck = checkHTTPMethod(request);
			if (methodCheck) return addSecurityHeaders(methodCheck);
			
			// 5. Request size validation
			const sizeCheck = checkRequestSize(request);
			if (sizeCheck) return addSecurityHeaders(sizeCheck);
			
			// 6. User-Agent validation
			const userAgentCheck = checkUserAgent(request);
			if (userAgentCheck) return addSecurityHeaders(userAgentCheck);
			
			// 7. Malicious pattern detection (SQL injection, XSS, etc.)
			const patternCheck = await checkMaliciousPatterns(request);
			if (patternCheck) return addSecurityHeaders(patternCheck);
			
			// All checks passed - forward to origin or return success
			const response = await handleOriginRequest(request);
			return addSecurityHeaders(response);
			
		} catch (error) {
			// Log error and return generic error response
			console.error('WAF Error:', error);
			
			return addSecurityHeaders(
				new Response(
					JSON.stringify({
						error: 'Internal Server Error',
						message: 'An error occurred processing your request',
					}),
					{
						status: 500,
						headers: { 'Content-Type': 'application/json' },
					}
				)
			);
		}
	},
};

/**
 * HANDLE ORIGIN REQUEST
 * 
 * This function handles the actual request after all security checks pass.
 * In a real implementation, you would:
 * 1. Forward the request to your origin server
 * 2. Or use a Service Binding to route to another Worker
 * 3. Or serve static content from R2/KV
 * 
 * For this demo, we return a success response with request information.
 */
async function handleOriginRequest(request) {
	// DEMO: Return information about the request
	// In production, you would forward to your origin:
	// return fetch(request);
	
	const url = new URL(request.url);
	
	// Example: Forward to origin server
	// const originURL = 'https://your-origin.example.com';
	// const originRequest = new Request(originURL + url.pathname + url.search, request);
	// return fetch(originRequest);
	
	return new Response(
		JSON.stringify({
			success: true,
			message: 'Request passed all WAF checks!',
			requestInfo: {
				method: request.method,
				path: url.pathname,
				country: request.headers.get('CF-IPCountry'),
				ip: request.headers.get('CF-Connecting-IP'),
				userAgent: request.headers.get('User-Agent'),
				timestamp: new Date().toISOString(),
			},
		}, null, 2),
		{
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		}
	);
}
