# TaskOn WhiteLabel Integration Guide (Partner Version)

> This document is specifically written for partner technical teams to help you quickly integrate the TaskOn white-label solution

## Table of Contents

1. [Quick Start](#quick-start)
2. [Pre-integration Preparation](#pre-integration-preparation)
3. [SDK Integration](#sdk-integration)
4. [Login Method Implementation](#login-method-implementation)
5. [Sensitive Operation Handling](#sensitive-operation-handling)
6. [Testing and Verification](#testing-and-verification)
7. [Production Deployment](#production-deployment)
8. [FAQ](#faq)

---

## Quick Start

### 10-minute Quick Experience

```html
<!DOCTYPE html>
<html>
<head>
    <title>Partner Website - TaskOn Integration Example</title>
</head>
<body>
    <!-- Your website content -->
    <div id="app">
        <button onclick="login()">Login and View Tasks</button>
        <div id="taskon-container"></div>
    </div>

    <!-- Import TaskOn Partner SDK -->
    <script src="https://unpkg.com/@taskon/partner-sdk@latest"></script>
    <script>
        // Initialize SDK
        const taskonSDK = new TaskonPartnerSDK({
            domain: 'your-domain.com',         // Your domain (required)
            taskonGateway: 'https://api.taskon.xyz', // TaskOn API address (required)
            apiEndpoint: 'https://your-backend.com/api' // Your backend API address (required)
        });

        // Login function
        async function login() {
            try {
                // Example: Email login
                const email = 'user@example.com';  // Get from your system
                await taskonSDK.loginWithEmail(email);
                
                // Show TaskOn task page
                taskonSDK.showTasks('taskon-container');
            } catch (error) {
                console.error('Login failed:', error);
            }
        }
    </script>
</body>
</html>
```

---

## Pre-integration Preparation

### 1. Required Information

Please contact the TaskOn business team to obtain the following information:

| Information Item | Description | Example |
|-------|------|------|
| Domain | Your domain (needs to be registered in TaskOn) | `partner.com` |
| Private Key | Partner private key (**stored only on backend server**, used for signing) | `-----BEGIN PRIVATE KEY-----...` |
| Public Key | Partner public key (provided to TaskOn) | `-----BEGIN PUBLIC KEY-----...` |
| Test Environment URL | Test environment address | `https://test-api.taskon.xyz` |

### 2. Technical Requirements

- **Frontend**: Modern browsers supporting ES6+
- **Backend** (optional): Environment capable of sending HTTP requests if server-side signing is needed
- **Domain**: HTTPS certificate required

### 3. Install SDK

#### NPM Installation (Recommended)

```bash
npm install @taskon/partner-sdk
# or
yarn add @taskon/partner-sdk
# or
pnpm add @taskon/partner-sdk
```

#### CDN Import

```html
<!-- Production environment -->
<script src="https://unpkg.com/@taskon/partner-sdk@1.0.0/dist/index.min.js"></script>

<!-- Development environment (includes debug info) -->
<script src="https://unpkg.com/@taskon/partner-sdk@1.0.0/dist/index.js"></script>
```

---

## SDK Integration

### Initialization Configuration

```javascript
import TaskonPartnerSDK from '@taskon/partner-sdk';

const taskonSDK = new TaskonPartnerSDK({
    // Required parameters
    domain: window.location.hostname,    // Your domain (TaskOn identifies partners through this)
    taskonGateway: 'https://api.taskon.xyz', // TaskOn API address
    apiEndpoint: 'https://your-backend.com/api', // Your backend API address (for signing)
    
    // Optional parameters
    environment: 'production',           // 'production' | 'test'
    language: 'en',                      // Interface language
    theme: {                            // Custom theme
        primaryColor: '#007AFF',
        backgroundColor: '#FFFFFF',
        textColor: '#333333'
    },
    debug: false,                       // Debug mode
    
    // Callback functions
    onReady: () => {
        console.log('SDK initialization completed');
    },
    onError: (error) => {
        console.error('SDK error:', error);
    }
});
```

### SDK Working Principle

Internal SDK processing flow:
1. **Frontend calls login method**: Pass user identifier (email/wallet address)
2. **SDK requests partner backend**: Get partner signature through configured `apiEndpoint`
3. **Partner backend verifies and signs**: Verify user identity, sign with private key
4. **SDK sends to TaskOn**: Call TaskOn white-label gateway with signature
5. **TaskOn verifies and returns tokens**: Verify partner signature, return dual tokens

### SDK Core Methods

```javascript
// Check if SDK is ready
if (taskonSDK.isReady()) {
    // SDK is ready
}

// Check user login status
const isLoggedIn = await taskonSDK.isAuthenticated();

// Get current user info
const userInfo = await taskonSDK.getCurrentUser();
// Returns: { userId, email, walletAddress, ... }

// Logout
await taskonSDK.logout();

// Destroy SDK instance
taskonSDK.destroy();
```

---

## Login Method Implementation

### Method 1: Email Login

Suitable for partners with existing email account systems.

```javascript
// Step 1: User enters email password in your system
// Step 2: Your backend verifies email password
// Step 3: After successful verification, only pass email address to TaskOn

async function loginWithEmail(email, password) {
    try {
        // Step 1: Verify email password and generate signature in your backend
        const authResult = await yourBackend.authenticateEmail({
            email: email,
            password: password
        });
        // Backend returns: { success: true, signature: "...", timestamp: ... }
        
        if (!authResult.success) {
            throw new Error('Incorrect email or password');
        }
        
        // Step 2: Call SDK login method, SDK will automatically request backend for signature
        const result = await taskonSDK.loginWithEmail(email);
        
        console.log('Login successful:', result);
        // result: { success: true, userId: '...', token: '...' }
        
        // Show task page after successful login
        taskonSDK.showTasks('taskon-container');
        
    } catch (error) {
        console.error('Login failed:', error);
    }
}
```

### Method 2: Wallet Login

Supports mainstream wallets like MetaMask, WalletConnect, etc.

```javascript
async function loginWithWallet() {
    try {
        // Step 1: Connect wallet
        const accounts = await window.ethereum.request({ 
            method: 'eth_requestAccounts' 
        });
        const address = accounts[0];
        
        // Step 2: Request user signature (to verify wallet ownership)
        const message = `Login to ${window.location.hostname}\nTimestamp: ${Date.now()}`;
        const signature = await window.ethereum.request({
            method: 'personal_sign',
            params: [message, address]
        });
        
        // Step 3: Partner verifies signature (confirm user owns the wallet)
        const isValid = await verifyWalletSignature(address, signature, message);
        if (!isValid) {
            throw new Error('Signature verification failed');
        }
        
        // Step 4: Call SDK login method, SDK will automatically request backend for partner signature
        const result = await taskonSDK.loginWithWallet(address);
        
        console.log('Wallet login successful:', result);
        // result: { success: true, address: '0x...', userId: '...' }
        
        taskonSDK.showTasks('taskon-container');
        
    } catch (error) {
        if (error.code === 'USER_REJECTED') {
            console.log('User rejected signature');
        } else if (error.code === 'NO_WALLET') {
            console.log('No wallet detected');
        } else {
            console.error('Login failed:', error);
        }
    }
}
```

### Method 3: OAuth Login (Google/Facebook)

```javascript
async function loginWithOAuth(provider) {
    try {
        // Step 1: Perform OAuth flow on partner side
        let email;
        if (provider === 'google') {
            // Use Google OAuth
            const googleUser = await performGoogleOAuth();
            email = googleUser.getBasicProfile().getEmail();
        } else if (provider === 'facebook') {
            // Use Facebook OAuth
            const fbUser = await performFacebookOAuth();
            email = fbUser.email;
        }
        
        // Step 2: Call SDK login method, SDK will automatically request backend for partner signature
        const result = await taskonSDK.loginWithOAuth(provider, email);
        
        console.log('OAuth login successful:', result);
        taskonSDK.showTasks('taskon-container');
        
    } catch (error) {
        console.error('OAuth login failed:', error);
    }
}
```

### Method 4: Custom Authentication System

If you have your own authentication system, you can use custom login.

```javascript
async function loginWithCustomAuth() {
    // Step 1: Verify user identity in your backend
    const authResult = await yourBackendAuth();
    
    // Step 2: Get user identifier (email or unique ID)
    const userIdentifier = authResult.email || authResult.userId;
    
    // Step 3: Request your backend to generate partner signature
    const signResult = await yourBackend.generateSignature({
        identifier: userIdentifier
    });
    
    // Step 4: Call SDK login method, SDK will automatically request backend for partner signature
    try {
        const result = await taskonSDK.loginWithCustom(
            userIdentifier,    // User identifier
            'email'           // 'email' | 'userId' | 'phone'
        );
        
        console.log('Custom login successful:', result);
        taskonSDK.showTasks('taskon-container');
        
    } catch (error) {
        console.error('Login failed:', error);
    }
}
```

### Backend API Implementation Example

#### Node.js Backend Example

```javascript
const crypto = require('crypto');
const express = require('express');
const app = express();

// Private key saved in backend environment variables, never exposed to frontend
const PRIVATE_KEY = process.env.PROJECT_PRIVATE_KEY;

// Email login authentication endpoint
app.post('/api/auth/email', async (req, res) => {
    const { email, password } = req.body;
    
    // Verify email password
    const isValid = await verifyEmailPassword(email, password);
    if (!isValid) {
        return res.status(401).json({ success: false });
    }
    
    // Build data to sign (format agreed with TaskOn)
    const timestamp = Date.now();
    const signData = {
        domain: req.hostname,
        email: email,
        loginMethod: 'email',
        timestamp: timestamp
    };
    
    // Generate signature
    const message = JSON.stringify(signData);
    const signature = generateSignature(message);
    
    res.json({
        success: true,
        signature: signature,
        timestamp: timestamp,
        signData: signData  // Return signed data for SDK use
    });
});

// Wallet login authentication endpoint
app.post('/api/auth/wallet', async (req, res) => {
    const { address, userSignature, message } = req.body;
    
    // Verify user's wallet signature
    const isValid = await verifyWalletSignature(address, userSignature, message);
    if (!isValid) {
        return res.status(401).json({ success: false });
    }
    
    // Build data to sign (format agreed with TaskOn)
    const timestamp = Date.now();
    const signData = {
        domain: req.hostname,
        walletAddress: address,
        loginMethod: 'wallet',
        timestamp: timestamp
    };
    
    // Generate signature
    const message = JSON.stringify(signData);
    const signature = generateSignature(message);
    
    res.json({
        success: true,
        signature: signature,
        timestamp: timestamp,
        signData: signData  // Return signed data for SDK use
    });
});

// Generate signature function
function generateSignature(message) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(message);
    sign.end();
    return sign.sign(PRIVATE_KEY, 'hex');
}
```

---

## Display Task Page

### Basic Display

```javascript
// Display task list in specified container
taskonSDK.showTasks('taskon-container', {
    // Optional configuration
    height: '600px',        // iframe height
    width: '100%',          // iframe width
    defaultTab: 'active',   // Default tab: 'active' | 'completed' | 'all'
    hideHeader: false,      // Whether to hide header
    hideNavigation: false,  // Whether to hide navigation
});
```

### Advanced Control

```javascript
// Show specific task
taskonSDK.showTask(taskId);

// Show task details modal
taskonSDK.openTaskModal(taskId);

// Refresh task list
taskonSDK.refreshTasks();

// Get task list data (without showing UI)
const tasks = await taskonSDK.getTasks({
    status: 'active',  // 'active' | 'completed' | 'all'
    page: 1,
    pageSize: 20
});
```

### Event Listening

```javascript
// Listen to task completion events
taskonSDK.on('task:completed', (event) => {
    console.log('Task completed:', event.taskId);
    // You can trigger your reward logic here
});

// Listen to user clicking tasks
taskonSDK.on('task:clicked', (event) => {
    console.log('User clicked task:', event.taskId);
});

// Listen to iframe load completion
taskonSDK.on('iframe:loaded', () => {
    console.log('Task page loaded');
});

// Remove event listener
taskonSDK.off('task:completed', handler);
```

---

## Sensitive Operation Handling

For sensitive operations of white-label users (withdrawal, unbinding, etc.), if they are TaskOn old users, email verification will be required.

### Dual Token Mechanism Explanation

TaskOn white-label uses dual token mechanism to ensure security and compatibility:
- **Primary Token**: Standard JWT format, 100% compatible with existing systems
- **Shadow Token**: Carries white-label metadata (old user status, email, etc.)

SDK automatically manages dual tokens, partners don't need to worry about specific implementation.

### Automatic Handling (Recommended)

SDK will automatically handle verification code flow, no additional development needed.

```javascript
// SDK will automatically show verification code input box
async function withdraw() {
    try {
        const result = await taskonSDK.withdraw({
            tokenId: 1,
            amount: '100',
            toAddress: '0x...',
            chain: 'ethereum'
        });
        
        // If verification code is needed, SDK will handle automatically
        console.log('Withdrawal successful:', result);
        
    } catch (error) {
        console.error('Withdrawal failed:', error);
    }
}
```

### Custom UI Handling

If you want to customize verification code input interface:

```javascript
// Configure custom verification code handler
taskonSDK.setVerificationHandler({
    // Called when verification code is required
    onVerificationRequired: async (operation) => {
        // Show your custom UI
        const code = await showCustomVerificationModal();
        return code;
    },
    
    // Verification code sent successfully
    onCodeSent: (email) => {
        showToast(`Verification code sent to ${email}`);
    },
    
    // Verification failed
    onVerificationFailed: (error) => {
        showError('Verification code error, please try again');
    }
});
```

---

## Testing and Verification

### Test Environment Configuration

```javascript
// Use test environment
const taskonSDK = new TaskonPartnerSDK({
    domain: 'test.partner.com',
    taskonGateway: 'https://test-api.taskon.xyz',  // Test API address
    apiEndpoint: 'https://test-backend.partner.com/api',  // Test backend API address
    environment: 'test',  // Switch to test environment
    debug: true  // Enable debug mode
});
```

### Test Case Checklist

#### 1. Login Flow Testing

```javascript
// Test script
async function runLoginTests() {
    const tests = [
        // Test email login
        async () => {
            const result = await taskonSDK.loginWithEmail('test@example.com');
            assert(result.success === true, 'Email login failed');
        },
        
        // Test duplicate login
        async () => {
            await taskonSDK.loginWithEmail('test@example.com');
            const isAuth = await taskonSDK.isAuthenticated();
            assert(isAuth === true, 'Login status abnormal');
        },
        
        // Test logout
        async () => {
            await taskonSDK.logout();
            const isAuth = await taskonSDK.isAuthenticated();
            assert(isAuth === false, 'Logout failed');
        }
    ];
    
    for (const test of tests) {
        try {
            await test();
            console.log('✅ Test passed');
        } catch (error) {
            console.error('❌ Test failed:', error);
        }
    }
}
```

#### 2. Task Display Testing

```javascript
// Check if iframe loads correctly
taskonSDK.on('iframe:loaded', () => {
    const iframe = document.querySelector('#taskon-container iframe');
    console.assert(iframe !== null, 'iframe not created');
    console.assert(iframe.src.includes('taskon'), 'iframe URL error');
});

taskonSDK.showTasks('taskon-container');
```

#### 3. Cross-domain Communication Testing

```javascript
// Test message communication
taskonSDK.on('message', (event) => {
    console.log('Message received:', event);
});

// Send test message
taskonSDK.sendMessage('ping');
```

### Debug Tools

```javascript
// Enable detailed logging
taskonSDK.enableDebug();

// View current state
console.log('SDK state:', taskonSDK.getState());
// Output: { isReady: true, isAuthenticated: true, user: {...} }

// View configuration info
console.log('SDK configuration:', taskonSDK.getConfig());

// Simulate error
taskonSDK.simulateError('NETWORK_ERROR');
```

---

## Production Deployment

### Pre-deployment Checklist

- [ ] Use production environment Partner ID and Community ID
- [ ] Switch to production environment API address
- [ ] Turn off debug mode
- [ ] Configure correct domain whitelist
- [ ] Implement error monitoring and log collection
- [ ] Set CSP policy to allow TaskOn domains
- [ ] Ensure HTTPS certificate is valid
- [ ] Test mainstream browser compatibility

### Security Configuration

#### 1. Content Security Policy (CSP)

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               frame-src https://*.taskon.xyz; 
               script-src 'self' https://unpkg.com; 
               connect-src https://*.taskon.xyz;">
```

#### 2. Domain Whitelist

Configure allowed domains in TaskOn backend:
- Production domain: `https://your-domain.com`
- Test domain: `https://test.your-domain.com`
- Development domain: `http://localhost:3000`

#### 3. Signature Verification

```javascript
// Backend verify request signature
function verifyWebhook(request) {
    const signature = request.headers['x-taskon-signature'];
    const timestamp = request.headers['x-taskon-timestamp'];
    
    // Verify timestamp (prevent replay attacks)
    if (Date.now() - timestamp > 5 * 60 * 1000) {
        throw new Error('Request expired');
    }
    
    // Verify signature
    const expected = generateSignature(request.body, timestamp);
    if (signature !== expected) {
        throw new Error('Signature verification failed');
    }
    
    return true;
}
```

### Performance Optimization

```javascript
// 1. Lazy load SDK
const loadTaskonSDK = () => {
    return import('@taskon/partner-sdk').then(module => {
        window.taskonSDK = new module.default(config);
    });
};

// 2. Pre-connection optimization
<link rel="preconnect" href="https://api.taskon.xyz">
<link rel="dns-prefetch" href="https://api.taskon.xyz">

// 3. Cache user state
const cachedUser = localStorage.getItem('taskon_user');
if (cachedUser) {
    taskonSDK.restoreSession(JSON.parse(cachedUser));
}
```

### Monitoring and Logging

```javascript
// Error monitoring
window.addEventListener('error', (event) => {
    if (event.error && event.error.source === 'taskon-sdk') {
        // Send to your monitoring system
        reportError({
            type: 'taskon_sdk_error',
            error: event.error,
            user: taskonSDK.getCurrentUser()
        });
    }
});

// Performance monitoring
taskonSDK.on('performance', (metrics) => {
    console.log('Performance metrics:', metrics);
    // metrics: { loadTime, apiLatency, renderTime }
});
```

---

## FAQ

### Q1: User can't see tasks after login

**Possible causes:**
1. User hasn't joined community
2. Community ID configuration error
3. Tasks not published or expired

**Solutions:**
```javascript
// Check user community status
const communities = await taskonSDK.getUserCommunities();
console.log('User communities:', communities);

// Manually join community (if needed)
await taskonSDK.joinCommunity(communityId);
```

### Q2: Cross-origin error: blocked by CORS policy

**Solutions:**
1. Confirm domain is configured in TaskOn backend whitelist
2. SDK uses postMessage for cross-domain communication, automatically handles cross-origin issues
3. If manually calling API, need to add correct request headers:
```javascript
// SDK automatically handles cross-domain communication
// Internally uses postMessage to communicate with iframe
// If directly calling TaskOn API, need:
headers: {
    'X-Partner-Domain': window.location.hostname,
    'X-Shadow-Token': shadowToken  // Shadow token for white-label users
}
```

### Q3: Safari browser can't maintain login state

**Reason:** Safari's ITP (Intelligent Tracking Prevention) restrictions

**Solutions:**
```javascript
// SDK automatically uses localStorage as fallback
// You can also manually configure:
const taskonSDK = new TaskonPartnerSDK({
    storage: 'localStorage',  // Force use localStorage
    // ... other configurations
});
```

### Q4: How to handle user duplicate login

```javascript
// SDK handles automatically, but you can listen to events:
taskonSDK.on('auth:duplicate', (event) => {
    console.log('User logged in elsewhere');
    // Optional: Prompt user
    if (confirm('Your account is logged in elsewhere, do you want to re-login?')) {
        taskonSDK.forceLogin();
    }
});
```

### Q5: Mobile adaptation issues

```javascript
// Responsive configuration
taskonSDK.showTasks('container', {
    responsive: true,
    mobileBreakpoint: 768,
    mobileConfig: {
        height: '100vh',
        hideHeader: true
    }
});
```

---

## Technical Support

### Get Help

- 📧 Technical support email: dev-support@taskon.xyz
- 📚 Complete API documentation: https://docs.taskon.xyz/whitelabel
- 💬 Developer community: https://discord.gg/taskon-dev
- 🐛 Issue feedback: https://github.com/taskon/partner-sdk/issues

### Changelog

View latest version and updates:
```bash
npm view @taskon/partner-sdk versions
npm view @taskon/partner-sdk@latest
```

### Example Code

Complete example projects:
- React example: https://github.com/taskon/examples/react
- Vue example: https://github.com/taskon/examples/vue
- Vanilla JS example: https://github.com/taskon/examples/vanilla

---

## Appendix

### SDK Method Quick Reference

| Method | Description | Return Value |
|------|------|--------|
| `loginWithEmail(email)` | Email login (SDK automatically requests backend signature) | Promise<LoginResult> |
| `loginWithWallet(address)` | Wallet login (SDK automatically requests backend signature) | Promise<LoginResult> |
| `loginWithOAuth(provider, email)` | OAuth login (SDK automatically requests backend signature) | Promise<LoginResult> |
| `logout()` | Logout | Promise<void> |
| `isAuthenticated()` | Check login status | Promise<boolean> |
| `getCurrentUser()` | Get user info | Promise<User> |
| `showTasks(container)` | Show task list | void |
| `getTasks(options)` | Get task data | Promise<Task[]> |
| `on(event, handler)` | Listen to events | void |
| `off(event, handler)` | Remove listener | void |

### Error Code Reference

| Error Code | Description | Handling Suggestion |
|--------|------|----------|
| `AUTH_FAILED` | Authentication failed | Check login parameters |
| `NETWORK_ERROR` | Network error | Retry request |
| `INVALID_DOMAIN` | Invalid domain | Check domain configuration |
| `USER_NOT_IN_COMMUNITY` | User not in community | Call joinCommunity |
| `SESSION_EXPIRED` | Session expired | Re-login |
| `VERIFICATION_REQUIRED` | Verification required | SDK handles automatically |

---

*Document version: 1.0.0*  
*Last updated: 2025-08-25*  
*Compatible SDK version: ^1.0.0*