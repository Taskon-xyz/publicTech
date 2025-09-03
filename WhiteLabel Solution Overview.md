# TaskOn WhiteLabel Technical Solution Documentation Overview

## Document Structure

This white-label technical solution includes two documents:

### 1. WhiteLabel Technical Solution.md (Main Solution)

- **Positioning**: Overall architecture design and implementation guide
- **Content**:
  - Solution overview and technical principles
  - Core component list and brief descriptions
  - Key code snippets and interface definitions
  - Detailed sequence diagrams (5 diagrams)
  - Database design
  - Deployment architecture
  - Implementation plan

### 2. WhiteLabel Technical Solution - Component Detailed Design.md (Detailed Design)

- **Positioning**: Complete implementation code for components
- **Content**:
  - Complete implementation of 6 new components
  - Detailed modification code for 3 refactored components
  - Integration testing solution

## Component List

### New Components (6)

#### 1. Token Manager (TM)
- **Type**: Backend service component
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/token/`
- **Documentation Location**: Main solution section 2.1.1, Detailed design - Chapter 1 - Section 1
- **Content Logic Description**:
  - Responsible for generating and managing dual tokens (main token + shadow token)
  - Main token maintains standard format unchanged, ensuring 100% compatibility with existing systems
  - Shadow token carries white-label metadata (old user status, email, etc.) for partner use
  - Handles token lifecycle management: creation, validation, refresh, revocation
  - Maintains mapping relationship from shadow token to main token
- **Global Link Role**:
  - Core component for identity authentication, foundation of the entire white-label solution
  - Generates token pairs during login flow, validates token validity in subsequent requests
  - Solves cross-domain authentication issues, enables user identity transfer between different domains

#### 2. WhiteLabel Config Service (WLC)
- **Type**: Backend configuration management service
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/service/whitelabel_config.go`
- **Documentation Location**: Main solution section 2.1.2, Detailed design - Chapter 1 - Section 2
- **Content Logic Description**:
  - Manages partner white-label configuration information (domain, community ID, theme, etc.)
  - Provides CRUD interfaces for configuration
  - Implements configuration caching mechanism for improved query performance
  - Supports dynamic configuration updates without service restart
- **Global Link Role**:
  - Provides partner configuration information to other components
  - Determines user's partner and corresponding community during login
  - Controls white-label display style and behavior customization

#### 3. WhiteLabel Community Service (WLCS)
- **Type**: Backend business logic service
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/service/community_whitelabel.go`
- **Documentation Location**: Main solution section 2.1.3
- **Content Logic Description**:
  - Encapsulates existing community joining logic, implements silent join functionality
  - Automatically joins users to specified communities based on partner configuration
  - Handles establishment and maintenance of community member relationships
  - Provides batch joining and asynchronous processing capabilities
- **Global Link Role**:
  - Automatically executes community joining after successful user login
  - Ensures partner users automatically become corresponding community members
  - Implements core "silent join" requirement

#### 4. WhiteLabel Auth Handler (WLM)
- **Type**: Backend coordination layer component
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/api/auth/whitelabel_handler.go`
- **Documentation Location**: Detailed design - Chapter 1 - Section 3
- **Content Logic Description**:
  - Coordinates token manager, configuration service, user service, community service
  - Handles complete white-label login flow
  - Validates partner signatures, determines user status
  - Generates and manages dual tokens
- **Global Link Role**:
  - Core coordinator for white-label authentication
  - Connects gateway layer and service layer
  - Implements business logic assembly and orchestration

#### 5. WhiteLabel Gateway (WLG)
- **Type**: Backend API gateway
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/gateway/whitelabel_gateway.go`
- **Documentation Location**: Main solution section 2.1.5
- **Content Logic Description**:
  - Uniformly handles all white-label related API requests
  - Implements request routing, parameter validation, response formatting
  - Provides cross-origin support (CORS configuration)
  - Integrates middleware for rate limiting, monitoring, logging
- **Global Link Role**:
  - Unified entry point for white-label functionality
  - Calls WhiteLabelAuthHandler to handle business logic
  - Provides cross-origin support (CORS configuration)
- **Global Link Role**:
  - Unified entry point for white-label functionality
  - Forwards requests to white-label authentication handler
  - Ensures API security and consistency

#### 6. WhiteLabel SDK (WLS)
- **Type**: Frontend JavaScript SDK
- **Project**: taskon-website
- **Implementation Location**: `taskon-website/packages/website/src/sdk/taskon-whitelabel-sdk.ts`
- **Documentation Location**: Main solution section 3.1.1
- **Content Logic Description**:
  - Runs inside TaskOn iframe, handles white-label mode detection
  - Manages cross-domain communication (postMessage)
  - Handles token storage and automatic refresh
  - Applies white-label styles and themes
- **Global Link Role**:
  - Core controller inside iframe
  - Communicates with partner SDK, receives tokens and commands
  - Ensures TaskOn functionality works properly in iframe

#### 7. Partner SDK (PSDK)
- **Type**: Frontend npm package
- **Project**: New independent npm package
- **Implementation Location**: `@taskon/partner-sdk`
- **Documentation Location**: Main solution section 3.1.2, Detailed design - Chapter 1 - Section 3
- **Content Logic Description**:
  - Runs on partner website, handles user login
  - Supports multiple login methods (wallet, email, OAuth, custom)
  - Manages iframe creation and communication
  - Handles wallet signature, email verification, OAuth callbacks and other login requests
  - Provides unified login interface adapting different authentication methods
  - Implements authorization UI and user interactions
- **Global Link Role**:
  - Main tool for partner integration
  - Connects partner systems with TaskOn white-label services
  - Simplifies partner integration work

### New Middleware (1)

#### WhiteLabel Sensitive Operation Middleware (WLSOM)
- **Type**: Backend security middleware
- **Project**: taskon-server
- **Implementation Location**: `taskon-server/api/middleware/whitelabel_sensitive.go`
- **Documentation Location**: Main solution section 7.4, Detailed design section 2.4
- **Content Logic Description**:
  - Identifies TaskOn old users among white-label users
  - Requires email verification code for sensitive operations (binding, unbinding, withdrawal, etc.)
  - Sends and verifies email verification codes
  - Does not affect normal operation flow of main site users
- **Global Link Role**:
  - Enhances account security for white-label users
  - Prevents unauthorized sensitive operations
  - Protects old users' assets and account information

### Refactored Components (3)

#### 1. WhiteLabel Middleware (WLM)
- **Type**: Backend middleware
- **Project**: taskon-server
- **Modification Location**: `taskon-server/api/auth/auth.go`
- **Documentation Location**: Main solution section 2.2.1
- **Modification Content Description**:
  - Extends white-label token validation based on existing JWT authentication
  - Identifies white-label requests, calls token manager for validation
  - Extracts user information and permissions from tokens
  - Supports transparent switching of dual token mechanism
  - **New**: Marks user source (white-label/main site) for sensitive operation verification
- **Global Link Role**:
  - First checkpoint of authentication
  - Uniformly handles standard login and white-label login
  - Ensures backward compatibility, no impact on existing users
  - **New**: Provides user source information for sensitive operation middleware

#### 2. API Routes
- **Type**: Backend route configuration
- **Project**: taskon-server
- **Modification Location**: `taskon-server/httpserver/httpserver.go`
- **Documentation Location**: Main solution section 2.2.2, Detailed design - Chapter 2 - Section 2
- **Modification Content Description**:
  - Registers white-label route group in Start method
  - Adds /api/whitelabel/* path handling
  - Configures white-label specific CORS policy
  - Integrates white-label middleware
- **Global Link Role**:
  - Routes white-label requests to correct handlers
  - Ensures white-label API isolation from standard API
  - Provides unified access entry point

#### 3. Community Page Component
- **Type**: Frontend Vue component
- **Project**: taskon-website
- **Modification Location**: `taskon-website/apps/website/src/views/consumer/CommunityPage/`
- **Documentation Location**: Main solution section 3.2.1, Detailed design - Chapter 2 - Section 1
- **Modification Content Description**:
  - Detects iframe embedding mode (IS_IN_IFRAME)
  - Adjusts UI display based on white-label mode
  - Hides unnecessary navigation and branding elements
  - Applies partner custom styles
- **Global Link Role**:
  - Interface users ultimately see
  - Adapts to iframe display requirements
  - Ensures consistent user experience

## Usage Guide

### For Architects and Technical Decision Makers

1. First read the **Main Solution** to understand overall architecture
2. Focus on **Sequence Diagrams** to understand system interaction flows
3. View **Component Interaction Relationship Diagram** to understand dependencies

### For Developers

1. Find corresponding chapters in **Main Solution** based on responsible components
2. For complete implementation code, check **Detailed Design** document
3. Reference **Integration Testing Solution** to write test cases

### For Project Managers

1. View implementation plan in **Main Solution** (Section 6)
2. Understand **Core Component Description** to evaluate development workload
3. Focus on **Implementation Risks** section for risk management

## Technical Highlights

### Core Design Patterns

- **Dual Token Mechanism**: Solves cross-domain authentication issues
- **Strategy Pattern**: Supports multiple partner configurations
- **Adapter Pattern**: Unifies different login systems (wallet, email, OAuth, etc.)
- **Configuration-Driven**: Minimizes code modifications
- **Multi-Authentication Support**: Flexibly supports Web3 and Web2 login methods

### Key Innovation Points

1. **Silent Login**: Users automatically log into TaskOn without awareness
2. **Transparent Authorization**: Complete authorization under partner domain
3. **Multiple Authentication Methods**:
   - Wallet signature login (MetaMask, etc.)
   - Email login (partner validates then passes email)
   - Google/Facebook OAuth login (partner validates then passes email)
   - Custom authentication system (partner validates then passes user identifier)
4. **Minimal Intrusion**: Reduce modifications to existing code through middleware and SDK encapsulation
5. **Good Scalability**: Support parallel access by multiple partners
6. **Security Enhancement**: White-label old users require email verification codes for sensitive operations

## Implementation Recommendations

1. **POC Phase**

   - Select one partner for pilot testing
   - Verify cross-domain communication and token mechanism
   - Test browser compatibility
2. **Development Phase**

   - Develop according to component priority order
   - Backend first, frontend follows
   - Continuous integration testing
3. **Deployment Phase**

   - Gradual release
   - Monitor key metrics
   - Collect feedback for optimization

## Documentation System

### Core Documents (3)

1. **WhiteLabel Technical Solution.md** - Architecture design and technical principles
2. **WhiteLabel Technical Solution - Component Detailed Design.md** - Complete implementation code
3. **WhiteLabel Implementation Guide.md** - Implementation steps and operations guide

### Document Relationship Diagram

```
WhiteLabel Solution Overview.md (This document)
    ├── WhiteLabel Technical Solution.md
    │   ├── Technical feasibility analysis
    │   ├── Technical principles and sequence diagrams
    │   ├── Component brief descriptions
    │   └── Implementation plan
    ├── WhiteLabel Technical Solution - Component Detailed Design.md
    │   ├── Complete code for new components
    │   ├── Detailed code for refactored components
    │   └── Integration testing solution
    └── WhiteLabel Implementation Guide.md
        ├── Development step guidance
        ├── Testing and deployment
        ├── Partner integration
        └── Operations monitoring
```

## Risk Points

### Technical Risks

1. **Browser Compatibility**

   - Safari ITP restrictions
   - Third-party Cookie limitations
   - Mitigation: localStorage + postMessage backup solution
2. **Performance Risks**

   - Cross-domain communication latency
   - Token validation overhead
   - Mitigation: Multi-level caching strategy

### Business Risks

1. **Partner Integration Willingness**

   - Requires partner cooperation
   - Mitigation: Provide comprehensive SDK and documentation
2. **User Experience**

   - Silent login may fail
   - Mitigation: Fallback to explicit login

## Notes

- Cross-domain cookies may be restricted in browsers like Safari, backup solutions needed
- iframe communication needs to handle various edge cases
- Ensure partner cooperation in SDK integration
- Perform security audits to prevent XSS and CSRF attacks

---

*This document was last updated: 2025/08/28*