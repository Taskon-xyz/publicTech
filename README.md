# TaskOn WhiteLabel Solution - Technical Documentation

## 📖 Overview

This repository contains the complete technical documentation for TaskOn's WhiteLabel solution, designed to enable seamless integration of TaskOn's community and reward features into partner websites through iframe embedding with silent login capabilities.

## 🎯 Background & Requirements

### Core Business Requirements
The WhiteLabel solution addresses the need for partners to integrate TaskOn functionality while maintaining their brand identity and user experience:

- **Silent Login**: Users logged into partner websites automatically access TaskOn features without re-authentication
- **Transparent Authorization**: All authorization operations occur under partner domains without redirects
- **Automatic Community Joining**: Users automatically join corresponding TaskOn communities when accessing through partner sites
- **Brand Consistency**: TaskOn features appear as native partner functionality through customizable theming

### Key Technical Challenges

#### 1. Cross-Domain Authentication
- **Challenge**: iframe-embedded TaskOn cannot access partner authentication tokens due to browser security restrictions
- **Solution**: Dual token mechanism (Primary Token + Shadow Token) with server-side mapping

#### 2. Wallet Integration in iframe Context  
- **Challenge**: Wallet plugins (MetaMask, etc.) only inject into top-level windows, not iframes
- **Solution**: Wallet Proxy Pattern using postMessage communication

#### 3. Security & Asset Protection
- **Challenge**: Existing TaskOn users accessing through partner sites may have historical assets that need protection
- **Solution**: Multi-factor verification for sensitive operations based on user classification

#### 4. System Compatibility
- **Challenge**: Minimize changes to existing TaskOn architecture while adding WhiteLabel capabilities
- **Solution**: Middleware-based architecture with configuration-driven customization

## 📚 Technical Documentation Suite

### 1. Core Architecture & Implementation

#### [WhiteLabel Technical Solution.md](./WhiteLabel%20Technical%20Solution.md)
**Main technical specification document** - Comprehensive 2,700+ line technical blueprint covering the complete WhiteLabel architecture including:
- Dual token authentication mechanism
- Component interaction diagrams and sequence flows
- Backend service design (7 new components, 3 modified components)
- Frontend SDK architecture and integration patterns
- Database schema and deployment architecture
- Security considerations and performance optimization strategies

#### [WhiteLabel Technical Solution - Component Detailed Design.md](./WhiteLabel%20Technical%20Solution%20-%20Component%20Detailed%20Design.md)
**Detailed component implementation guide** - In-depth technical specifications for each system component including:
- Token Manager with JWT handling and lifecycle management
- WhiteLabel Config Service with partner domain mapping
- Community Service integration for automatic user onboarding  
- SDK implementations for both iframe and partner website integration
- API gateway modifications and middleware implementations
- Complete code examples and interface definitions

### 2. Integration & Implementation Guides

#### [WhiteLabel Partner Integration Guide.md](./WhiteLabel%20Partner%20Integration%20Guide.md)
**Partner-facing integration manual** - Step-by-step guide for partners implementing WhiteLabel integration:
- SDK installation and configuration procedures
- Multiple authentication method support (wallet, email, OAuth, custom)
- Frontend integration examples and best practices
- API usage documentation with request/response samples
- Troubleshooting guide and common integration issues

#### [WhiteLabel Implementation Guide.md](./WhiteLabel%20Implementation%20Guide.md) 
**Development team implementation handbook** - Comprehensive guide for TaskOn developers:
- Phase-by-phase implementation roadmap
- Component development priorities and dependencies  
- Testing strategies and quality assurance procedures
- Deployment configurations and environment setup
- Monitoring and maintenance procedures

### 3. Specialized Technical Solutions

#### [WhiteLabel Wallet Signature Technical Solution.md](./WhiteLabel%20Wallet%20Signature%20Technical%20Solution.md)
**Wallet integration technical specification** - Advanced solution for blockchain wallet integration in iframe contexts:
- Wallet Proxy Pattern implementation supporting 17+ wallet types (MetaMask, Phantom, Petra, etc.)
- Cross-domain postMessage communication protocols
- Multi-chain support architecture (Ethereum, Solana, Aptos, Sui, TRON, TON, Bitcoin, Cosmos)
- Security measures including domain whitelisting and message validation
- Error handling and fallback mechanisms for various wallet scenarios

#### [WhiteLabel Wallet Signature Implementation Guide.md](./WhiteLabel%20Wallet%20Signature%20Implementation%20Guide.md)
**Quick implementation guide for wallet integration** - Streamlined 5-minute integration guide:
- Partner website integration code examples
- Supported wallet type quick reference table
- Core proxy service implementation patterns
- Common business scenarios (login, withdrawal, transaction signing)
- Security checklist and testing procedures

#### [WhiteLabel Third-Party OAuth Technical Solution.md](./WhiteLabel%20Third-Party%20OAuth%20Technical%20Solution.md)
**OAuth integration comprehensive specification** - Complete OAuth 2.0 integration solution:
- Multi-provider OAuth support (Google, Facebook, Twitter, custom providers)
- Secure token exchange mechanisms and validation procedures
- Cross-domain state management and session handling
- Privacy compliance and data protection measures
- Integration sequence diagrams and API specifications

### 4. Security & Compatibility Solutions

#### [WhiteLabel Sensitive Operation Design Concept.md](./WhiteLabel%20Sensitive%20Operation%20Design%20Concept.md)
**Security framework design philosophy** - Advanced security design for protecting user assets:
- User classification system (main site users vs. WhiteLabel existing/new users)
- Shadow Token metadata-based user identification mechanism
- Multi-factor authentication requirements for sensitive operations (withdrawals, account changes)
- Email verification code system implementation
- Performance optimization through token-embedded user state

#### [WhiteLabel Token Compatibility Solution.md](./WhiteLabel%20Compatibility%20Solution.md)
**Authentication compatibility framework** - Zero-intrusion token compatibility system:
- Dual token architecture ensuring 100% backward compatibility
- Shadow token implementation with WhiteLabel metadata
- Token lifecycle management and refresh mechanisms
- Mapping relationships and cache strategies
- Integration with existing authentication systems

### 5. Project Overview & Planning

#### [WhiteLabel Solution Overview.md](./WhiteLabel%20Solution%20Overview.md)
**Executive summary and project scope** - High-level overview document covering:
- Business requirements and market positioning
- Technical approach and architectural decisions
- Component overview and responsibility matrix
- Implementation phases and timeline estimates
- Risk assessment and mitigation strategies

## 🔧 Technical Architecture Summary

### System Components

**New Components (7):**
- Token Manager (TM) - Dual token lifecycle management
- WhiteLabel Config Service (WLC) - Partner configuration management  
- WhiteLabel Community Service (WLCS) - Automatic community joining
- WhiteLabel Gateway (WLG) - Unified API entry point
- WhiteLabel Auth Handler (WLM) - Authentication coordination
- WhiteLabel SDK (WLS) - iframe-embedded SDK
- Partner SDK (PSDK) - Partner website integration SDK

**Modified Components (3):**
- Auth Middleware - Extended for WhiteLabel token support
- API Router - Added WhiteLabel-specific routing
- Community Page Component - iframe-optimized UI rendering

### Key Technologies
- **Backend**: Go + Chi router, MySQL + Redis
- **Frontend**: Vue 3 + TypeScript, postMessage communication
- **Authentication**: JWT with dual token architecture
- **Integration**: iframe embedding with SDK-based communication

## 🚀 Getting Started

1. **For Partners**: Start with [WhiteLabel Partner Integration Guide.md](./WhiteLabel%20Partner%20Integration%20Guide.md)
2. **For Developers**: Begin with [WhiteLabel Technical Solution.md](./WhiteLabel%20Technical%20Solution.md) and [WhiteLabel Implementation Guide.md](./WhiteLabel%20Implementation%20Guide.md)
3. **For Specific Features**: Refer to specialized solution documents for wallet integration, OAuth, or security requirements

## 📋 Implementation Status

All documentation represents the complete technical specification ready for implementation. The solution provides:

- ✅ **Minimal Code Intrusion**: Middleware and SDK-based approach
- ✅ **Multi-Partner Support**: Configuration-driven tenant isolation  
- ✅ **Security Compliance**: Advanced user classification and verification
- ✅ **Performance Optimized**: Token-embedded metadata and caching strategies
- ✅ **Extensive Compatibility**: Support for 17+ wallet types and multiple auth methods

---

*For technical support and implementation assistance, refer to the detailed documentation or contact the TaskOn technical team.*