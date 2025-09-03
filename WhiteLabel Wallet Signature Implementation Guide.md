# WhiteLabel Wallet Signature Solution - Quick Implementation Guide

## I. Core Problems and Solutions

### Problems
- TaskOn is embedded in partner websites through iframe
- Wallet plugins (like MetaMask) only inject objects into the top-level window, iframes cannot directly access them
- Need to support 17+ wallet types

### Solution
**Wallet Proxy Pattern**
- Partner websites provide wallet proxy services
- TaskOn requests wallet operations through postMessage
- Proxy service calls wallets and returns results

## II. Quick Integration Steps

### 2.1 Partner Website Integration (5 minutes)

```html
<!-- 1. Include wallet proxy script -->
<script src="https://cdn.taskon.xyz/whitelabel/wallet-proxy.min.js"></script>

<!-- 2. Initialize proxy service -->
<script>
const walletProxy = new WalletProxyService({
  allowedOrigins: [
    'https://taskon.xyz',
    'https://app.taskon.xyz'
  ],
  debug: false
});
</script>

<!-- 3. Embed TaskOn iframe -->
<iframe 
  id="taskon-iframe"
  src="https://taskon.xyz/embed?project=1001&wallet=proxy"
  width="100%" 
  height="600">
</iframe>
```

### 2.2 TaskOn Configuration

```typescript
// Environment variables
VUE_APP_WALLET_MODE=proxy
VUE_APP_PARENT_ORIGIN=https://project1.com
```

## III. Supported Wallet Types Quick Reference

| Wallet Type | Wallet Name | Detection Method | Supported Chains |
|---------|---------|----------|----------|
| **EVM Wallets** | MetaMask | `window.ethereum.isMetaMask` | ETH/BSC/Polygon |
| | OKX Wallet | `window.okxwallet` | Multi-chain |
| | Bitget Wallet | `window.bitkeep` | Multi-chain |
| | Binance Wallet | `window.BinanceChain` | BSC primarily |
| **Solana** | Phantom | `window.solana.isPhantom` | Solana |
| **Aptos** | Petra | `window.petra` | Aptos |
| | Martian | `window.martian` | Aptos/Sui |
| **Sui** | Suiet | `window.suiWallet` | Sui |
| **TRON** | TronLink | `window.tronLink` | TRON |
| **TON** | TonConnect | `window.ton` | TON |
| **Bitcoin** | Unisat | `window.unisat` | Bitcoin |
| **Cosmos** | Leap | `window.leap` | Cosmos ecosystem |
| **Universal** | WalletConnect | Protocol | Cross-chain mobile wallets |

## IV. Core Code Implementation

### 4.1 Wallet Proxy Service (Partner Side)

```javascript
class WalletProxyService {
  // Handle messages from iframe
  async handleMessage(event) {
    // 1. Verify origin
    if (!this.allowedOrigins.includes(event.origin)) return;
    
    // 2. Process request
    const { method, params, walletType } = event.data;
    const result = await this.processWalletRequest(method, params, walletType);
    
    // 3. Return result
    event.source.postMessage({
      id: event.data.id,
      type: 'wallet_response',
      success: true,
      result: result
    }, event.origin);
  }
  
  // Route to different wallet handlers
  async processWalletRequest(method, params, walletType) {
    switch(walletType) {
      case 'metamask':
      case 'okx':
        return this.processEVMWallet(method, params);
      case 'phantom':
        return this.processSolanaWallet(method, params);
      case 'petra':
        return this.processAptosWallet(method, params);
      // ... other wallets
    }
  }
}
```

### 4.2 Wallet Client (TaskOn iframe)

```typescript
class WalletClient {
  // Request wallet operation
  async request(method: string, params: any[]): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = this.generateRequestId();
      
      // Save request callback
      this.requestMap.set(id, { resolve, reject });
      
      // Send to parent window
      window.parent.postMessage({
        id,
        type: 'wallet_request',
        method,
        params,
        walletType: this.currentWalletType
      }, this.parentOrigin);
    });
  }
  
  // Convenience methods
  async connectWallet() {
    return this.request('eth_requestAccounts');
  }
  
  async signMessage(message: string) {
    const accounts = await this.getAccounts();
    return this.request('personal_sign', [message, accounts[0]]);
  }
}
```

## V. Typical Business Scenario Implementation

### 5.1 Wallet Login

```javascript
// TaskOn side
async function walletLogin() {
  // 1. Connect wallet
  const accounts = await walletClient.connectWallet();
  
  // 2. Construct login message
  const message = `Login to TaskOn\nAddress: ${accounts[0]}\nTimestamp: ${Date.now()}`;
  
  // 3. Request signature
  const signature = await walletClient.signMessage(message);
  
  // 4. Submit to backend for verification
  await api.verifyLogin({ address: accounts[0], signature, message });
}
```

### 5.2 Token Withdrawal

```javascript
async function withdraw() {
  // 1. Construct withdrawal message and sign
  const signature = await walletClient.signMessage(withdrawMessage);
  
  // 2. Submit to backend to generate transaction
  const txData = await api.prepareWithdraw({ signature });
  
  // 3. Send transaction
  const txHash = await walletClient.sendTransaction({
    from: account,
    to: txData.contractAddress,
    data: txData.data,
    value: '0x0'
  });
  
  // 4. Confirm transaction
  await api.confirmWithdraw({ txHash });
}
```

## VI. Security Checklist

- [ ] **Domain Whitelist**: Only accept messages from specified domains
- [ ] **Message Validation**: Verify message format and required fields
- [ ] **Timeout Handling**: 30-second request timeout
- [ ] **Error Handling**: Gracefully handle all types of errors
- [ ] **Sensitive Operation Confirmation**: Transactions require user double confirmation

## VII. Testing Points

### 7.1 Functional Testing
1. Wallet connection
2. Message signing
3. Transaction sending
4. Multi-wallet switching

### 7.2 Compatibility Testing
- Chrome/Edge + MetaMask
- Firefox + MetaMask
- Mobile + WalletConnect
- Various wallet types

### 7.3 Security Testing
- Non-whitelisted domain requests
- Malicious message injection
- Timeout handling

## VIII. Common Issues Quick Solutions

### Q: MetaMask not detected?
Check for `window.ethereum` object, ensure it's in the top-level window, not iframe.

### Q: Messages not receiving responses?
1. Check domain whitelist
2. Confirm message format
3. Check browser console for errors

### Q: How to handle mobile?
Use WalletConnect or deep links to invoke wallet apps.

## IX. Monitoring Metrics

```javascript
// Key monitoring metrics
{
  walletRequests: 0,      // Total requests
  successRate: 0,         // Success rate
  avgResponseTime: 0,     // Average response time
  walletTypes: {},        // Wallet usage statistics
  errors: []              // Error logs
}
```

## X. Deployment Architecture

```
┌─────────────────┐
│   User Browser   │
├─────────────────┤
│Partner Site(Top)│ ← Wallet plugin injection
│ ┌─────────────┐ │
│ │Wallet Proxy │ │ ← Handle wallet requests
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │TaskOn iframe│ │ ← postMessage communication
│ └─────────────┘ │
└─────────────────┘
```

## Appendix: Complete Implementation Timeline

| Phase | Task | Estimated Time | Responsible |
|-----|------|---------|--------|
| 1 | Wallet proxy service development | 2 days | TaskOn |
| 2 | SDK integration documentation | 1 day | TaskOn |
| 3 | Partner integration | 0.5 days | Partner |
| 4 | Joint testing | 1 day | Both parties |
| 5 | Production deployment | 0.5 days | Both parties |

---

**Technical Support**: For any issues, please contact the TaskOn technical team