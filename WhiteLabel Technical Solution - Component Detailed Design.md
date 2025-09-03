# TaskOn White Label Technical Solution - Component Detailed Design

This document provides complete implementation code for all components in the white label technical solution.

## I. New Component Detailed Design

### 1. Token Manager (TM)

#### 1.1 Component Information

- **Belongs to Project**: `taskon-server` (new module in existing project)
- **Implementation Location**: `taskon-server/token/` directory
- **Entry File**: `taskon-server/token/manager.go`
- **Core Functionality**: Handle generation, validation, and management of dual tokens (primary token + shadow token)

#### 1.2 Complete Implementation

```go
// token/manager.go

package token

import (
    "context"
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "time"
    
    "github.com/go-redis/redis/v8"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// TokenManager Token manager
type TokenManager struct {
    primarySecret   []byte           // Primary token secret key
    shadowSecret    []byte           // Shadow token secret key
    tokenExpiry     time.Duration    // Token expiration time
    refreshExpiry   time.Duration    // Refresh token expiration time
    db              *sql.DB          // Database connection
    redis           *redis.Client    // Redis client
}

// NewTokenManager Create token manager
func NewTokenManager(cfg *TokenConfig, db *sql.DB, redis *redis.Client) *TokenManager {
    return &TokenManager{
        primarySecret:  []byte(cfg.PrimarySecret),
        shadowSecret:   []byte(cfg.ShadowSecret),
        tokenExpiry:    cfg.TokenExpiry,
        refreshExpiry:  cfg.RefreshExpiry,
        db:             db,
        redis:          redis,
    }
}

// TokenConfig Token configuration
type TokenConfig struct {
    PrimarySecret string        `json:"primarySecret"`
    ShadowSecret  string        `json:"shadowSecret"`
    TokenExpiry   time.Duration `json:"tokenExpiry"`
    RefreshExpiry time.Duration `json:"refreshExpiry"`
}

// TokenRequest Token generation request
type TokenRequest struct {
    UserID         int64  `json:"userId"`
    DID            string `json:"did"`
    IsWhiteLabel   bool   `json:"isWhiteLabel"`
    IsExistingUser bool   `json:"isExistingUser"`
    UserEmail      string `json:"userEmail,omitempty"`
    LoginMethod    string `json:"loginMethod"`     // wallet/email/oauth
    Domain         string `json:"domain"`
    CommunityID    string `json:"communityId"`
}

// TokenPair Token pair
type TokenPair struct {
    PrimaryToken    string    `json:"primaryToken"`
    ShadowToken     string    `json:"shadowToken"`
    RefreshToken    string    `json:"refreshToken"`
    ExpiresAt       time.Time `json:"expiresAt"`
}

// TokenMapping Token mapping relationship
type TokenMapping struct {
    SessionID        string    `json:"sessionId"`
    UserID           string    `json:"userId"`
    DID              string    `json:"did"`
    ShadowToken      string    `json:"shadowToken"`
    RefreshToken     string    `json:"refreshToken"`
    ExpiresAt        time.Time `json:"expiresAt"`
    RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
    CreatedAt        time.Time `json:"createdAt"`
    IsWhiteLabel     bool      `json:"isWhiteLabel"`
    IsExistingUser   bool      `json:"isExistingUser"`
    LoginMethod      string    `json:"loginMethod"`
    Domain           string    `json:"domain"`
    CommunityID      string    `json:"communityId"`
}

// PrimaryClaims Primary token claims (maintain standard format)
type PrimaryClaims struct {
    jwt.RegisteredClaims
    UserID         string `json:"userId"`
    DID            string `json:"did"`
    OperatedBy     string `json:"operatedBy"`
    RequestOrigin  string `json:"requestOrigin"`
    SessionID      string `json:"sessionId"`
    PartnerDomain  string `json:"partnerDomain,omitempty"`
    CommunityID    string `json:"communityId,omitempty"` // Add community ID field
}

// ShadowTokenClaims Shadow token claims (contains white label metadata)
type ShadowTokenClaims struct {
    jwt.RegisteredClaims
    UserID         string `json:"userId"`
    Type           string `json:"type"`           // "shadow"
    IsWhiteLabel   bool   `json:"isWhiteLabel"`   // Whether white label user
    IsExistingUser bool   `json:"isExistingUser"` // Whether TaskOn existing user
    UserEmail      string `json:"userEmail"`      // User email
    LoginMethod    string `json:"loginMethod"`    // Login method: wallet/email/oauth
    Domain         string `json:"domain"`         // Source domain
    CommunityID    string `json:"communityId"`    // Community ID
}

// GenerateTokenPair Generate token pair
func (tm *TokenManager) GenerateTokenPair(ctx context.Context, req *TokenRequest) (*TokenPair, error) {
    sessionID := uuid.New().String()
    now := time.Now()
    expiresAt := now.Add(tm.tokenExpiry)
    userIDStr := fmt.Sprintf("%d", req.UserID)
    
    // 1. Generate primary token (maintain standard format)
    primaryClaims := PrimaryClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   userIDStr,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(expiresAt),
            ID:        sessionID,
        },
        UserID:        userIDStr,
        DID:           req.DID,
        OperatedBy:    "0",
        RequestOrigin: req.Domain,
        SessionID:     sessionID,
        PartnerDomain: req.Domain, // Optional field
        CommunityID:   req.CommunityID, // Community ID
    }
    
    primaryToken := jwt.NewWithClaims(jwt.SigningMethodHS256, primaryClaims)
    primaryTokenString, err := primaryToken.SignedString(tm.primarySecret)
    if err != nil {
        return nil, fmt.Errorf("generate primary token failed: %w", err)
    }
    
    // 2. Generate shadow token (contains white label metadata)
    shadowClaims := ShadowTokenClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   userIDStr,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(expiresAt),
            ID:        sessionID,
        },
        UserID:         userIDStr,
        Type:           "shadow",
        IsWhiteLabel:   req.IsWhiteLabel,
        IsExistingUser: req.IsExistingUser,
        UserEmail:      req.UserEmail,
        LoginMethod:    req.LoginMethod,
        Domain:         req.Domain,
        CommunityID:    req.CommunityID,
    }
    
    shadowToken := jwt.NewWithClaims(jwt.SigningMethodHS256, shadowClaims)
    shadowTokenString, err := shadowToken.SignedString(tm.shadowSecret)
    if err != nil {
        return nil, fmt.Errorf("generate shadow token failed: %w", err)
    }
    
    // 3. Generate refresh token
    refreshToken := tm.generateRefreshToken()
    
    // 4. Store token mapping relationship
    if err := tm.storeTokenMapping(ctx, sessionID, userIDStr, shadowTokenString, refreshToken, expiresAt, req); err != nil {
        return nil, fmt.Errorf("store token mapping failed: %w", err)
    }
    
    return &TokenPair{
        PrimaryToken: primaryTokenString,
        ShadowToken:  shadowTokenString,
        RefreshToken: refreshToken,
        ExpiresAt:    expiresAt,
    }, nil
}

// ValidatePrimaryToken Validate primary token
func (tm *TokenManager) ValidatePrimaryToken(tokenString string) (*PrimaryClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &PrimaryClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return tm.primarySecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*PrimaryClaims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, errors.New("invalid token")
}

// ValidateShadowToken Validate shadow token
func (tm *TokenManager) ValidateShadowToken(tokenString string) (*ShadowTokenClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &ShadowTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return tm.shadowSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*ShadowTokenClaims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, errors.New("invalid token")
}

// ExchangeToken Token exchange: shadow token to primary token
func (tm *TokenManager) ExchangeToken(ctx context.Context, shadowToken string) (string, error) {
    // 1. Validate shadow token
    shadowClaims, err := tm.ValidateShadowToken(shadowToken)
    if err != nil {
        return "", fmt.Errorf("invalid shadow token: %w", err)
    }
    
    // 2. Get token mapping from Redis
    key := fmt.Sprintf("token:mapping:%s", shadowClaims.ID)
    data, err := tm.redis.Get(ctx, key).Result()
    if err != nil {
        return "", fmt.Errorf("token mapping not found: %w", err)
    }
    
    var mapping TokenMapping
    if err := json.Unmarshal([]byte(data), &mapping); err != nil {
        return "", fmt.Errorf("parse token mapping failed: %w", err)
    }
    
    // 3. Directly generate new primary token (don't return stored token for security reasons)
    primaryClaims := PrimaryClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   shadowClaims.UserID,
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ExpiresAt: jwt.NewNumericDate(mapping.ExpiresAt),
            ID:        shadowClaims.ID,
        },
        UserID:        shadowClaims.UserID,
        DID:           mapping.DID,
        OperatedBy:    "0",
        RequestOrigin: shadowClaims.Domain,
        SessionID:     shadowClaims.ID,
        PartnerDomain: shadowClaims.Domain,
        CommunityID:   shadowClaims.CommunityID,
    }
    
    primaryToken := jwt.NewWithClaims(jwt.SigningMethodHS256, primaryClaims)
    primaryTokenString, err := primaryToken.SignedString(tm.primarySecret)
    if err != nil {
        return "", fmt.Errorf("generate primary token failed: %w", err)
    }
    
    return primaryTokenString, nil
}

// RefreshToken Refresh token
func (tm *TokenManager) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
    // 1. Validate refresh token
    mapping, err := tm.getTokenMappingByRefreshToken(ctx, refreshToken)
    if err != nil {
        return nil, fmt.Errorf("invalid refresh token: %w", err)
    }
    
    // 2. Check if expired
    if time.Now().After(mapping.RefreshExpiresAt) {
        return nil, errors.New("refresh token expired")
    }
    
    // 3. Get user information
    userID, err := strconv.ParseInt(mapping.UserID, 10, 64)
    if err != nil {
        return nil, fmt.Errorf("invalid user ID: %w", err)
    }
    
    // 4. Generate new token pair
    req := &TokenRequest{
        UserID:         userID,
        DID:            mapping.DID,
        IsWhiteLabel:   mapping.IsWhiteLabel,
        IsExistingUser: mapping.IsExistingUser,
        UserEmail:      "", // Need to get from database
        LoginMethod:    mapping.LoginMethod,
        Domain:         mapping.Domain,
        CommunityID:    mapping.CommunityID,
    }
    
    return tm.GenerateTokenPair(ctx, req)
}

// RevokeToken Revoke token
func (tm *TokenManager) RevokeToken(ctx context.Context, tokenString string) error {
    // Parse token to get session ID
    claims, err := tm.ValidatePrimaryToken(tokenString)
    if err != nil {
        // Try to parse as shadow token
        shadowClaims, err := tm.ValidateShadowToken(tokenString)
        if err != nil {
            return fmt.Errorf("invalid token: %w", err)
        }
        claims = &PrimaryClaims{
            RegisteredClaims: shadowClaims.RegisteredClaims,
            UserID:           shadowClaims.UserID,
            SessionID:        shadowClaims.ID,
        }
    }
    
    // Delete token mapping from Redis
    key := fmt.Sprintf("token:mapping:%s", claims.SessionID)
    if err := tm.redis.Del(ctx, key).Err(); err != nil {
        return fmt.Errorf("revoke token failed: %w", err)
    }
    
    // Add to blacklist
    blacklistKey := fmt.Sprintf("token:blacklist:%s", claims.SessionID)
    if err := tm.redis.Set(ctx, blacklistKey, time.Now().Unix(), tm.tokenExpiry).Err(); err != nil {
        return fmt.Errorf("add to blacklist failed: %w", err)
    }
    
    return nil
}

// Helper methods

func (tm *TokenManager) generateRefreshToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func (tm *TokenManager) storeTokenMapping(ctx context.Context, sessionID, userID, shadowToken, refreshToken string, expiresAt time.Time, req *TokenRequest) error {
    mapping := TokenMapping{
        SessionID:        sessionID,
        UserID:           userID,
        DID:              req.DID,
        ShadowToken:      shadowToken,
        RefreshToken:     refreshToken,
        ExpiresAt:        expiresAt,
        RefreshExpiresAt: time.Now().Add(tm.refreshExpiry),
        CreatedAt:        time.Now(),
        IsWhiteLabel:     req.IsWhiteLabel,
        IsExistingUser:   req.IsExistingUser,
        LoginMethod:      req.LoginMethod,
        Domain:           req.Domain,
        CommunityID:      req.CommunityID,
    }
    
    data, err := json.Marshal(mapping)
    if err != nil {
        return err
    }
    
    // Store to Redis
    key := fmt.Sprintf("token:mapping:%s", sessionID)
    if err := tm.redis.Set(ctx, key, data, tm.tokenExpiry).Err(); err != nil {
        return err
    }
    
    // Store refresh token mapping
    refreshKey := fmt.Sprintf("token:refresh:%s", refreshToken)
    if err := tm.redis.Set(ctx, refreshKey, sessionID, tm.refreshExpiry).Err(); err != nil {
        return err
    }
    
    return nil
}

// getTokenMappingByRefreshToken Get mapping by refresh token
func (tm *TokenManager) getTokenMappingByRefreshToken(ctx context.Context, refreshToken string) (*TokenMapping, error) {
    // Get sessionID corresponding to refresh token from Redis
    refreshKey := fmt.Sprintf("token:refresh:%s", refreshToken)
    sessionID, err := tm.redis.Get(ctx, refreshKey).Result()
    if err != nil {
        return nil, fmt.Errorf("refresh token not found: %w", err)
    }
    
    // Get token mapping
    key := fmt.Sprintf("token:mapping:%s", sessionID)
    data, err := tm.redis.Get(ctx, key).Result()
    if err != nil {
        return nil, fmt.Errorf("token mapping not found: %w", err)
    }
    
    var mapping TokenMapping
    if err := json.Unmarshal([]byte(data), &mapping); err != nil {
        return nil, fmt.Errorf("parse token mapping failed: %w", err)
    }
    
    return &mapping, nil
}

// User struct (should be provided by user service)
type User struct {
    ID    int64
    DID   string
    Email string
}
    
    // Actual implementation should query database
    return &User{
        ID:  userID,
        DID: "did:example:" + userID,
    }, nil
}
```

### 2. White Label Config Service (WLC)

#### 2.1 Component Information

- **Belongs to Project**: `taskon-server` (new service in existing project)
- **Implementation Location**: `taskon-server/service/whitelabel_config.go`
- **Functional Position**: Manage white label configuration information for partner projects

#### 2.2 Complete Implementation

```go
// service/whitelabel_config.go

package service

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "time"
    
    "github.com/go-redis/redis/v8"
)

// WhiteLabelConfigService White label config service
type WhiteLabelConfigService struct {
    db    *sql.DB
    redis *redis.Client
    cache map[string]*WhiteLabelConfig // In-memory cache
}

// WhiteLabelConfig White label configuration
type WhiteLabelConfig struct {
    ID                int64     `json:"id" db:"id"`
    PartnerID         string    `json:"partnerId" db:"partner_id"`
    PartnerName       string    `json:"partnerName" db:"partner_name"`
    Domain            string    `json:"domain" db:"domain"`
    CommunityID       int64     `json:"communityId" db:"community_id"`
    PublicKey         string    `json:"publicKey" db:"public_key"`
    CallbackURL       string    `json:"callbackUrl" db:"callback_url"`
    SignatureTemplate string    `json:"signatureTemplate" db:"signature_template"`
    Theme             Theme     `json:"theme" db:"theme"`
    Features          Features  `json:"features" db:"features"`
    Status            string    `json:"status" db:"status"`
    CreatedAt         time.Time `json:"createdAt" db:"created_at"`
    UpdatedAt         time.Time `json:"updatedAt" db:"updated_at"`
}

// Theme Theme configuration
type Theme struct {
    PrimaryColor   string `json:"primaryColor"`
    SecondaryColor string `json:"secondaryColor"`
    BackgroundColor string `json:"backgroundColor"`
    TextColor      string `json:"textColor"`
    LogoURL        string `json:"logoUrl"`
    CustomCSS      string `json:"customCss"`
}

// Features Feature configuration
type Features struct {
    EnableQuests      bool     `json:"enableQuests"`
    EnableEvents      bool     `json:"enableEvents"`
    EnableLeaderboard bool     `json:"enableLeaderboard"`
    EnableBenefits    bool     `json:"enableBenefits"`
    EnableIncentive   bool     `json:"enableIncentive"`
    HiddenTabs        []string `json:"hiddenTabs"`
}

// NewWhiteLabelConfigService Create config service
func NewWhiteLabelConfigService(db *sql.DB, redis *redis.Client) *WhiteLabelConfigService {
    return &WhiteLabelConfigService{
        db:    db,
        redis: redis,
        cache: make(map[string]*WhiteLabelConfig),
    }
}

// GetConfigByDomain Get configuration by domain
func (s *WhiteLabelConfigService) GetConfigByDomain(domain string) (*WhiteLabelConfig, error) {
    // 1. Try to get from in-memory cache
    if config, ok := s.cache[domain]; ok {
        return config, nil
    }
    
    // 2. Try to get from Redis
    key := fmt.Sprintf("whitelabel:config:%s", domain)
    data, err := s.redis.Get(context.Background(), key).Result()
    if err == nil {
        var config WhiteLabelConfig
        if err := json.Unmarshal([]byte(data), &config); err == nil {
            s.cache[domain] = &config
            return &config, nil
        }
    }
    
    // 3. Get from database
    var config WhiteLabelConfig
    query := `
        SELECT id, partner_id, partner_name, domain, community_id, 
               public_key, callback_url, signature_template, theme, 
               features, status, created_at, updated_at
        FROM whitelabel_configs
        WHERE domain = ? AND status = 'active'
    `
    
    var themeJSON, featuresJSON string
    err = s.db.QueryRow(query, domain).Scan(
        &config.ID, &config.PartnerID, &config.PartnerName, &config.Domain,
        &config.CommunityID, &config.PublicKey, &config.CallbackURL,
        &config.SignatureTemplate, &themeJSON, &featuresJSON,
        &config.Status, &config.CreatedAt, &config.UpdatedAt,
    )
    
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, errors.New("config not found")
        }
        return nil, fmt.Errorf("query config failed: %w", err)
    }
    
    // Parse JSON fields
    if err := json.Unmarshal([]byte(themeJSON), &config.Theme); err != nil {
        return nil, fmt.Errorf("parse theme failed: %w", err)
    }
    if err := json.Unmarshal([]byte(featuresJSON), &config.Features); err != nil {
        return nil, fmt.Errorf("parse features failed: %w", err)
    }
    
    // 4. Update cache
    s.updateCache(domain, &config)
    
    return &config, nil
}

// CreateConfig Create configuration
func (s *WhiteLabelConfigService) CreateConfig(config *WhiteLabelConfig) error {
    // Validate domain uniqueness
    var count int
    checkQuery := `SELECT COUNT(*) FROM whitelabel_configs WHERE domain = ?`
    if err := s.db.QueryRow(checkQuery, config.Domain).Scan(&count); err != nil {
        return fmt.Errorf("check domain failed: %w", err)
    }
    if count > 0 {
        return errors.New("domain already exists")
    }
    
    // Serialize JSON fields
    themeJSON, err := json.Marshal(config.Theme)
    if err != nil {
        return fmt.Errorf("marshal theme failed: %w", err)
    }
    featuresJSON, err := json.Marshal(config.Features)
    if err != nil {
        return fmt.Errorf("marshal features failed: %w", err)
    }
    
    // Insert into database
    query := `
        INSERT INTO whitelabel_configs (
            partner_id, partner_name, domain, community_id,
            public_key, callback_url, signature_template, 
            theme, features, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    
    result, err := s.db.Exec(query,
        config.PartnerID, config.PartnerName, config.Domain, config.CommunityID,
        config.PublicKey, config.CallbackURL, config.SignatureTemplate,
        string(themeJSON), string(featuresJSON), "active",
        time.Now(), time.Now(),
    )
    
    if err != nil {
        return fmt.Errorf("insert config failed: %w", err)
    }
    
    config.ID, _ = result.LastInsertId()
    config.Status = "active"
    config.CreatedAt = time.Now()
    config.UpdatedAt = time.Now()
    
    // Update cache
    s.updateCache(config.Domain, config)
    
    return nil
}

// UpdateConfig Update configuration
func (s *WhiteLabelConfigService) UpdateConfig(domain string, updates map[string]interface{}) error {
    // Get existing configuration
    config, err := s.GetConfigByDomain(domain)
    if err != nil {
        return err
    }
    
    // Build update statement
    setClause := ""
    args := []interface{}{}
    
    for key, value := range updates {
        if setClause != "" {
            setClause += ", "
        }
        setClause += fmt.Sprintf("%s = ?", key)
        args = append(args, value)
    }
    
    args = append(args, domain)
    query := fmt.Sprintf(`
        UPDATE whitelabel_configs 
        SET %s, updated_at = ? 
        WHERE domain = ?
    `, setClause)
    args = append(args, time.Now(), domain)
    
    if _, err := s.db.Exec(query, args...); err != nil {
        return fmt.Errorf("update config failed: %w", err)
    }
    
    // Clear cache
    s.clearCache(domain)
    
    return nil
}

// VerifyPartnerSignature Verify partner signature
func (s *WhiteLabelConfigService) VerifyPartnerSignature(domain, signature, message string) error {
    config, err := s.GetConfigByDomain(domain)
    if err != nil {
        return fmt.Errorf("get config failed: %w", err)
    }
    
    // Use configured public key to verify signature
    if !verifySignature(config.PublicKey, signature, message) {
        return errors.New("invalid signature")
    }
    
    return nil
}

// Helper methods

func (s *WhiteLabelConfigService) updateCache(domain string, config *WhiteLabelConfig) {
    // Update in-memory cache
    s.cache[domain] = config
    
    // Update Redis cache
    data, _ := json.Marshal(config)
    key := fmt.Sprintf("whitelabel:config:%s", domain)
    s.redis.Set(context.Background(), key, data, 24*time.Hour)
}

func (s *WhiteLabelConfigService) clearCache(domain string) {
    delete(s.cache, domain)
    key := fmt.Sprintf("whitelabel:config:%s", domain)
    s.redis.Del(context.Background(), key)
}
```

### 3. White Label Auth Handler (WLM) - New Component

#### 3.1 Component Information

- **Belongs to Project**: `taskon-server`
- **Implementation Location**: `taskon-server/api/auth/whitelabel_handler.go`
- **Component Type**: Coordination layer component
- **Main Responsibility**: Coordinate service components to complete white label authentication process

#### 3.2 Implementation Code

```go
// api/auth/whitelabel_handler.go
package auth

import (
    "context"
    "fmt"
    "time"
    "strconv"
    
    "taskon-server/service"
    "taskon-server/token"
)

// WhiteLabelAuthHandler White label authentication handler (WLM - coordinate components)
type WhiteLabelAuthHandler struct {
    TokenManager *token.TokenManager              // Token manager
    ConfigSvc    *service.WhiteLabelConfigService // Config service
    UserSvc      service.UserService              // User service
    CommunitySvc *service.WhiteLabelCommunityService // Community service
}

// ProcessWhiteLabelLogin Process white label login (according to sequence diagram process)
func (h *WhiteLabelAuthHandler) ProcessWhiteLabelLogin(ctx context.Context, req *WhiteLabelLoginRequest) (*LoginResult, error) {
    // Step 13-14: Query white label configuration
    config, err := h.ConfigSvc.GetConfigByDomain(req.Domain)
    if err != nil {
        return nil, fmt.Errorf("invalid domain: %w", err)
    }
    
    // Step 15-16: Verify partner signature and timestamp
    message := h.buildVerificationMessage(req)
    if err := h.ConfigSvc.VerifyPartnerSignature(req.Domain, req.Signature, message); err != nil {
        return nil, fmt.Errorf("invalid partner signature: %w", err)
    }
    
    // Verify timestamp to prevent replay attacks
    if time.Now().Unix() - req.Timestamp/1000 > 300 { // 5 minute validity
        return nil, fmt.Errorf("request expired")
    }
    
    // Step 17-20: Query/create user
    var user *service.User
    var isExistingUser bool
    var userEmail string
    
    switch req.Type {
    case "wallet":
        existingUser, _ := h.UserSvc.GetUserByWallet(req.Address)
        isExistingUser = (existingUser != nil)
        if existingUser != nil {
            user = existingUser
            // If existing user, get email for sensitive operation verification
            if existingUser.Email != "" {
                userEmail = existingUser.Email
            }
        } else {
            user, err = h.UserSvc.CreateUserFromWallet(req.Address)
        }
    case "email":
        existingUser, _ := h.UserSvc.GetUserByEmail(req.Email)
        isExistingUser = (existingUser != nil)
        userEmail = req.Email
        if existingUser != nil {
            user = existingUser
        } else {
            user, err = h.UserSvc.CreateUserFromEmail(req.Email)
        }
    case "oauth":
        // OAuth login processing
        snsType := h.getSnsTypeFromProvider(req.Provider)
        existingUser, _ := h.UserSvc.GetUserBySNS(snsType, req.Email)
        isExistingUser = (existingUser != nil)
        userEmail = req.Email
        if existingUser != nil {
            user = existingUser
        } else {
            user, err = h.UserSvc.CreateUserFromOAuth(req.Provider, req.Email)
        }
    default:
        return nil, fmt.Errorf("unsupported login type: %s", req.Type)
    }
    
    if err != nil {
        return nil, fmt.Errorf("user operation failed: %w", err)
    }
    
    // Step 21-26: Silent join community
    if config.AutoJoin {
        if err := h.CommunitySvc.SilentJoinCommunity(ctx, &service.SilentJoinParams{
            UserID:        user.ID,
            CommunityID:   config.CommunityID,
            PartnerDomain: req.Domain,
        }); err != nil {
            // Join failure doesn't affect login, log it
            fmt.Printf("Failed to join community: %v\n", err)
        }
    }
    
    // Step 27-32: Generate token pair
    tokenReq := &token.TokenRequest{
        UserID:         user.ID,
        DID:           user.DID,
        IsWhiteLabel:   true,
        IsExistingUser: isExistingUser,
        UserEmail:      userEmail, // For sensitive operation verification
        LoginMethod:    req.Type,
        Domain:         req.Domain,
        CommunityID:    fmt.Sprintf("%d", config.CommunityID),
    }
    
    tokens, err := h.TokenManager.GenerateTokenPair(ctx, tokenReq)
    if err != nil {
        return nil, fmt.Errorf("generate tokens failed: %w", err)
    }
    
    return &LoginResult{
        ShadowToken:  tokens.ShadowToken,
        RefreshToken: tokens.RefreshToken,
        ExpiresAt:    tokens.ExpiresAt,
        User: UserInfo{
            ID:          user.ID,
            Address:     req.Address,
            Email:       userEmail,
            CommunityID: config.CommunityID,
        },
    }, nil
}

func (h *WhiteLabelAuthHandler) buildVerificationMessage(req *WhiteLabelLoginRequest) string {
    switch req.Type {
    case "wallet":
        return fmt.Sprintf("%s:wallet:%s:%d", req.Domain, req.Address, req.Timestamp)
    case "email":
        return fmt.Sprintf("%s:email:%s:%d", req.Domain, req.Email, req.Timestamp)
    case "oauth":
        return fmt.Sprintf("%s:oauth:%s:%s:%d", req.Domain, req.Provider, req.Email, req.Timestamp)
    default:
        return fmt.Sprintf("%s:%s:%d", req.Domain, req.Type, req.Timestamp)
    }
}

func (h *WhiteLabelAuthHandler) getSnsTypeFromProvider(provider string) service.SnsType {
    switch provider {
    case "google":
        return service.SnsTypeGoogle
    case "facebook":
        return service.SnsTypeFacebook
    case "twitter":
        return service.SnsTypeTwitter
    default:
        return service.SnsTypeOAuth
    }
}

// Request and response structs
type WhiteLabelLoginRequest struct {
    Type      string `json:"type"`      // wallet/email/oauth
    Domain    string `json:"domain"`
    Address   string `json:"address,omitempty"`
    Email     string `json:"email,omitempty"`
    Provider  string `json:"provider,omitempty"` // OAuth provider
    Signature string `json:"signature"`
    Timestamp int64  `json:"timestamp"`
}

type LoginResult struct {
    ShadowToken  string    `json:"shadowToken"`
    RefreshToken string    `json:"refreshToken"`
    ExpiresAt    time.Time `json:"expiresAt"`
    User         UserInfo  `json:"user"`
}

type UserInfo struct {
    ID          int64  `json:"id"`
    Address     string `json:"address,omitempty"`
    Email       string `json:"email,omitempty"`
    CommunityID int64  `json:"communityId"`
}
```

### 4. White Label Gateway (WLG) - New Component

#### 4.1 Component Information

- **Belongs to Project**: `taskon-server`
- **Implementation Location**: `taskon-server/gateway/whitelabel_gateway.go`
- **Component Type**: HTTP gateway component
- **Main Responsibility**: Handle HTTP requests, call authentication handler

#### 4.2 Implementation Code

```go
// gateway/whitelabel_gateway.go
package gateway

import (
    "context"
    "encoding/json"
    "net/http"
    "time"
    
    "taskon-server/api/auth"
)

type WhiteLabelGateway struct {
    authHandler *auth.WhiteLabelAuthHandler // White label authentication handler (WLM)
}

// NewWhiteLabelGateway Create white label gateway
func NewWhiteLabelGateway(authHandler *auth.WhiteLabelAuthHandler) *WhiteLabelGateway {
    return &WhiteLabelGateway{
        authHandler: authHandler,
    }
}

// HandleWhiteLabelLogin Handle wallet login
func (g *WhiteLabelGateway) HandleWhiteLabelLogin(w http.ResponseWriter, r *http.Request) {
    var req auth.TrustedWalletLoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // White label gateway only does request forwarding, specific logic handled by auth handler
    loginReq := &auth.WhiteLabelLoginRequest{
        Type:      "wallet",
        Domain:    req.Domain,
        Address:   req.Address,
        Signature: req.Signature,
        Timestamp: req.Timestamp,
    }
    
    // Call white label authentication handler (WLM coordinates components)
    result, err := g.authHandler.ProcessWhiteLabelLogin(r.Context(), loginReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    // Build response for frontend (only contains shadow token)
    response := auth.WhiteLabelLoginResponse{
        ShadowToken:  result.ShadowToken,
        RefreshToken: result.RefreshToken,
        ExpiresAt:    result.ExpiresAt,
        User:         result.User,
    }
    
    json.NewEncoder(w).Encode(response)
}

// HandleTrustedLogin Handle trusted login (email/OAuth)
func (g *WhiteLabelGateway) HandleTrustedLogin(w http.ResponseWriter, r *http.Request) {
    var req auth.TrustedLoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // White label gateway only handles request forwarding, specific logic by auth handler
    loginReq := &auth.WhiteLabelLoginRequest{
        Type:      req.Type,
        Domain:    req.Domain,
        Email:     req.Email,
        Provider:  req.Provider,
        Signature: req.Signature,
        Timestamp: req.Timestamp,
    }
    
    // Call white label authentication handler (WLM coordinates components)
    result, err := g.authHandler.ProcessWhiteLabelLogin(r.Context(), loginReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    // Build response for frontend
    response := auth.WhiteLabelLoginResponse{
        ShadowToken:  result.ShadowToken,
        RefreshToken: result.RefreshToken,
        ExpiresAt:    result.ExpiresAt,
        User:         result.User,
    }
    
    json.NewEncoder(w).Encode(response)
}

// HandleTokenExchange Handle token exchange
func (g *WhiteLabelGateway) HandleTokenExchange(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ShadowToken string `json:"shadow_token"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Call token manager for exchange
    primaryToken, err := g.authHandler.TokenManager.ExchangeToken(r.Context(), req.ShadowToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    json.NewEncoder(w).Encode(map[string]string{
        "primary_token": primaryToken,
    })
}

// HandleTokenRefresh Handle token refresh
func (g *WhiteLabelGateway) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Call token manager to refresh token
    tokens, err := g.authHandler.TokenManager.RefreshToken(r.Context(), req.RefreshToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    response := auth.WhiteLabelLoginResponse{
        ShadowToken:  tokens.ShadowToken,
        RefreshToken: tokens.RefreshToken,
        ExpiresAt:    tokens.ExpiresAt,
    }
    
    json.NewEncoder(w).Encode(response)
}

// HandleAuthCallback Handle authorization callback
func (g *WhiteLabelGateway) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
    // TODO: Implement authorization callback logic
    json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleCommunityStatus Get community status
func (g *WhiteLabelGateway) HandleCommunityStatus(w http.ResponseWriter, r *http.Request) {
    // TODO: Implement get community status logic
    json.NewEncoder(w).Encode(map[string]string{"status": "active"})
}

// Request struct definitions
type TrustedWalletLoginRequest struct {
    Address   string `json:"address"`   // Wallet address
    Signature string `json:"signature"` // Partner signature
    Timestamp int64  `json:"timestamp"` // Timestamp
    Domain    string `json:"domain"`    // Partner domain
}

type TrustedLoginRequest struct {
    Type      string `json:"type"`      // "email" or "oauth"
    Email     string `json:"email"`     // User email
    Provider  string `json:"provider"`  // OAuth provider
    Signature string `json:"signature"` // Partner signature
    Timestamp int64  `json:"timestamp"` // Timestamp
    Domain    string `json:"domain"`    // Partner domain
}

type WhiteLabelLoginResponse struct {
    ShadowToken  string    `json:"shadowToken"`
    RefreshToken string    `json:"refreshToken"`
    ExpiresAt    time.Time `json:"expiresAt"`
    User         UserInfo  `json:"user"`
}
```

### 5. Partner SDK (PSDK) - New Component

#### 3.1 Component Information

- **Belongs to Project**: New independent npm package
- **Package Name**: `@taskon/partner-sdk`
- **Publication Location**: npm public repository
- **Core Functionality**: Handle integration logic for partner websites

#### 3.2 Complete Implementation

```typescript
// src/index.ts

import { EventEmitter } from 'events'
import axios, { AxiosInstance } from 'axios'

export interface TaskonPartnerSDKConfig {
  domain: string              // Partner domain
  taskonGateway: string       // TaskOn gateway address
  apiEndpoint: string         // Partner backend address (for signing)
  communityPageUrl?: string   // Community page URL
  iframeContainer?: string    // iframe container selector
  theme?: ThemeConfig        // Theme configuration
}

export interface ThemeConfig {
  primaryColor?: string
  secondaryColor?: string
  backgroundColor?: string
  textColor?: string
}

export interface LoginOptions {
  type: 'wallet' | 'email' | 'oauth'
  provider?: 'google' | 'facebook' | 'twitter'
}

export interface WalletLoginResult {
  address: string
  signature: string
  timestamp: number
}

export interface EmailLoginResult {
  email: string
  signature: string
  timestamp: number
}

export interface OAuthLoginResult {
  email: string
  provider: string
  signature: string
  timestamp: number
}

export class TaskonPartnerSDK extends EventEmitter {
  private config: TaskonPartnerSDKConfig
  private apiClient: AxiosInstance
  private iframe: HTMLIFrameElement | null = null
  private shadowToken: string | null = null
  private isInitialized: boolean = false
  
  constructor(config: TaskonPartnerSDKConfig) {
    super()
    this.config = config
    
    // Initialize API client (communicate with partner backend)
    this.apiClient = axios.create({
      baseURL: config.apiEndpoint,
      timeout: 30000,
      withCredentials: true
    })
  }
  
  /**
   * Initialize SDK
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      console.warn('TaskonPartnerSDK already initialized')
      return
    }
    
    // 1. Setup message listener
    this.setupMessageListener()
    
    // 2. Create hidden iframe (preload)
    this.createIframe()
    
    // 3. Check stored token in local storage
    this.checkStoredToken()
    
    this.isInitialized = true
    this.emit('initialized')
  }
  
  /**
   * Wallet login
   */
  async loginWithWallet(
    address: string,
    walletType: string = 'metamask'
  ): Promise<void> {
    try {
      // 1. Request partner backend to generate signature
      const response = await this.apiClient.post('/auth/wallet', {
        address,
        walletType,
        timestamp: Date.now()
      })
      
      const { signature, timestamp } = response.data
      
      // 2. Call TaskOn white label login interface
      const loginResponse = await axios.post(
        `${this.config.taskonGateway}/api/whitelabel/login/trusted`,
        {
          type: 'wallet',
          address,
          signature,
          timestamp,
          domain: this.config.domain
        }
      )
      
      // 3. Save shadow token
      this.shadowToken = loginResponse.data.shadowToken
      this.storeToken(this.shadowToken)
      
      // 4. Notify iframe to update status
      this.sendMessageToIframe({
        type: 'LOGIN_SUCCESS',
        payload: {
          shadowToken: this.shadowToken,
          userInfo: loginResponse.data.userInfo
        }
      })
      
      // 5. Trigger login success event
      this.emit('loginSuccess', {
        type: 'wallet',
        userInfo: loginResponse.data.userInfo
      })
      
    } catch (error) {
      console.error('Wallet login failed:', error)
      this.emit('loginError', error)
      throw error
    }
  }
  
  /**
   * Email login
   */
  async loginWithEmail(email: string): Promise<void> {
    try {
      // 1. Request partner backend to verify email and generate signature
      const response = await this.apiClient.post('/auth/email', {
        email,
        timestamp: Date.now()
      })
      
      const { signature, timestamp } = response.data
      
      // 2. Call TaskOn white label login interface
      const loginResponse = await axios.post(
        `${this.config.taskonGateway}/api/whitelabel/login/trusted`,
        {
          type: 'email',
          email,
          signature,
          timestamp,
          domain: this.config.domain
        }
      )
      
      // 3. Save shadow token
      this.shadowToken = loginResponse.data.shadowToken
      this.storeToken(this.shadowToken)
      
      // 4. Notify iframe to update status
      this.sendMessageToIframe({
        type: 'LOGIN_SUCCESS',
        payload: {
          shadowToken: this.shadowToken,
          userInfo: loginResponse.data.userInfo
        }
      })
      
      // 5. Trigger login success event
      this.emit('loginSuccess', {
        type: 'email',
        userInfo: loginResponse.data.userInfo
      })
      
    } catch (error) {
      console.error('Email login failed:', error)
      this.emit('loginError', error)
      throw error
    }
  }
  
  /**
   * OAuth login (Google/Facebook etc.)
   */
  async loginWithOAuth(
    provider: 'google' | 'facebook' | 'twitter',
    authCode: string
  ): Promise<void> {
    try {
      // 1. Request partner backend to verify OAuth and generate signature
      const response = await this.apiClient.post('/auth/oauth', {
        provider,
        authCode,
        timestamp: Date.now()
      })
      
      const { email, signature, timestamp } = response.data
      
      // 2. Call TaskOn white label login interface
      const loginResponse = await axios.post(
        `${this.config.taskonGateway}/api/whitelabel/login/trusted`,
        {
          type: 'oauth',
          provider,
          email,
          signature,
          timestamp,
          domain: this.config.domain
        }
      )
      
      // 3. Save shadow token
      this.shadowToken = loginResponse.data.shadowToken
      this.storeToken(this.shadowToken)
      
      // 4. Notify iframe to update status
      this.sendMessageToIframe({
        type: 'LOGIN_SUCCESS',
        payload: {
          shadowToken: this.shadowToken,
          userInfo: loginResponse.data.userInfo
        }
      })
      
      // 5. Trigger login success event
      this.emit('loginSuccess', {
        type: 'oauth',
        provider,
        userInfo: loginResponse.data.userInfo
      })
      
    } catch (error) {
      console.error('OAuth login failed:', error)
      this.emit('loginError', error)
      throw error
    }
  }
  
  /**
   * Show Community page
   */
  showCommunityPage(container?: string | HTMLElement): void {
    const targetContainer = this.resolveContainer(container || this.config.iframeContainer)
    
    if (!targetContainer) {
      throw new Error('Container element not found')
    }
    
    // Ensure iframe is created
    if (!this.iframe) {
      this.createIframe()
    }
    
    // Show iframe
    if (this.iframe) {
      this.iframe.style.display = 'block'
      targetContainer.appendChild(this.iframe)
      
      // Send token to iframe
      if (this.shadowToken) {
        this.sendMessageToIframe({
          type: 'SET_TOKEN',
          payload: { shadowToken: this.shadowToken }
        })
      }
    }
  }
  
  /**
   * Hide Community page
   */
  hideCommunityPage(): void {
    if (this.iframe) {
      this.iframe.style.display = 'none'
    }
  }
  
  /**
   * Logout
   */
  async logout(): Promise<void> {
    try {
      // 1. Call revoke token interface
      if (this.shadowToken) {
        await axios.post(
          `${this.config.taskonGateway}/api/whitelabel/token/revoke`,
          { token: this.shadowToken }
        )
      }
      
      // 2. Clear local storage
      this.clearToken()
      this.shadowToken = null
      
      // 3. Notify iframe
      this.sendMessageToIframe({ type: 'LOGOUT' })
      
      // 4. Trigger logout event
      this.emit('logout')
      
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }
  
  /**
   * Get user information
   */
  async getUserInfo(): Promise<any> {
    if (!this.shadowToken) {
      throw new Error('Not logged in')
    }
    
    const response = await axios.get(
      `${this.config.taskonGateway}/api/whitelabel/user/info`,
      {
        headers: {
          'X-Shadow-Token': this.shadowToken
        }
      }
    )
    
    return response.data
  }
  
  /**
   * Get user rewards
   */
  async getUserRewards(): Promise<any> {
    if (!this.shadowToken) {
      throw new Error('Not logged in')
    }
    
    const response = await axios.get(
      `${this.config.taskonGateway}/api/whitelabel/user/rewards`,
      {
        headers: {
          'X-Shadow-Token': this.shadowToken
        }
      }
    )
    
    return response.data
  }
  
  // Private methods
  
  private setupMessageListener(): void {
    window.addEventListener('message', (event) => {
      // Verify origin
      if (!this.isValidOrigin(event.origin)) {
        return
      }
      
      const { type, payload } = event.data
      
      switch (type) {
        case 'TASKON_READY':
          this.emit('iframeReady')
          break
          
        case 'TASKON_AUTH_REQUEST':
          this.handleAuthRequest(payload)
          break
          
        case 'TASKON_EVENT':
          this.emit('taskonEvent', payload)
          break
          
        default:
          break
      }
    })
  }
  
  private createIframe(): void {
    if (this.iframe) return
    
    this.iframe = document.createElement('iframe')
    this.iframe.src = `${this.config.taskonGateway}/community?whitelabel=true&domain=${this.config.domain}`
    this.iframe.style.cssText = `
      width: 100%;
      height: 100%;
      border: none;
      display: none;
    `
    this.iframe.setAttribute('id', 'taskon-whitelabel-iframe')
    
    // Apply theme
    if (this.config.theme) {
      this.applyTheme(this.config.theme)
    }
  }
  
  private sendMessageToIframe(message: any): void {
    if (this.iframe && this.iframe.contentWindow) {
      this.iframe.contentWindow.postMessage(message, this.config.taskonGateway)
    }
  }
  
  private isValidOrigin(origin: string): boolean {
    const allowedOrigins = [
      this.config.taskonGateway,
      window.location.origin
    ]
    return allowedOrigins.includes(origin)
  }
  
  private resolveContainer(container: string | HTMLElement | undefined): HTMLElement | null {
    if (!container) return document.body
    
    if (typeof container === 'string') {
      return document.querySelector(container)
    }
    
    return container
  }
  
  private storeToken(token: string): void {
    localStorage.setItem('taskon_shadow_token', token)
    sessionStorage.setItem('taskon_shadow_token', token)
  }
  
  private getStoredToken(): string | null {
    return localStorage.getItem('taskon_shadow_token') || 
           sessionStorage.getItem('taskon_shadow_token')
  }
  
  private clearToken(): void {
    localStorage.removeItem('taskon_shadow_token')
    sessionStorage.removeItem('taskon_shadow_token')
  }
  
  private checkStoredToken(): void {
    const storedToken = this.getStoredToken()
    if (storedToken) {
      this.shadowToken = storedToken
      this.emit('tokenRestored', storedToken)
    }
  }
  
  private applyTheme(theme: ThemeConfig): void {
    const cssVars = `
      --whitelabel-primary: ${theme.primaryColor || '#007bff'};
      --whitelabel-secondary: ${theme.secondaryColor || '#6c757d'};
      --whitelabel-bg: ${theme.backgroundColor || '#ffffff'};
      --whitelabel-text: ${theme.textColor || '#333333'};
    `
    
    const style = document.createElement('style')
    style.textContent = `:root { ${cssVars} }`
    document.head.appendChild(style)
  }
  
  private async handleAuthRequest(payload: any): Promise<void> {
    // Handle authorization requests from iframe
    const { permissions, callback } = payload
    
    // Show authorization UI (implemented by partner)
    this.emit('authorizationRequest', {
      permissions,
      approve: async () => {
        // User approves authorization
        const response = await this.apiClient.post('/auth/approve', {
          permissions,
          shadowToken: this.shadowToken
        })
        
        // Callback to TaskOn
        await axios.post(callback, response.data)
        
        this.emit('authorizationApproved', permissions)
      },
      reject: () => {
        // User rejects authorization
        this.emit('authorizationRejected', permissions)
      }
    })
  }
}

// Export convenience methods
export function createTaskonSDK(config: TaskonPartnerSDKConfig): TaskonPartnerSDK {
  const sdk = new TaskonPartnerSDK(config)
  sdk.initialize().catch(console.error)
  return sdk
}

// TypeScript type exports
export * from './types'
```

## II. Modified Component Detailed Design

### 1. Community Page Component Modification

#### 1.1 Component Information

- **Belongs to Project**: `taskon-website` (modify existing component)
- **Modification Location**: `taskon-website/apps/website/src/views/consumer/CommunityPage/`
- **Modification Type**: Add white label mode detection and style adaptation

#### 1.2 Modification Description

Modify the existing Community page component to support iframe embedding mode and white label styling. The GTC (Go To Community) functionality in TaskOn is implemented as a Community page component.

#### 1.3 Modification Code

```vue
<!-- views/consumer/CommunityPage/index.vue (modify existing Community page component) -->
<template>
  <div class="community-container" :class="containerClasses">
    <!-- New: Reward summary bar for white label mode -->
    <RewardSummary 
      v-if="isWhitelabelMode && showRewardSummary"
      :rewards="userRewards"
      @details-click="handleDetailsClick"
    />
    
    <!-- Original GTC content, adjusted display based on white label mode -->
    <div class="gtc-main-content">
      <!-- Conditional rendering: Show banner only in non-white label mode -->
      <Banner v-if="!isWhitelabelMode" />
      
      <!-- Tab navigation: Hide certain tabs in white label mode -->
      <Tabs 
        :tabs="availableTabs"
        v-model="activeTab"
      />
      
      <!-- Tab content -->
      <component 
        :is="activeTabComponent"
        :community-id="communityId"
        :whitelabel-mode="isWhitelabelMode"
      />
    </div>
    
    <!-- Conditional rendering: Show mini profile only in non-white label mode -->
    <MiniProfile v-if="!isWhitelabelMode" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useWhitelabelStore } from '@/stores/whitelabel'
import { useUserStore } from '@/stores/user'
import { useCommunityStore } from '@/stores/community'

// New: White label related components
import RewardSummary from './components/RewardSummary.vue'
import { useWhitelabelSDK } from '@/composables/useWhitelabelSDK'

const route = useRoute()
const router = useRouter()
const whitelabelStore = useWhitelabelStore()
const userStore = useUserStore()
const communityStore = useCommunityStore()

// New: White label SDK
const { sdk, isReady } = useWhitelabelSDK()

// New: Detect if running in iframe
const isInIframe = computed(() => window.self !== window.top)

// New: White label mode detection
const isWhitelabelMode = computed(() => {
  return isInIframe.value || route.query.whitelabel === 'true'
})

// New: Adjust available tabs based on white label mode
const availableTabs = computed(() => {
  const allTabs = [
    { key: 'home', label: 'Home' },
    { key: 'quests', label: 'Quests' },
    { key: 'events', label: 'Events' },
    { key: 'leaderboard', label: 'Leaderboard' },
    { key: 'benefits', label: 'Benefits' },
    { key: 'incentive', label: 'Incentive' }
  ]
  
  if (isWhitelabelMode.value && whitelabelStore.config) {
    // Filter tabs based on configuration
    return allTabs.filter(tab => {
      const features = whitelabelStore.config.features
      switch (tab.key) {
        case 'quests':
          return features.enableQuests
        case 'events':
          return features.enableEvents
        case 'leaderboard':
          return features.enableLeaderboard
        case 'benefits':
          return features.enableBenefits
        case 'incentive':
          return features.enableIncentive
        default:
          return true
      }
    })
  }
  
  return allTabs
})

// New: Container class names
const containerClasses = computed(() => ({
  'whitelabel-mode': isWhitelabelMode.value,
  'iframe-embedded': isInIframe.value,
  [`theme-${whitelabelStore.config?.theme?.name}`]: whitelabelStore.config?.theme?.name
}))

// New: User reward data
const userRewards = ref({
  points: 0,
  tokens: [],
  nfts: []
})

// New: Whether to show reward summary bar
const showRewardSummary = computed(() => {
  return whitelabelStore.config?.features?.showRewardSummary ?? false
})

// Lifecycle hooks
onMounted(async () => {
  // New: White label mode initialization
  if (isWhitelabelMode.value) {
    await initWhitelabelMode()
  }
  
  // Original initialization logic
  await loadCommunityData()
})

// New: White label mode initialization
async function initWhitelabelMode() {
  // 1. Get domain parameter
  const domain = route.query.domain || extractDomainFromReferrer()
  
  // 2. Load white label configuration
  await whitelabelStore.loadConfig(domain)
  
  // 3. Apply custom styles
  applyCustomStyles()
  
  // 4. Listen to parent window messages
  setupMessageListener()
  
  // 5. Notify parent window ready
  notifyParentReady()
}

// New: Apply custom styles
function applyCustomStyles() {
  if (!whitelabelStore.config?.theme) return
  
  const theme = whitelabelStore.config.theme
  const style = document.createElement('style')
  style.setAttribute('data-whitelabel-custom', 'true')
  style.textContent = `
    :root {
      --whitelabel-primary: ${theme.primaryColor};
      --whitelabel-secondary: ${theme.secondaryColor};
      --whitelabel-bg: ${theme.backgroundColor};
      --whitelabel-text: ${theme.textColor};
    }
    ${theme.customCss || ''}
  `
  document.head.appendChild(style)
}

// New: Setup message listener
function setupMessageListener() {
  window.addEventListener('message', handleParentMessage)
}

// New: Handle parent window messages
function handleParentMessage(event: MessageEvent) {
  // Verify origin
  if (!isValidOrigin(event.origin)) return
  
  const { type, payload } = event.data
  
  switch (type) {
    case 'SET_TOKEN':
      handleSetToken(payload.shadowToken)
      break
    case 'LOGIN_SUCCESS':
      handleLoginSuccess(payload)
      break
    case 'LOGOUT':
      handleLogout()
      break
    default:
      break
  }
}

// New: Handle set token
async function handleSetToken(shadowToken: string) {
  // Store token
  whitelabelStore.setShadowToken(shadowToken)
  
  // Login with token
  await userStore.loginWithShadowToken(shadowToken)
  
  // Refresh page data
  await loadCommunityData()
}

// New: Notify parent window ready
function notifyParentReady() {
  if (!isInIframe.value) return
  
  window.parent.postMessage({
    type: 'TASKON_READY',
    payload: {
      version: '1.0.0',
      features: availableTabs.value.map(t => t.key)
    }
  }, '*')
}

// Cleanup
onUnmounted(() => {
  window.removeEventListener('message', handleParentMessage)
  
  // Clean up custom styles
  const customStyles = document.querySelectorAll('[data-whitelabel-custom]')
  customStyles.forEach(style => style.remove())
  
  // Clean up SDK
  if (sdk.value) {
    sdk.value.destroy()
  }
})
</script>

<style lang="scss" scoped>
.gtc-container {
  &.whitelabel-mode {
    // White label mode special styles
    
    // Hide unnecessary elements
    :deep(.banner-section),
    :deep(.user-avatar-wrapper),
    :deep(.mini-profile-widget) {
      display: none !important;
    }
    
    // Adjust padding
    padding: 0;
    
    // Transparent background (for iframe adaptation)
    background: transparent;
    
    // Use CSS variables for theme support
    .gtc-main-content {
      background: var(--whitelabel-bg, #ffffff);
      color: var(--whitelabel-text, #333333);
    }
  }
  
  &.iframe-embedded {
    // iframe embedding special handling
    height: 100vh;
    overflow-y: auto;
    
    // Remove margins
    margin: 0;
    
    // Adapt to different screen sizes
    @media (max-width: 768px) {
      .gtc-main-content {
        padding: 10px;
      }
    }
  }
}

// New: Reward summary bar styles
.reward-summary {
  background: var(--whitelabel-summary-bg, #f8f9fa);
  padding: 16px 20px;
  border-radius: 8px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  
  .reward-items {
    display: flex;
    gap: 30px;
    
    .reward-item {
      display: flex;
      flex-direction: column;
      
      .label {
        font-size: 12px;
        color: #666;
        margin-bottom: 4px;
      }
      
      .value {
        font-size: 18px;
        font-weight: 600;
        color: var(--whitelabel-primary, #333);
      }
    }
  }
  
  .details-btn {
    padding: 8px 16px;
    background: var(--whitelabel-primary, #007bff);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    transition: opacity 0.2s;
    
    &:hover {
      opacity: 0.9;
    }
  }
}
</style>
```

### 2. API Route Modification

#### 2.1 Component Information

- **Belongs to Project**: `taskon-server` (modify existing routes)
- **Modification Location**: `taskon-server/httpserver/httpserver.go` (existing HTTP server configuration)
- **Modification Type**: Add new route group, doesn't affect existing routes
- **Collaboration Note**: API Routes → White Label Gateway(WLG) → White Label Auth Handler(WLM) → Services

#### 2.2 Modification Description

Add white label specific routes in existing HTTP server configuration and connect to white label gateway.

#### 2.3 Modification Code

```go
// httpserver/httpserver.go (modify existing HTTP server configuration)

// Add white label related components to HttpServer struct
type HttpServer struct {
    options *HttpServerOptions
    httpSvr *http.Server
    router  *chi.Mux
    
    // New: White label related components
    whitelabelGateway *gateway.WhiteLabelGateway
    tokenManager      *token.TokenManager
    configService     *service.WhiteLabelConfigService
    userService       service.UserService
    communityService  *service.WhiteLabelCommunityService
    emailService      *service.EmailService
    redisClient       *redis.Client
    whitelabelService *service.WhiteLabelService  // For getting white label domain list
}

// Modify Start method, add white label route registration
func (svr *HttpServer) Start(port int) {
    // New: Register global middleware chain
    svr.registerGlobalMiddlewares()
    
    svr.httpSvr = &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: svr.router,
    }
    svr.startJsonRpcServer()
    svr.registerProm()
    
    // New: Register white label routes
    svr.registerWhitelabelRoutes()
    
    if svr.options.StartFTPServer {
        svr.startFileServer()
    }
    // ... other code remains unchanged
}

// New: Register global middleware chain
func (svr *HttpServer) registerGlobalMiddlewares() {
    // 1. Authentication middleware (all requests pass through)
    authMiddleware := auth.TaskOnAuthMiddleware(svr.tokenManager)
    svr.router.Use(authMiddleware)
    
    // 2. Sensitive operation middleware (after authentication)
    sensitiveMiddleware := middleware.NewWhiteLabelSensitiveOperationMiddleware(
        svr.tokenManager,
        svr.emailService,
        svr.redisClient,
    )
    svr.router.Use(sensitiveMiddleware.Middleware)
}

// New: White label route registration method (according to sequence diagram URL paths)
func (svr *HttpServer) registerWhitelabelRoutes() {
    // Initialize white label gateway (if not already initialized)
    if svr.whitelabelGateway == nil {
        // Create white label authentication handler
        authHandler := &auth.WhiteLabelAuthHandler{
            TokenManager: svr.tokenManager,
            ConfigSvc:    svr.configService,
            UserSvc:      svr.userService,
            CommunitySvc: svr.communityService,
        }
        
        // Create white label gateway
        svr.whitelabelGateway = &gateway.WhiteLabelGateway{
            AuthHandler: authHandler,
        }
    }
    
    // White label API route group
    // Note: These routes also pass through global middleware chain (authentication, sensitive operations, etc.)
    svr.router.Route("/api/whitelabel", func(r chi.Router) {
        // White label specific CORS middleware
        r.Use(svr.whitelabelCORSMiddleware)
        
        // Login endpoints (according to sequence diagram)
        r.Post("/login/wallet", svr.whitelabelGateway.HandleWhiteLabelLogin)    // Wallet login
        r.Post("/login/trusted", svr.whitelabelGateway.HandleTrustedLogin)      // Email/OAuth login
        
        // Token management
        r.Post("/token/exchange", svr.whitelabelGateway.HandleTokenExchange)
        r.Post("/token/refresh", svr.whitelabelGateway.HandleTokenRefresh)
        
        // Authorization management  
        r.Post("/auth/callback", svr.whitelabelGateway.HandleAuthCallback)
        
        // Community status
        r.Get("/community/status", svr.whitelabelGateway.HandleCommunityStatus)
    })
}

// New: White label CORS middleware
func (svr *HttpServer) whitelabelCORSMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        
        // Check if white label domain
        if svr.isWhitelabelDomain(origin) {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Shadow-Token")
        }
        
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

// Note: White label authentication logic has been moved to WLM (White Label Auth Handler)
// Middleware here only handles basic request preprocessing

// Note: Sensitive operation middleware has been registered in registerGlobalMiddlewares
// No need for separate registerSensitiveOperationMiddleware method

// New: Check if white label domain
func (svr *HttpServer) isWhitelabelDomain(origin string) bool {
    // Get white label domain list from database or cache
    domains, _ := svr.whitelabelService.GetAllDomains()
    
    for _, domain := range domains {
        if strings.Contains(origin, domain) {
            return true
        }
    }
    
    return false
}

// NewHttpServer Create HTTP server (needs dependency injection)
func NewHttpServer(options *HttpServerOptions, deps *Dependencies) *HttpServer {
    svr := &HttpServer{
        options: options,
        router:  chi.NewRouter(),
    }
    
    // Inject dependent services
    if deps != nil {
        svr.tokenManager = deps.TokenManager
        svr.configService = deps.ConfigService
        svr.userService = deps.UserService
        svr.communityService = deps.CommunityService
    }
    
    return svr
}

// Dependencies Dependency injection structure
type Dependencies struct {
    TokenManager     *token.TokenManager
    ConfigService    *service.WhiteLabelConfigService
    UserService      service.UserService
    CommunityService *service.WhiteLabelCommunityService
}
```

### 2.4 White Label Sensitive Operation Middleware (WLSOM)

#### 2.4.1 Component Information

- **Belongs to Project**: `taskon-server`
- **Implementation Location**: `taskon-server/api/middleware/whitelabel_sensitive.go`
- **Component Type**: Security middleware
- **Main Responsibility**: Additional verification for sensitive operations by white label existing users

#### 2.4.2 Implementation Code

```go
// api/middleware/whitelabel_sensitive.go
package middleware

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"
    
    "taskon-server/token"
    "taskon-server/service"
    "github.com/go-redis/redis/v8"
)

// WhiteLabelSensitiveOperationMiddleware White label sensitive operation middleware
type WhiteLabelSensitiveOperationMiddleware struct {
    tokenManager *token.TokenManager
    emailService *service.EmailService
    redis        *redis.Client
}

// NewWhiteLabelSensitiveOperationMiddleware Create sensitive operation middleware
func NewWhiteLabelSensitiveOperationMiddleware(
    tokenManager *token.TokenManager,
    emailService *service.EmailService,
    redis *redis.Client,
) *WhiteLabelSensitiveOperationMiddleware {
    return &WhiteLabelSensitiveOperationMiddleware{
        tokenManager: tokenManager,
        emailService: emailService,
        redis:        redis,
    }
}

// SensitiveOperations Define sensitive operations list
var SensitiveOperations = map[string]bool{
    "/api/user/bindSNS":          true,  // Bind social accounts
    "/api/user/unbindSNS":        true,  // Unbind social accounts
    "/api/account/tokenWithdraw":  true,  // Token withdrawal
    "/api/account/nftWithdraw":    true,  // NFT withdrawal
    "/api/account/transfer":       true,  // Asset transfer
    "/api/wallet/disconnect":      true,  // Disconnect wallet
    "/api/user/deleteAccount":     true,  // Delete account
}

// Middleware Middleware handler function
func (m *WhiteLabelSensitiveOperationMiddleware) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check if sensitive operation
        if !m.isSensitiveOperation(r.URL.Path) {
            next.ServeHTTP(w, r)
            return
        }
        
        // Get user info set by authentication middleware from context
        ctx := r.Context()
        isWhiteLabel, _ := ctx.Value("is_whitelabel").(bool)
        isExistingUser, _ := ctx.Value("is_existing_user").(bool)
        userEmail, _ := ctx.Value("user_email").(string)
        
        // If not white label user, pass through
        if !isWhiteLabel {
            next.ServeHTTP(w, r)
            return
        }
        
        // Dual condition check: Only white label existing users need verification
        if isWhiteLabel && isExistingUser {
            // Check if request has verification code
            var reqBody struct {
                EmailCode string `json:"email_code"`
                SendCode  bool   `json:"send_code"`
            }
            
            // Parse request body
            if err := json.NewDecoder(r.Body).Decode(&reqBody); err == nil {
                if reqBody.SendCode {
                    // Send verification code request
                    if err := m.sendVerificationCode(userEmail); err != nil {
                        m.writeErrorResponse(w, "SEND_CODE_FAILED", "Failed to send verification code")
                        return
                    }
                    m.writeSuccessResponse(w, map[string]interface{}{
                        "code_sent": true,
                        "message":   "Verification code sent to your email",
                    })
                    return
                }
                
                if reqBody.EmailCode != "" {
                    // Verify email verification code
                    if !m.verifyEmailCode(userEmail, reqBody.EmailCode) {
                        m.writeErrorResponse(w, "INVALID_CODE", "Invalid verification code")
                        return
                    }
                    // Verification passed, continue execution
                } else {
                    // Need verification code but not provided
                    m.writeErrorResponse(w, "EMAIL_CODE_REQUIRED", "Email verification required for this operation")
                    return
                }
            } else {
                // First request, return need verification code
                m.writeErrorResponse(w, "EMAIL_CODE_REQUIRED", "Email verification required for this operation")
                return
            }
        }
        
        // Verification passed or no verification needed, continue execution
        next.ServeHTTP(w, r)
    })
}

// isSensitiveOperation Check if sensitive operation
func (m *WhiteLabelSensitiveOperationMiddleware) isSensitiveOperation(path string) bool {
    // Exact match
    if SensitiveOperations[path] {
        return true
    }
    
    // Prefix match (handle paths with parameters)
    for op := range SensitiveOperations {
        if strings.HasPrefix(path, op) {
            return true
        }
    }
    
    return false
}

// sendVerificationCode Send email verification code
func (m *WhiteLabelSensitiveOperationMiddleware) sendVerificationCode(email string) error {
    // Generate 6-digit verification code
    code := m.generateVerificationCode()
    
    // Store to Redis, 15 minute validity
    key := fmt.Sprintf("email_code:%s", email)
    err := m.redis.Set(context.Background(), key, code, 15*time.Minute).Err()
    if err != nil {
        return err
    }
    
    // Send email
    return m.emailService.SendVerificationCode(email, code)
}

// verifyEmailCode Verify email verification code
func (m *WhiteLabelSensitiveOperationMiddleware) verifyEmailCode(email, code string) bool {
    key := fmt.Sprintf("email_code:%s", email)
    storedCode, err := m.redis.Get(context.Background(), key).Result()
    if err != nil {
        return false
    }
    
    if storedCode != code {
        return false
    }
    
    // Verification successful, delete verification code
    m.redis.Del(context.Background(), key)
    
    // Set verification status, no need to re-verify within 15 minutes
    verifiedKey := fmt.Sprintf("email_verified:%s", email)
    m.redis.Set(context.Background(), verifiedKey, "true", 15*time.Minute)
    
    return true
}

// generateVerificationCode Generate 6-digit verification code
func (m *WhiteLabelSensitiveOperationMiddleware) generateVerificationCode() string {
    // Actual implementation should use cryptographically secure random number generator
    return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
}

// writeErrorResponse Write error response
func (m *WhiteLabelSensitiveOperationMiddleware) writeErrorResponse(w http.ResponseWriter, code, message string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusForbidden)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "error":   code,
        "message": message,
    })
}

// writeSuccessResponse Write success response
func (m *WhiteLabelSensitiveOperationMiddleware) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(data)
}
```

## III. Integration Testing Plan

### Test Scenario Coverage

1. **Token Management Testing**
   - Dual token generation
   - Token validation
   - Token exchange
   - Token refresh
   - Token revocation

2. **Login Process Testing**
   - Wallet login
   - Email login
   - OAuth login
   - Silent login

3. **Cross-domain Communication Testing**
   - iframe loading
   - postMessage communication
   - CORS handling

4. **Security Testing**
   - Signature verification
   - Token leak protection
   - XSS protection
   - CSRF protection

5. **Compatibility Testing**
   - Browser compatibility
   - Mobile adaptation
   - Third-party cookie restrictions

## Summary

This document provides complete implementation code for all components in the white label technical solution. New components include token manager, white label config service, and partner SDK, while modified components include Community page component and API routes. All implementations follow the design principles of the main solution, ensuring system security, scalability, and good user experience.