package jwt

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWT структура для работы с токенами
type JWT struct {
	SecretKey        string
	RefreshSecretKey string
}

// NewJWT создает новый экземпляр JWT с секретными ключами
func NewJWT(secretKey, refreshSecretKey string) *JWT {
	return &JWT{
		SecretKey:        secretKey,
		RefreshSecretKey: refreshSecretKey,
	}
}

// TokenPair содержит access и refresh токены
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // время жизни access токена в секундах
}

// Claims для JWT токенов
type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	Login     string    `json:"login"`
	TokenType string    `json:"token_type"` // "access" или "refresh"
	jwt.RegisteredClaims
}

// Время жизни токенов
const (
	UserAccessTokenDuration     = 15 * time.Minute
	UserRefreshTokenDuration    = 30 * time.Hour
)

// CreateAccessToken создает access токен
func (j *JWT) CreateAccessToken(userID uuid.UUID, login string) (string, error) {
	var duration time.Duration
	duration = UserAccessTokenDuration

	now := time.Now()
	claims := &Claims{
		UserID:    userID,
		Login:     login,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
}

// CreateRefreshToken создает refresh токен
func (j *JWT) CreateRefreshToken(userID uuid.UUID, login string) (string, error) {
	var duration time.Duration
	duration = UserRefreshTokenDuration

	now := time.Now()
	claims := &Claims{
		UserID:    userID,
		Login:     login,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.RefreshSecretKey))
}

// CreateTokenPair создает пару access и refresh токенов
func (j *JWT) CreateTokenPair(userID uuid.UUID, login string) (*TokenPair, error) {
	accessToken, err := j.CreateAccessToken(userID, login)
	if err != nil {
		return nil, err
	}

	refreshToken, err := j.CreateRefreshToken(userID, login)
	if err != nil {
		return nil, err
	}

	var accessDuration time.Duration
	accessDuration = UserAccessTokenDuration

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessDuration.Seconds()),
	}, nil
}

// ValidateAccessToken проверяет access токен
func (j *JWT) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.TokenType != "access" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidateRefreshToken проверяет refresh токен
func (j *JWT) ValidateRefreshToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.RefreshSecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.TokenType != "refresh" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshTokens обновляет токены используя refresh токен
func (j *JWT) RefreshTokens(refreshTokenString string) (*TokenPair, error) {
	claims, err := j.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	return j.CreateTokenPair(claims.UserID, claims.Login)
}

// GetSecretKey возвращает секретный ключ для access токенов (для middleware)
func (j *JWT) GetSecretKey() []byte {
	return []byte(j.SecretKey)
}

// GetClaimsFromFiberContext извлекает claims из контекста Fiber
func GetClaimsFromFiberContext(c *fiber.Ctx) (*Claims, error) {
	user := c.Locals("user").(*jwt.Token)
	if user == nil {
		return nil, errors.New("token not found in context")
	}

	claims, ok := user.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("user_id not found in claims")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user_id format")
	}

	login, ok := claims["login"].(string)
	if !ok {
		return nil, errors.New("login not found in claims")
	}

	tokenType, ok := claims["token_type"].(string)
	if !ok {
		return nil, errors.New("token_type not found in claims")
	}

	return &Claims{
		UserID:    userID,
		Login:     login,
		TokenType: tokenType,
	}, nil
}

// CreatePasswordResetToken создает токен для сброса пароля
func (j *JWT) CreatePasswordResetToken(userID uuid.UUID, email string) (string, error) {
    now := time.Now()
    claims := &Claims{
        UserID:    userID,
        Login:     email,
        TokenType: "password_reset", 
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)), // TTL 1 час
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Subject:   userID.String(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(j.SecretKey)) // Используем основной секрет
}

// ValidatePasswordResetToken проверяет токен для сброса пароля
func (j *JWT) ValidatePasswordResetToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.TokenType != "password_reset" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}