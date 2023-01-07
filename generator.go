package kanji_jwt

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Generator struct {
	secretKey string
}

var (
	ErrInvalidToken = errors.New("token not valid")
	ErrNotMapClaims = errors.New("parsedToken.Claims not jwt.MapClaims")
	ErrIdNotFound   = errors.New("id not found")
	ErrIsEmpty      = errors.New("jwt field is empty")
)

func New(secretKey string) (*Generator, error) {
	return &Generator{secretKey: secretKey}, nil
}

func (g *Generator) Generate(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))

	return token.SignedString([]byte(g.secretKey))
}

func (g *Generator) ParseToken(token string) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(g.secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrNotMapClaims
	}

	return claims, nil
}

func GetUserId(ctx context.Context, g *Generator) (uuid.UUID, error) {
	jwtToken := ctx.Value("jwt").(string)
	if len(jwtToken) == 0 {
		return uuid.UUID{}, ErrIsEmpty
	}

	claims, err := g.ParseToken(jwtToken)
	if err != nil {
		return uuid.UUID{}, err
	}

	id, ok := claims["user_id"]
	if !ok {
		return uuid.UUID{}, ErrIdNotFound
	}

	userId, err := uuid.Parse(id.(string))
	if err != nil {
		return uuid.UUID{}, err
	}

	return userId, nil
}
