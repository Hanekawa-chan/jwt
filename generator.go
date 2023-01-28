package kanji_jwt

import (
	"github.com/golang-jwt/jwt/v4"
)

type Generator struct {
	secretKey string
}

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
