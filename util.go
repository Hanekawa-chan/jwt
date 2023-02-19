package jwt

import (
	"context"
	"github.com/google/uuid"
)

// GetUserId gets user id from jwt inside context
func GetUserId(ctx context.Context, g IGenerator) (uuid.UUID, error) {
	jwtToken := ctx.Value("access_token").(string)
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
