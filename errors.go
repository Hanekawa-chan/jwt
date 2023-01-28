package kanji_jwt

import "errors"

var (
	ErrInvalidToken = errors.New("token not valid")
	ErrNotMapClaims = errors.New("parsedToken.Claims not jwt.MapClaims")
	ErrIdNotFound   = errors.New("id not found")
	ErrIsEmpty      = errors.New("jwt field is empty")
)
