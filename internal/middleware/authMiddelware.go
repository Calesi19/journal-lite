package middleware

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const secret = "your-super-duper-secret-magic-key-of-power"

func Test(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return next(c)
	}
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")

		if authHeader == "" {

			res := map[string]string{
				"message": "Missing Authorization header",
			}
			return c.JSON(http.StatusUnauthorized, res)
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := parseToken(tokenString)
		if err != nil || !token.Valid {

			res := map[string]string{
				"message": "Invalid token",
			}
			return c.JSON(http.StatusUnauthorized, res)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			res := map[string]string{
				"message": "Invalid token claims",
			}

			return c.JSON(http.StatusUnauthorized, res)
		}

		userId, ok := claims["userId"].(string)
		if !ok || userId == "" {
			res := map[string]string{
				"message": "userId not found in token",
			}
			return c.JSON(http.StatusUnauthorized, res)
		}

		c.Set("userId", userId)

		return next(c)
	}
}

func parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, echo.NewHTTPError(401, "Unexpected signing method")
		}

		return []byte(secret), nil
	})
}
