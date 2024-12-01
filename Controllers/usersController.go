package controllers

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	initializers "github.com/pequod44/test-go-jwt/Initializers"
	models "github.com/pequod44/test-go-jwt/Models"
)

func send_email() {
	fmt.Println("Email sent to user")
}

func generateAccessToken(userID string, Clients_IP string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":    userID,
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
		"clients_ip": Clients_IP,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("KEY")))
}

func generateRefreshToken(UserID string, Clients_IP string) (string, string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":        UserID,
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
		"clients_ip": Clients_IP,
	})

	// Sign and get the complete encoded token as a string using the key
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("KEY")))

	if err != nil {
		fmt.Println("Failed to sign refresh token")
	}

	// Hash pass
	hashed := sha512.Sum512([]byte(refreshTokenString))
	hashedToken := base64.StdEncoding.EncodeToString(hashed[:])
	return refreshTokenString, string(hashedToken), nil
}

func GenerateTokens(c *gin.Context) {
	var body struct {
		UserID string `json:"UserID"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	accessToken, err := generateAccessToken(body.UserID, c.ClientIP())
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create Access Token"})
		return
	}

	refreshToken, hashedRefreshToken, err := generateRefreshToken(body.UserID, c.ClientIP())
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create Refresh Token"})
		return
	}

	// Record refresh token in db
	var token models.RefreshToken
	initializers.DB.First(&token, "user_id = ?", body.UserID)

	if token.ID == 0 {
		token.UserID = body.UserID
	}
	token.TokenHash = hashedRefreshToken
	result := initializers.DB.Save(&token)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to record token",
		})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func RefreshTokens(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"RefreshToken"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Decode/validate it
	token, err := jwt.Parse(body.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("KEY")), nil
	})
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return

	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check the experation
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Find the user with token sub
		var rToken models.RefreshToken
		initializers.DB.First(&rToken, "user_id = ?", claims["sub"])

		if rToken.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		//Hash sent in token
		hashed := sha512.Sum512([]byte(body.RefreshToken))
		hashedToken := base64.StdEncoding.EncodeToString(hashed[:])

		// Hash check
		if hashedToken != rToken.TokenHash {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Generate new pair
		accessToken, err := generateAccessToken(claims["sub"].(string), c.ClientIP())
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to create Access Token"})
			return
		}
		refreshToken, hashedRefreshToken, err := generateRefreshToken(claims["sub"].(string), c.ClientIP())
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to create Refresh Token"})
			return
		}
		// Update refresh token in db
		rToken.TokenHash = hashedRefreshToken
		result := initializers.DB.Save(&rToken)

		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to record token",
			})
			return
		}
		// IP check
		if c.ClientIP() != claims["clients_ip"] {
			send_email()
		}

		c.JSON(200, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})

	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

}
