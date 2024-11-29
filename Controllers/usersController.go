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
	"golang.org/x/crypto/bcrypt"
)

func Sign_up(c *gin.Context) {
	//Get the email/pass of req body
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}
	// Hash pass
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
	}
	// Create the user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
	}

	// Respond

	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	// Get the email and pass off req body
	var body struct {
		Email    string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}
	//Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return
	}
	//Compare sent in pass with saved pass has
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return
	}
	//Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("KEY")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create Token",
		})

		return
	}

	//Send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func Validate(c *gin.Context) {
	// // Извлечение пользователя из контекста
	// user, exists := c.Get("user")
	// if !exists {
	// 	c.AbortWithStatus(http.StatusUnauthorized)
	// 	return
	// }

	// // Проверка на существование пользователя
	// if user == nil {
	// 	c.AbortWithStatus(http.StatusUnauthorized)
	// 	return
	// }

	c.JSON(http.StatusOK, gin.H{
		"message": "I'm logged in",
	})
}

// func GenerateTokens(c *gin.Context) {
// 	// Get the email and pass off req body
// 	var body struct {
// 		UserID string
// 	}

// 	if c.Bind(&body) != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "Failed to read body",
// 		})

// 		return
// 	}

// 	//Generate a jwt access token
// 	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
// 		"sub": body.UserID,
// 		"exp": time.Now().Add(time.Minute * 15).Unix(),
// 	})

// 	// Sign and get the complete encoded token as a string using the key
// 	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("KEY")))

// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "Failed to create Access Token",
// 		})

// 		return
// 	}
// 	//Generate a jwt refresh token
// 	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
// 		"sub": body.UserID,
// 		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
// 	})

// 	// Sign and get the complete encoded token as a string using the key
// 	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("KEY")))

// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "Failed to create Access Token",
// 		})

// 		return
// 	}

// 	// Hash pass
// 	hashed := sha512.Sum512([]byte(refreshTokenString))
// 	hashedToken := base64.StdEncoding.EncodeToString(hashed[:])

// 	fmt.Println("Хешированный токен (SHA512):", hashedToken)
// 	// Check existing statement
// 	var existingToken models.RefreshToken
// 	if err := initializers.DB.Where("token_hash = ?", hashedToken).First(&existingToken).Error; err == nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "Token already exists",
// 		})
// 		return
// 	}

// 	// Create the token
// 	token := models.RefreshToken{TokenHash: string(hashedToken)}

// 	result := initializers.DB.Create(&token)

// 	if result.Error != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "Failed to create token hash",
// 		})
// 	}

// 	//Send it back
// 	// c.SetSameSite(http.SameSiteLaxMode)
// 	// c.SetCookie("Authorization", accessTokenString, 900, "", "", false, true)

// 	c.JSON(http.StatusOK, gin.H{
// 		"accessToken":  accessTokenString,
// 		"refreshToken": refreshTokenString,
// 	})
// }

// type controllers struct {
// 	ctx context.Context
// 	server *server.Server
// 	tokenMaker *token.JWTMaker
// }

// func (h * controllers)GenerateTokens() {
// 	var u LoginUserReq
// 	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
// 		http.Error(w, "error decoding request body", http.StatusBadRequest)
// 		return
// 	}

// 	ur, err := h.client.GetUser(h.ctx, &pb.UserReq{
// 		Email: u.Email,
// 	})
// 	if err != nil {
// 		http.Error(w, "error getting user", http.StatusInternalServerError)
// 		return
// 	}

// 	err = util.CheckPassword(u.Password, ur.GetPassword())
// 	if err != nil {
// 		http.Error(w, "wrong password", http.StatusUnauthorized)
// 		return
// 	}

// 	//create JSON web token and return it as response
// 	h.tokenMaker.CreateToken(gu.ID, gu.Email, gu.IsAdmin, 15 * time.Minute)
// }

// Secret key для подписи JWT

// Структура запроса
type TokenRequest struct {
	UserID string `json:"user_id"`
}

// Структура ответа
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Генерация Access Token
func generateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(15 * time.Minute).Unix(), // Время жизни 15 минут
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("KEY")))
}

// Генерация Refresh Token
func generateRefreshToken(UserID string) (string, string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": UserID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	// Sign and get the complete encoded token as a string using the key
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("KEY")))

	if err != nil {
		fmt.Println("Failed to sign refresh token")
	}

	// Hash pass
	hashed := sha512.Sum512([]byte(refreshTokenString))
	hashedToken := base64.StdEncoding.EncodeToString(hashed[:])

	fmt.Println("Хешированный токен (SHA512):", hashedToken)
	// // Check existing statement
	// var existingToken models.RefreshToken
	// if err := initializers.DB.Where("token_hash = ?", hashedToken).First(&existingToken).Error; err == nil {
	// 	fmt.Errorf("Failed to sign refresh token")
	// }

	// // Генерация случайного токена
	// rawToken := make([]byte, 32)
	// if _, err := rand.Read(rawToken); err != nil {
	// 	return "", "", err
	// }
	// refreshToken := base64.RawURLEncoding.EncodeToString(rawToken)

	// // Хеширование токена для сохранения в базе данных
	// hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	// if err != nil {
	// 	return "", "", err
	// }

	return refreshTokenString, string(hashedToken), nil
}

// // Проверка Refresh токена
// func verifyRefreshToken(refreshToken string, hashedToken string) error {
// 	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
// }

func GenerateTokens(c *gin.Context) {
	var body struct {
		UserID string `json:"UserID"` // Получаем UserID из запроса
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Генерация Access токена
	accessToken, err := generateAccessToken(body.UserID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not generate access token"})
		return
	}

	// Генерация Refresh токена
	refreshToken, hashedRefreshToken, err := generateRefreshToken(body.UserID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not generate refresh token"})
		return
	}

	// Create the token
	fmt.Println(hashedRefreshToken)
	token := models.RefreshToken{UserID: body.UserID, TokenHash: string(hashedRefreshToken)}

	result := initializers.DB.Create(&token)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token hash",
		})
		return
	}

	// Ответ с токенами
	c.JSON(200, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func RefreshTokens(c *gin.Context) {
	var body struct {
		UserID       string `json:"UserID"`
		RefreshToken string `json:"RefreshToken"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}
	//Look up requested user
	var token models.RefreshToken
	initializers.DB.First(&token, "user_id = ?", body.UserID)
	if token.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token 1",
		})

		return
	}

	fmt.Printf("Token hash: %s", token.TokenHash)
	fmt.Printf("RefreshToken: %s", body.RefreshToken)

	//Compare sent in pass with saved pass has
	err := bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(body.RefreshToken))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token 2",
		})

		return
	}

}
