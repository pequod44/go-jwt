package main

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/pequod44/test-go-jwt/Controllers"
	initializers "github.com/pequod44/test-go-jwt/Initializers"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDataBase()
}

func main() {
	r := gin.Default()
	r.POST("/generate", controllers.GenerateTokens)
	r.POST("/refresh", controllers.RefreshTokens)
	r.Run()
}
