package main

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/pequod44/test-go-jwt/Controllers"
	initializers "github.com/pequod44/test-go-jwt/Initializers"
	middleware "github.com/pequod44/test-go-jwt/Middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDataBase()
}

func main() {
	r := gin.Default()
	r.POST("/sign_up", controllers.Sign_up)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	r.Run()
}
