package initializers

import models "github.com/pequod44/test-go-jwt/Models"

// import models "github.com/pequod44/test-go-jwt/Models"

func SyncDataBase() {
	// DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.RefreshToken{})

}
