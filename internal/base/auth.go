package base

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/auth"

	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)


/**
@summary Authorize a user request
@param c gin.Context -  Gin context to extract the request details
@route /auth/authorize
@method GET
@return 200 - If the user is authorized
@return 403 - If the user is not authorized
*/
func (server *Server) Authorize(c *gin.Context) {
	userID, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
		return
	}
	log.Println("userID:", userID)
	if !server.checkAuthorization(c, userID) {
		c.JSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Authorized"})
}

func (server *Server) checkAuthorization(c *gin.Context, userID uint32) bool {

	token := c.GetHeader("Authorization")

	redisConn := auth.GetRedisConnection()
	isBlacklisted, err := redisConn.SIsMember("blacklisted_tokens", token).Result()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return false
	}

	fmt.Println("blacklisted_tokens")

	if isBlacklisted {
		c.AbortWithError(http.StatusUnauthorized, errors.New("token is invalid"))
		return false
	}

	fmt.Println("TokenValid")
	r := c.Request
	err = auth.TokenValid(r)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return false
	}
	fmt.Println("TokenValid+++++++++")
	var user models.User
	err = server.DB.Where("id = ?", userID).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithError(http.StatusUnauthorized, errors.New("user not found"))
			return false
		}
		log.Println(err)
	}

	return true
}
