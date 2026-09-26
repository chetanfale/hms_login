package utils

import (
	"hms_login/internal/models"

	"github.com/gin-gonic/gin"
)

// SendSuccess sends a standardized JSON HTTP success response.
func SendSuccess(c *gin.Context, statusCode int, message string, data interface{}) {
	c.JSON(statusCode, models.APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// SendError sends a standardized JSON HTTP error response.
func SendError(c *gin.Context, statusCode int, message string, errorCode string, details string) {
	c.JSON(statusCode, models.APIResponse{
		Success: false,
		Message: message,
		Error: &models.APIError{
			Code:    errorCode,
			Details: details,
		},
	})
}
