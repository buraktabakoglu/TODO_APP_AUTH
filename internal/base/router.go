package base

import(
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"


)

func (s *Server) initializeRoutes() {

	Router := s.Router.Group("/auth")

	{
		// use ginSwagger middleware to serve the API docs
		Router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

		Router.POST("/login", s.Login)

		Router.POST("/logout", s.Logout)

		Router.GET("/authorize", s.Authorize)

	}

}
