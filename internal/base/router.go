package base




func (s *Server) initializeRoutes() {

	Router := s.Router.Group("/auth")
	{
		
		Router.POST("/login", s.Login)
		
		Router.POST("/logout", s.Logout)

		Router.GET("/authorize", s.authorize)
	}
	
}
