# Spring Boot Security Project
This Spring Boot project is focused on implementing robust security features within a web application context. Utilizing Spring Security, the project provides a secure and scalable foundation for managing authentication, authorization, and other security-related concerns.

## Features

### Authentication and Authorization
- User Registration and Authentication: The project includes a comprehensive authentication mechanism, allowing users to register and log in. This is handled by the auth package, with classes like AuthenticationController, AuthenticationRequest, and AuthenticationResponse.
- JWT Integration: Utilizing JSON Web Tokens (JWT) for secure and stateless authentication. The JwtService class and JwtAuthenticationFilter are central to this implementation.
- Role-based Access Control: Defined by the Role.java class, the application supports different user roles, enabling fine-grained access control based on user roles.
### Security Configuration
- Spring Security Configuration: The SecurityConfiguration class in the config package outlines the security settings, including URL-based security, custom userDetailsService, and password encoding.
- Cross-Origin Resource Sharing (CORS): Managed within the WebConfig class, ensuring the application can interact safely with requests from different origins.
### Database Integration
- User Management: The User class, along with the UserRepository, provides the necessary setup for user data management, interfacing with the project's database.
### RESTful API Design
- Rest Controllers: Rest Controllers demonstrate simple RESTful APIs, showcasing various endpoint implementations (login, register, logout, refresh, demo).
### Application Configuration
- Configuration: ApplicationConfig class in the config package demonstrates the application's approach to configuration.
- Properties: application.yaml can be used as a resource file to extract different parameters. Create one based on the application-example.yaml

## Getting Started

### Prerequisites
- JDK 17 or later
- Maven
- A suitable IDE like IntelliJ IDEA or Eclipse

### Running the Application
- Clone the repository.
- Navigate to the project directory.
- Run ```mvn clean install``` to build the project.
- Run *SpringSecurityApplication.java* to start the application.
