# Golang SPA Authorization Example

This project demonstrates a simple Single Page Application (SPA) with authorization using Go. It consists of a server that handles authentication and a client that interacts with the server.

## Project Structure

```
golang-spa-auth
├── server
│   ├── main.go          # Entry point for the server, sets up HTTP server and routes
│   ├── auth             # Contains authorization logic
│   │   └── auth.go      # Functions for generating and validating JWT tokens
│   ├── handlers          # Defines request handling functions
│   │   └── handlers.go   # Functions for login and protected routes
│   └── middleware        # Middleware for request processing
│       └── middleware.go # JWT validation middleware
├── client
│   ├── index.html       # HTML entry point for the client
│   ├── css              # Contains client-side styles
│   │   └── style.css     # CSS styles for the client
│   └── js               # Contains client-side JavaScript
│       └── app.js        # JavaScript logic for handling login and requests
├── go.mod               # Go module configuration file
├── go.sum               # Go module dependency versions
└── README.md            # Project documentation
```

## Getting Started

### Prerequisites

- Go (version 1.16 or later)
- A web browser

### Running the Server

1. Navigate to the `server` directory:
   ```
   cd server
   ```

2. Run the server:
   ```
   go run main.go
   ```

The server will start on `http://localhost:8080`.

### Running the Client

1. Open the `client/index.html` file in your web browser.

### Usage

- Use the login form in the client to authenticate users.
- Upon successful login, a JWT token will be generated and used for subsequent requests to protected routes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.