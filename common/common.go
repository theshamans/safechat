package common

// Server constants
const (
	SERVER_BIND = "0.0.0.0"
	SERVER_HOST = "localhost"
	SERVER_PORT = "2345"
	SERVER_TYPE = "tcp"
)

// Message headers
const (
	NO_HEADER    byte = 255
	CLIENT_HELLO byte = 0
	SERVER_HELLO byte = 1
	CLIENT_DONE  byte = 2
	SERVER_DONE  byte = 3
	ERROR        byte = 4
	CLIENT_MSG   byte = 5
	SERVER_MSG   byte = 6
	CLIENT_CLOSE byte = 7
	SERVER_CLOSE byte = 8
)
