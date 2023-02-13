package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"safechat/common"
	"strconv"
	"strings"

	crypt "safechat/encryption"
)

type ConnState struct {
	pubKey *crypt.PublicKey
	symKey *[32]byte
}

func newState() ConnState {
	return ConnState{
		pubKey: nil,
		symKey: nil,
	}
}

// readMessage reads a message from the client and returns the computed header and the message.
func readMessage() (byte, string) {
	var msg string

	fmt.Print("Write your message: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		msg = scanner.Text()
	}

	headerDelimPos := strings.Index(msg, ":")
	if headerDelimPos == -1 {
		return common.CLIENT_MSG, msg
	} else {
		header, err := strconv.ParseUint(msg[:headerDelimPos], 10, 8)
		if err != nil {
			return common.CLIENT_MSG, msg
		}
		return byte(header), msg[headerDelimPos+1:]
	}
}

// writeMsg returns an AES encrypted message given a header, message and connection state.
func writeMsg(header byte, msg string, s *ConnState) []byte {
	sends := []byte{header}
	if s.symKey != nil && msg != "" {
		msg = fmt.Sprintf("%s", crypt.EncryptAES(s.symKey[:], []byte(msg)))
	}
	sends = append(sends, []byte(msg)...)
	return sends
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	address := ""
	fmt.Printf("please enter address (defaults to %s:%s): ", common.SERVER_HOST, common.SERVER_PORT)
	if scanner.Scan() {
		address = scanner.Text()
	}

	//establish connection
	if address == "" {
		address = common.SERVER_HOST + ":" + common.SERVER_PORT
	}

	connection, err := net.Dial(common.SERVER_TYPE, address)
	if err != nil {
		panic(err)
	}

	state := newState()

	autoConnect(connection, &state)

	for {
		header, msg := readMessage()
		sends := writeMsg(header, msg, &state)
		_, err := connection.Write(sends)
		if err != nil {
			panic(err)
		}
		// send the hello automatically so it's taken care of by the client
		displayMessage(connection)
		if header == common.CLIENT_CLOSE {
			break
		}
	}
}

// autoConnect performs the handshake with the server and sets the connection state with the symmetric key and public key.
func autoConnect(connection net.Conn, s *ConnState) {
	sends := []byte{common.CLIENT_HELLO}
	connection.Write(sends)

	// Receives server hello
	buffer, mLen, err := readFromServer(connection)
	if err != nil {
		fmt.Printf("an error occured: %v", err)
	}
	header := buffer[0]
	content := buffer[1:mLen]

	if header != common.SERVER_HELLO {
		fmt.Println("an error occured during the handshake")
		os.Exit(1)
	}

	// Generate symmetric key after client hello
	fmt.Println("[server hello] received server hello")

	pubKey := &crypt.PublicKey{}
	pubKey.Unmarshal(content)
	s.pubKey = pubKey

	fmt.Printf("[server hello] public key is %+v\n", pubKey)

	symKey := generateSymKey()
	fmt.Printf("[server hello] generated sym key: %v\n", symKey)

	msg := pubKey.EncryptString(symKey[:])
	connection.Write(writeMsg(common.CLIENT_DONE, msg, s))

	s.symKey = &symKey

	// Receives server done
	buffer, mLen, err = readFromServer(connection)
	if err != nil {
		fmt.Printf("an error occured: %v", err)
	}
	header = buffer[0]
	if header != common.SERVER_DONE {
		fmt.Println("did not receive server done")
		os.Exit(1)
	}
	fmt.Println("[server done] handshake complete")
}

// readFromServer reads a message from the server and returns the message, the message length and an error if one occured.
func readFromServer(connection net.Conn) ([]byte, int, error) {
	buffer := make([]byte, 1024*1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		return nil, 0, err
	}
	if mLen == 0 {
		return nil, 0, errors.New("Received null message")
	}
	return buffer, mLen, nil
}

// displayMessage returns the message received from the server.
func displayMessage(connection net.Conn) (byte, error) {

	buffer, mLen, err := readFromServer(connection)
	if err != nil {
		fmt.Printf("an error occured: %v", err)
	}
	header := buffer[0]
	content := buffer[1:mLen]

	switch header {
	case common.SERVER_HELLO:

		fmt.Println("[server hello] received server hello")
		pubKey := &crypt.PublicKey{}
		pubKey.Unmarshal(content)
		fmt.Printf("[server hello] public key is %+v\n", pubKey)

	case common.SERVER_MSG:
		fmt.Printf("[message] server encrypted message as: %s\n", base64.URLEncoding.EncodeToString(content))

	case common.SERVER_DONE:
		fmt.Println("[server done] handshake complete")

	case common.SERVER_CLOSE:
		fmt.Printf("[server close] %s\n", content)
	case common.ERROR:
		fmt.Printf("[error] received error: %s\n", content)

	default:
		fmt.Println("[error] handshake complete")
	}
	return common.NO_HEADER, nil
}

// generateSymKey generates a random 32 byte AES key.
func generateSymKey() [32]byte {
	var key32 [32]byte
	key := make([]byte, 32)
	rand.Read(key)
	copy(key32[:], key[:])
	return key32
}
