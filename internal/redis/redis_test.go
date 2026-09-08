package redis

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func startMockServer(stopChan chan struct{}, wg *sync.WaitGroup) int {
	// Listen on a random port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Println("Error starting TCP server:", err)
		return -1
	}

	// Get the assigned port and print it
	port := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Mock server started on port %d\n", port)

	// Use WaitGroup to track active connections
	wg.Add(1)
	defer wg.Done()

	go func() {
		<-stopChan
		//fmt.Println("Stopping server...")
		listener.Close()
	}()

	go func() {
		for {
			// Accept new connections
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopChan:
					listener.Close()
					//fmt.Println("Server has been stopped.")
					return
				default:
					fmt.Println("Error accepting connection:", err)
					continue
				}
			}

			// Handle the connection in a new goroutine
			wg.Add(1)
			go handleConnection(conn, wg)
		}
	}()
	return port
}

// handleConnection processes a single client connection
func handleConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// Read data from the client until newline
		message, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading from connection:", err)
			}
			return
		}

		// to debug
		// fmt.Println(message)

		// Trim newline characters
		message = strings.TrimSpace(message)

		// Respond based on the received message
		if message == "PING" {
			conn.Write([]byte("+PONG\r\n"))
		}
		if message == "SELECT" {
			conn.Write([]byte("+OK\r\n"))
		}
		if message == "AUTH" {
			conn.Write([]byte("+OK\r\n"))
		}
		if message == "LOAD" { // ok it is SCRIPT LOAD ...
			conn.Write([]byte("$40\r\nffffffffffffffffffffffffffffffffffffffff\r\n"))
		}
		if message == "EVALSHA" {
			conn.Write([]byte("$3\r\naaa\r\n"))
		}
	}
}

func TestPool(t *testing.T) {
	t.Run("happy path: ping", func(t *testing.T) {
		stopChan := make(chan struct{})
		var wg sync.WaitGroup

		// Start the mock server in a separate goroutine
		port := startMockServer(stopChan, &wg)

		client, err := NewClient(Options{Addr: fmt.Sprintf("localhost:%d", port), ConnectionTimeout: 2 * time.Second})
		assert.NotNil(t, client)
		assert.Nil(t, err)

		err = client.Ping()
		assert.Nil(t, err)

		client.Close()

		close(stopChan)
		wg.Wait()
	})

	t.Run("happy path: run script", func(t *testing.T) {
		stopChan := make(chan struct{})
		var wg sync.WaitGroup

		// Start the mock server in a separate goroutine
		port := startMockServer(stopChan, &wg)

		client, err := NewClient(Options{Addr: fmt.Sprintf("localhost:%d", port), ConnectionTimeout: 2 * time.Second})
		assert.NotNil(t, client)
		assert.Nil(t, err)

		script := client.NewScript("return 'aaa'")
		res, err := script.Run([]string{})
		assert.Nil(t, err)

		assert.Equal(t, "aaa", res)

		client.Close()

		close(stopChan)
		wg.Wait()
	})
}
