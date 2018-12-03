package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapfile    string
	bpf         string
	network     string
	address     string
	maxInterval int
	interactive bool
	verbose     bool
	iolock      sync.Mutex
)

func init() {
	flag.StringVar(&pcapfile, "f", "", "pcap file to replay")
	flag.StringVar(&bpf, "x", "tcp", "BPF filter for pcap")
	flag.StringVar(&address, "r", "", "remote server address (e.g., localhost:1337")
	flag.StringVar(&network, "net", "tcp", "network type to dial")
	flag.IntVar(&maxInterval, "t", 30, "max interval between two packets")
	flag.BoolVar(&interactive, "i", true, "interactive mode")
	flag.BoolVar(&verbose, "v", true, "verbose mode")
	flag.Parse()
	if pcapfile == "" {
		flag.Usage()
		log.Fatal("Need a pcap file to replay")
	}
	if address == "" {
		flag.Usage()
		log.Fatal("Specify a remote address to pwn?")
	}
}

func verboseIO(isRead bool, data []byte) {
	iolock.Lock()
	defer iolock.Unlock()
	if verbose {
		if isRead {
			fmt.Println(time.Now().Format("15:04:05 [RECV]"))
		} else {
			fmt.Println(time.Now().Format("15:04:05 [SEND]"))
		}
		fmt.Println(hex.Dump(data))
	} else {
		fmt.Println(string(data))
	}
}

func main() {
	// open pcap file
	handle, err := pcap.OpenOffline(pcapfile)
	if err != nil {
		log.Fatal("PCAP OpenOffline error:", err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(bpf); err != nil {
		log.Fatal("PCAP SetBPFFilter error:", err)
	}
	// initialize network connection
	conn, err := net.Dial(network, address)
	if err != nil {
		log.Fatal("NET Dial error:", err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				verboseIO(true, buf[:n])
			}
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			}
		}
		fmt.Println("Got EOF while reading in interactive")
	}()
	// replay the traffic
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	var lastTS, lastSend time.Time
	for pkt := range packets {
		ts := pkt.Metadata().Timestamp
		intervalInCapture := ts.Sub(lastTS)
		elapsedTime := time.Since(lastSend)
		if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
			time2sleep := intervalInCapture - elapsedTime
			if time2sleep > time.Duration(maxInterval)*time.Second {
				time2sleep = time.Duration(maxInterval) * time.Second
			}
			time.Sleep(time2sleep)
		}
		lastTS = ts
		lastSend = time.Now()
		tcp := pkt.Layer(layers.LayerTypeTCP)
		payload := tcp.LayerPayload()
		if len(payload) != 0 {
			verboseIO(false, payload)
			_, err := conn.Write(payload)
			if err != nil {
				log.Fatal("NET Write error:", err)
			}
		}
	}
	if interactive {
		r := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("$ ")
			line, _, err := r.ReadLine()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal("IO error:", err)
			} else {
				conn.Write(line)
			}
		}
	}
}
