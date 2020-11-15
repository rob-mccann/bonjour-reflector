package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	log.Println("Reading config...")

	// Read config file and generate mDNS forwarding maps
	cfg, err := readConfig(os.Args[1:])

	if err != nil {
		log.Fatalf("Could not read configuration: %v", err)
	}

	// Start debug server
	if cfg.Debug {
		go debugServer(6060)
	}

	poolsMap := mapByPool(cfg.Devices)

	log.Println("Opening handle...")
	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(cfg.NetInterface, 65536, true, time.Second)
	if err != nil {
		log.Fatalf("Could not find network interface: %v", cfg.NetInterface)
	}

	// Get the local MAC address, to filter out Bonjour packet generated locally
	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		log.Fatal(err)
	}
	brMACAddress := intf.HardwareAddr
	log.Printf("MAC of this interface %s", brMACAddress)

	// Filter tagged bonjour traffic
	filterTemplate := "not (ether src %s) and vlan and dst net (224.0.0.251 or ff02::fb) and udp dst port 5353"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, brMACAddress))
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	// Process Bonjours packets
	for bonjourPacket := range bonjourPackets {
		// Forward the mDNS query or response to appropriate VLANs
		if bonjourPacket.isDNSQuery {
			tags, ok := poolsMap[*bonjourPacket.vlanTag]
			if !ok {
				continue
			}

			fmt.Println("Matching DNS query packet:")
			fmt.Println(bonjourPacket.packet.String())

			for _, tag := range tags {
				fmt.Printf("Forwarding query to %s\n", fmt.Sprint(tag))
				sendBonjourPacket(rawTraffic, &bonjourPacket, tag, brMACAddress)
			}
		} else {
			device, ok := cfg.Devices[bonjourPacket.srcMAC.String()]
			if !ok {
				continue
			}

			fmt.Println("Matching broadcast packet:")
			fmt.Println(bonjourPacket.packet.String())

			for _, tag := range device.SharedPools {
				fmt.Printf("Forwarding to %s\n", fmt.Sprint(tag))
				sendBonjourPacket(rawTraffic, &bonjourPacket, tag, brMACAddress)
			}
		}
	}
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with --Debug flag but could not listen on port %v: \n %s", port, err)
	}
}
