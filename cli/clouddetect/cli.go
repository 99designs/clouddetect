package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/99designs/clouddetect"
)

func main() {
	rawIP := flag.String("ip", "", "ip address to determine is in a cloud")
	flag.Parse()

	ip := net.ParseIP(*rawIP)
	if ip == nil {
		fmt.Printf("%v is not a valid IP\n", *rawIP)
		os.Exit(1)
	}

	cloud, err := clouddetect.Resolve(ip)
	if err != nil {
		fmt.Printf("Error resolving %v: %v\n", ip, err)
		os.Exit(1)
	}

	fmt.Println(cloud.ProviderName)
}
