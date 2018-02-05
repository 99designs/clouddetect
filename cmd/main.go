package main

import (
	"fmt"

	"github.com/99designs/clouddetect"
)

func main() {
	cloud := clouddetect.Resolve("127.0.0.1")
	fmt.Println(cloud)
}
