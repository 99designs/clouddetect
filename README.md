# clouddetect

[![](https://godoc.org/github.com/99designs/clouddetect?status.svg)](http://godoc.org/github.com/99designs/clouddetect) [![Go Report Card](https://goreportcard.com/badge/github.com/99designs/clouddetect)](https://goreportcard.com/report/github.com/99designs/clouddetect)

Go package to determine if an IP address resolves to one of the major cloud providers. Helpful for risk-scoring potential bot traffic in conjunction with other signals such as User Agent.

Currently the library consumes the published IP ranges from Amazon, Google, and Microsoft.

## API usage

```
package main

import (
	"fmt"
	"os"

	"github.com/99designs/clouddetect"
)

func main() {
    ip := net.ParseIP("127.0.0.1")
    if cloud, err := clouddetect.Resolve(ip); err == nil {
        fmt.Println(cloud.ProviderName)
    }
}
```

The default `Client` has an internal cache with a TTL of 12 hours. The first request to resolve an IP will be slow as it fetches all published ranges. See the [clouddetect godocs](http://godoc.org/github.com/99designs/clouddetect) for more detail on the API.

## CLI usage

`go get github.com/99designs/clouddetect/cli/clouddetect`

then

`clouddetect -ip=127.0.0.1`

## LICENSE

[MIT](/LICENSE) 2018 99designs
