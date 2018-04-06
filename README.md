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

## Caching to Disk

```
package main

import (
    "fmt"
    "os"

    "github.com/99designs/clouddetect"
    "time"
)

var (
    client = clouddetect.NewClient(24 * time.Hour)
)

func init() {
    client.CacheFilePath = path.Join(os.TempDir(), "cloud-ip-cache.json")
    // Cache will be persisted and loaded from disk. A lock file is also generated during this process to allow multiple instances to share the same cache file path without having competing refreshes.
    client.RefreshCache()
}

func main() {
    ip := net.ParseIP("127.0.0.1")
    if cloud, err := client.Resolve(ip); err == nil {
        fmt.Println(cloud.ProviderName)
    }
}
```

Using a `CacheFilePath` speeds up the initial launch time, so your first request to resolve an IP will only be slow if no local cache exists. Optionally, manually calling the `client.RefreshCache()` function in your `init()` ensures your cache is ready to go even for the first request.

## LICENSE

[MIT](/LICENSE) 2018 99designs
