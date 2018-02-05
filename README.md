# clouddetect

Go package to determine if an IP address resolves to one of the major cloud providers. Helpful for risk-scoring potential bot traffic in conjunction with other signals such as User Agent.

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

## CLI usage

`go get github.com/99designs/clouddetect/cli/clouddetect`

then

`clouddetect -ip=127.0.0.1`

## TODO

- [x] AWS
- [x] GCP
- [x] Azure
- [ ] Persistent client with caching
- [ ] Digital Ocean
- [x] Extra metadata like region/service etc

## LICENSE

[MIT](/LICENSE) 2018 99designs
