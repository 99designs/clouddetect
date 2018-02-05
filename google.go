package clouddetect

import (
	"net"
	"regexp"
)

var domainRegexp = regexp.MustCompile(`include:([^\s]+)`)
var ipRegexp = regexp.MustCompile(`ip\d:([^\s]+)`)

func getGoogleCIDRs() ([]*Response, error) {
	r, err := net.LookupTXT("_cloud-netblocks.googleusercontent.com")
	if err != nil {
		return nil, err
	}

	ranges := []*Response{}

	// TXT record returns result like:
	// v=spf1 include:_cloud-netblocks1.googleusercontent.com include:_cloud-netblocks2.googleusercontent.com include:_cloud-netblocks3.googleusercontent.com include:_cloud-netblocks4.googleusercontent.com include:_cloud-netblocks5.googleusercontent.com ?all
	for _, e := range r {
		matches := domainRegexp.FindAllStringSubmatch(e, -1)
		for _, subMatches := range matches {
			r, err := net.LookupTXT(subMatches[1])
			if err != nil {
				return nil, err
			}
			// v=spf1 ip4:35.190.0.0/17 ip4:35.190.128.0/18 ip4:35.190.192.0/19 ip4:35.190.224.0/20 ip4:35.192.0.0/14 ip4:35.196.0.0/15 ip4:35.198.0.0/16 ip4:35.199.0.0/17 ip4:35.199.128.0/18 ip4:35.200.0.0/15 ip4:35.204.0.0/15 ip6:2600:1900::/35 ?all
			for _, e := range r {
				ipMatches := ipRegexp.FindAllStringSubmatch(e, -1)

				for _, ipSubMatches := range ipMatches {
					_, net, err := net.ParseCIDR(ipSubMatches[1])
					if err != nil {
						return nil, err
					}
					resp := &Response{
						ProviderName: ProviderGoogle,
						Subnet:       net,
					}
					ranges = append(ranges, resp)
				}
			}

		}
	}
	return ranges, nil
}
