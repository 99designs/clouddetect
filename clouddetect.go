package clouddetect

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
)

// Client will eventually hold cache of IP ranges
type Client struct {
	foo int // unexported nothing
}

// Response provides details of the cloud environment the IP resolved to
type Response struct {
	ProviderName string
}

var (
	// ErrNotCloudIP is error returned when IP does not match any of the published list of ranges
	ErrNotCloudIP = errors.New("not resolved to any known cloud IP range")
)

// DefaultClient is the default Client for resolving requests
func DefaultClient() *Client {
	return &Client{}
}

// Resolve is a convenience function to resolve an IP against the DefaultClient
func Resolve(ip net.IP) (*Response, error) {
	return DefaultClient().Resolve(ip)
}

// Resolve will take the given ip and determine if it exists within any of the major
// cloud providers' published IP ranges and any extra metadata that may be of use.
// It returns ErrNotCloudIP if the IP does not resolve against any lists
func (c *Client) Resolve(ip net.IP) (*Response, error) {
	_, err := resolveAmazon(ip)
	if err != ErrNotCloudIP {
		if err == nil {
			return &Response{
				ProviderName: "Amazon",
			}, nil
		}
		return nil, err
	}

	// Azure

	// GCP

	return nil, ErrNotCloudIP
}

type amazonIPPrefixes struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix string `json:"ip_prefix"`
		Region   string `json:"region"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	Ipv6Prefixes []struct {
		Ipv6Prefix string `json:"ipv6_prefix"`
		Region     string `json:"region"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

func resolveAmazon(ip net.IP) (string, error) {
	ipPrefixes := amazonIPPrefixes{}

	r, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	if err = json.NewDecoder(r.Body).Decode(&ipPrefixes); err != nil {
		return "", err
	}

	if ip.To4() == nil {
		// ipv6
		for _, prefix := range ipPrefixes.Ipv6Prefixes {
			_, ipNet, err := net.ParseCIDR(prefix.Ipv6Prefix)
			if err != nil {
				return "", err
			}
			if ipNet.Contains(ip) {
				return prefix.Region, nil
			}
		}
	} else {
		for _, prefix := range ipPrefixes.Prefixes {
			_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
			if err != nil {
				return "", err
			}
			if ipNet.Contains(ip) {
				return prefix.Region, nil
			}
		}
	}

	return "", ErrNotCloudIP
}
