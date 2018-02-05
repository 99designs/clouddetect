package clouddetect

import (
	"encoding/json"
	"net"
	"net/http"
)

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

func getAmazonCIDRs() ([]*Response, error) {
	ipPrefixes := amazonIPPrefixes{}

	r, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if err = json.NewDecoder(r.Body).Decode(&ipPrefixes); err != nil {
		return nil, err
	}

	responses := []*Response{}

	for _, prefix := range ipPrefixes.Prefixes {
		_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			return nil, err
		}
		resp := &Response{
			ProviderName: ProviderAmazon,
			Region:       prefix.Region,
			Subnet:       ipNet,
		}
		responses = append(responses, resp)
	}

	// ipv6
	for _, prefix := range ipPrefixes.Ipv6Prefixes {
		_, ipNet, err := net.ParseCIDR(prefix.Ipv6Prefix)
		if err != nil {
			return nil, err
		}
		resp := &Response{
			ProviderName: ProviderAmazon,
			Region:       prefix.Region,
			Subnet:       ipNet,
		}
		responses = append(responses, resp)
	}

	return responses, nil
}
