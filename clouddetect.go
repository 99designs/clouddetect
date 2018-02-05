package clouddetect

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net"
	"net/http"
	"regexp"

	"golang.org/x/net/html"
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

const (
	// ProviderAmazon is AWS
	ProviderAmazon = "Amazon Web Services"
	// ProviderGoogle is Google Cloud
	ProviderGoogle = "Google Cloud"
	// ProviderMicrosft is Microsoft Azure
	ProviderMicrosoft = "Microsoft Azure"
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
				ProviderName: ProviderAmazon,
			}, nil
		}
		return nil, err
	}

	// Azure
	_, err = resolveMicrosoft(ip)
	if err != ErrNotCloudIP {
		if err == nil {
			return &Response{
				ProviderName: ProviderMicrosoft,
			}, nil
		}
		return nil, err
	}

	// GCP
	match, err := resolveGoogle(ip)
	if !match || err != ErrNotCloudIP {
		if err == nil {
			return &Response{
				ProviderName: ProviderGoogle,
			}, nil
		}
		return nil, err
	}

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

var domainRegexp = regexp.MustCompile(`include:([^\s]+)`)
var ipRegexp = regexp.MustCompile(`ip\d:([^\s]+)`)

func resolveGoogle(ip net.IP) (bool, error) {
	r, err := net.LookupTXT("_cloud-netblocks.googleusercontent.com")
	if err != nil {
		return false, err
	}

	// TXT record returns result like:
	// v=spf1 include:_cloud-netblocks1.googleusercontent.com include:_cloud-netblocks2.googleusercontent.com include:_cloud-netblocks3.googleusercontent.com include:_cloud-netblocks4.googleusercontent.com include:_cloud-netblocks5.googleusercontent.com ?all
	for _, e := range r {
		matches := domainRegexp.FindAllStringSubmatch(e, -1)
		for _, subMatches := range matches {
			r, err := net.LookupTXT(subMatches[1])
			if err != nil {
				return false, err
			}
			// v=spf1 ip4:35.190.0.0/17 ip4:35.190.128.0/18 ip4:35.190.192.0/19 ip4:35.190.224.0/20 ip4:35.192.0.0/14 ip4:35.196.0.0/15 ip4:35.198.0.0/16 ip4:35.199.0.0/17 ip4:35.199.128.0/18 ip4:35.200.0.0/15 ip4:35.204.0.0/15 ip6:2600:1900::/35 ?all
			for _, e := range r {
				ipMatches := ipRegexp.FindAllStringSubmatch(e, -1)

				for _, ipSubMatches := range ipMatches {
					_, net, err := net.ParseCIDR(ipSubMatches[1])
					if err != nil {
						return false, err
					}
					if net.Contains(ip) {
						return true, nil
					}
				}
			}

		}
	}
	return false, ErrNotCloudIP
}

type azureIPRanges struct {
	Regions []azureRegion `xml:"Region"`
}

type azureRegion struct {
	Name     string         `xml:"Name,attr"`
	IPRanges []azureIPRange `xml:"IpRange"`
}

type azureIPRange struct {
	Subnet string `xml:"Subnet,attr"`
}

var azureXMLFileRegexp = regexp.MustCompile(`.*?PublicIPs.*?xml`)

func resolveMicrosoft(ip net.IP) (string, error) {
	downloadPage := "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"
	res, err := http.Get(downloadPage)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	xmlURI := ""
	doc := html.NewTokenizer(res.Body)
	for {
		e := doc.Next()
		if e == html.StartTagToken {
			tag := doc.Token()
			if tag.Data == "a" {
				for _, a := range tag.Attr {
					if a.Key == "href" {
						if azureXMLFileRegexp.Match([]byte(a.Val)) {
							xmlURI = a.Val
						}
						break
					}
				}
			}
		}

		if xmlURI != "" {
			break
		}
	}

	req, err := http.NewRequest("GET", xmlURI, nil)
	if err != nil {
		return "", err
	}
	for _, cookie := range res.Cookies() {
		req.AddCookie(cookie)
	}

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// 	<?xml version="1.0" encoding="utf-8"?>
	// 	<AzurePublicIpAddresses xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	//   	<Region Name="australiaeast">
	//     		<IpRange Subnet="13.70.64.0/18" />
	azure := azureIPRanges{}
	if err := xml.NewDecoder(res.Body).Decode(&azure); err != nil {
		return "", err
	}
	for _, region := range azure.Regions {
		for _, v := range region.IPRanges {
			_, net, err := net.ParseCIDR(v.Subnet)
			if err != nil {
				return "", err
			}
			if net.Contains(ip) {
				return region.Name, nil
			}
		}
	}
	return "", ErrNotCloudIP
}
