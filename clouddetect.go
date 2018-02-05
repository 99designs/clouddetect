package clouddetect

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Client will eventually hold cache of IP ranges
type Client struct {
	// unexported cache storage
	subnetCache    []*Response
	cacheWriteTime time.Time
	cacheMutex     *sync.Mutex

	// Time to keep IP ranges cached for (default 12 hours)
	TTL time.Duration
}

// Response provides details of the cloud environment the IP resolved to
type Response struct {
	ProviderName string
	Region       string
	Subnet       *net.IPNet
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
	// ProviderMicrosoft is Microsoft Azure
	ProviderMicrosoft = "Microsoft Azure"
)

// NewClient generates a Client with specified cache TTL
func NewClient(TTL time.Duration) *Client {
	return &Client{
		TTL:        TTL,
		cacheMutex: &sync.Mutex{},
	}
}

var defaultClient *Client

// DefaultClient is the default Client for resolving requests
func DefaultClient() *Client {
	if defaultClient == nil {
		defaultClient = NewClient(12 * time.Hour)
	}
	return defaultClient
}

// Resolve is a convenience function to resolve an IP against the DefaultClient
func Resolve(ip net.IP) (*Response, error) {
	return DefaultClient().Resolve(ip)
}

func (c *Client) allSubnetsForProviders() ([]*Response, error) {
	c.cacheMutex.Lock()
	if c.subnetCache == nil || c.cacheWriteTime.Add(c.TTL).Before(time.Now()) {
		c.subnetCache = []*Response{}

		amazon, err := getAmazonCIDRs()
		if err != nil {
			return nil, err
		}
		c.subnetCache = append(c.subnetCache, amazon...)

		google, err := getGoogleCIDRs()
		if err != nil {
			return nil, err
		}
		c.subnetCache = append(c.subnetCache, google...)

		microsoft, err := getMicrosoftCIDRs()
		if err != nil {
			return nil, err
		}
		c.subnetCache = append(c.subnetCache, microsoft...)
		c.cacheWriteTime = time.Now()
	}
	c.cacheMutex.Unlock()

	return c.subnetCache, nil
}

// Resolve will take the given ip and determine if it exists within any of the major
// cloud providers' published IP ranges and any extra metadata that may be of use.
// It returns ErrNotCloudIP if the IP does not resolve against any lists
func (c *Client) Resolve(ip net.IP) (*Response, error) {
	subNets, err := c.allSubnetsForProviders()
	if err != nil {
		return nil, err
	}

	for _, subNet := range subNets {
		if subNet.Subnet.Contains(ip) {
			return subNet, nil
		}
	}

	return nil, ErrNotCloudIP
}
