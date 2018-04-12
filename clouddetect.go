package clouddetect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"
)

// Client will eventually hold cache of IP ranges
type Client struct {
	// unexported cache storage
	subnetCache            []*Response
	cacheWriteTime         time.Time
	cacheMutex             *sync.RWMutex
	cacheSource            string
	cacheRefreshInProgress bool

	// Time to keep IP ranges cached for (default 12 hours)
	TTL           time.Duration
	CacheFilePath string
}

type diskCache struct {
	SubnetCache []*Response `json:"cache"`
}

// Response provides details of the cloud environment the IP resolved to
type Response struct {
	ProviderName string     `json:"providerName"`
	Region       string     `json:"region"`
	Subnet       *net.IPNet `json:"subnet"`
}

var (
	// ErrNotCloudIP is error returned when IP does not match any of the published list of ranges
	ErrNotCloudIP = errors.New("not resolved to any known cloud IP range")
	// ErrCacheFileLocked is returned when a RefreshCache call times out due to the presence of a lock file
	ErrCacheFileLocked = errors.New("cache lock file exists, skipping cache refresh")
)

const (
	// ProviderAmazon is AWS
	ProviderAmazon = "Amazon Web Services"
	// ProviderGoogle is Google Cloud
	ProviderGoogle = "Google Cloud"
	// ProviderMicrosoft is Microsoft Azure
	ProviderMicrosoft = "Microsoft Azure"
	cacheSourceDisk   = "Disk"
	cacheSourceWeb    = "Web"
)

// NewClient generates a Client with specified cache TTL
func NewClient(TTL time.Duration) *Client {
	return &Client{
		TTL:        TTL,
		cacheMutex: &sync.RWMutex{},
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

// Resolve will take the given ip and determine if it exists within any of the major
// cloud providers' published IP ranges and any extra metadata that may be of use.
// It returns ErrNotCloudIP if the IP does not resolve against any lists
func (c *Client) Resolve(ip net.IP) (response *Response, err error) {
	c.cacheMutex.RLock()
	if len(c.subnetCache) == 0 || c.cacheWriteTime.Add(c.TTL).Before(time.Now()) {
		isFirstRun := len(c.subnetCache) == 0
		c.cacheMutex.RUnlock()

		if isFirstRun {
			// Synchronously refresh the cache
			c.RefreshCache()
		} else {
			// Ensure future checks don't trigger subsequent refreshes
			c.cacheMutex.Lock()
			c.cacheWriteTime = time.Now()
			c.cacheMutex.Unlock()

			// Asynchronously refresh the cache because we already have subnets in memory
			go c.RefreshCache()
		}
	}

	c.cacheMutex.RLock()
	for _, subNet := range c.subnetCache {
		if subNet.Subnet.Contains(ip) {
			c.cacheMutex.RUnlock()
			return subNet, nil
		}
	}
	c.cacheMutex.RUnlock()

	return nil, ErrNotCloudIP
}

// RefreshCache loads the cloud provider subnet data from disk (if available) and then from the web
func (c *Client) RefreshCache() (err error) {
	c.cacheMutex.Lock()
	c.cacheRefreshInProgress = true
	c.cacheMutex.Unlock()
	defer func() {
		c.cacheMutex.Lock()
		c.cacheRefreshInProgress = false
		c.cacheMutex.Unlock()
	}()

	if c.CacheFilePath != "" {
		// Always check the local cache first, it may have been updated by another process
		if err = c.refreshCacheFromDisk(c.cacheWriteTime); err == nil {
			if c.cacheWriteTime.Add(c.TTL).Before(time.Now()) {
				// The local cache is still up to date
				return nil
			}
		}

		if stat, err := os.Stat(c.lockFilePath()); err == nil {
			// Another process is refreshing the cache, ensure it's not an old lock file
			if stat.ModTime().Add(c.TTL).Before(time.Now()) {
				// The lock file has existed longer than expected
				os.Remove(c.lockFilePath())
				// Restart and generate a new lock file
				return c.RefreshCache()
			}

			start := time.Now()
			for start.Add(c.TTL).After(time.Now()) {
				time.Sleep(5 * time.Second)
				if _, err := os.Stat(c.lockFilePath()); os.IsNotExist(err) {
					// Lock file has been removed, refresh the cache from disk, we pass time.Time{} to ensure we always use the disk data after a lock file is removed
					return c.refreshCacheFromDisk(time.Time{})
				}
			}

			// The other process didn't successfully refresh the cache, await the next interval of refresh cache
			return ErrCacheFileLocked
		}

		// This process is the one responsible for the lock file refresh.
		if lockFile, err := os.OpenFile(c.lockFilePath(), os.O_RDONLY|os.O_CREATE, os.ModePerm); err == nil {
			// We don't need to interact with the file, so we can close it immediately.
			lockFile.Close()
			defer os.Remove(lockFile.Name())
		}
	}

	// Refresh the cache from the web
	subnetCache := []*Response{}

	amazon, err := getAmazonCIDRs()
	if err != nil {
		return err
	}
	subnetCache = append(subnetCache, amazon...)

	google, err := getGoogleCIDRs()
	if err != nil {
		return err
	}
	subnetCache = append(subnetCache, google...)

	microsoft, err := getMicrosoftCIDRs()
	if err != nil {
		return err
	}
	subnetCache = append(subnetCache, microsoft...)

	if c.CacheFilePath != "" {
		cache := diskCache{
			SubnetCache: subnetCache,
		}
		// The > 2 check is to ensure we're not serializing an empty JSON file, i.e. {}
		if data, err := json.MarshalIndent(cache, "", "  "); err == nil && len(data) > 2 {
			ioutil.WriteFile(c.CacheFilePath, data, os.ModePerm)
		}
	}

	c.cacheMutex.Lock()
	c.subnetCache = subnetCache
	c.cacheWriteTime = time.Now()
	c.cacheSource = cacheSourceWeb
	c.cacheMutex.Unlock()

	return nil
}

func (c *Client) lockFilePath() (lfp string) {
	return fmt.Sprintf("%s.lock", c.CacheFilePath)
}

func (c *Client) refreshCacheFromDisk(minModTime time.Time) (err error) {
	f, err := os.OpenFile(c.CacheFilePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()

	var modTime time.Time
	if stat, err := f.Stat(); err != nil {
		return err
	} else if modTime = stat.ModTime(); minModTime.After(modTime) {
		// The local disk cache needs to be refreshed too
		return nil
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	var cache diskCache
	err = json.Unmarshal(data, &cache)
	if err != nil {
		return err
	}

	c.cacheMutex.Lock()
	c.subnetCache = cache.SubnetCache
	c.cacheWriteTime = modTime
	c.cacheSource = cacheSourceDisk
	// This is technically set twice by RefreshCache() and this method, but since we're writing cache data in this method, we should ensure this flag is accurate
	c.cacheRefreshInProgress = false
	c.cacheMutex.Unlock()

	return nil
}

// Count retruns the number of cloud provider subnets loaded in the cache
func (c *Client) Count() (subnetCount int) {
	return len(c.subnetCache)
}
