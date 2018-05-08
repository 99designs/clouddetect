package clouddetect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var (
	DefaultCacheRefreshTimeout time.Duration = 2 * time.Minute
	logger                     *Logger       = &Logger{false}
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
	TTL                 time.Duration
	CacheFilePath       string
	CacheRefreshTimeout time.Duration
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
	// ErrCacheRefreshInProgress is returned when RefreshCache is called while an existing refresh is occurring
	ErrCacheRefreshInProgress = errors.New("cache refresh is already in progress")
	// ErrDiskCacheExpired is returned when trying to refresh from disk with a file that has exceeded the TTL
	ErrDiskCacheExpired = errors.New("cache on disk is expired")
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
		TTL:                 TTL,
		cacheMutex:          &sync.RWMutex{},
		CacheRefreshTimeout: DefaultCacheRefreshTimeout,
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
	self := "clouddetect.Resolve"

	c.cacheMutex.RLock()
	if len(c.subnetCache) == 0 || c.cacheWriteTime.Add(c.TTL).Before(time.Now()) {
		c.cacheMutex.RUnlock()
		logger.Printf("[%s] Cloud IP cache may need to be refreshed", self)

		// Only allow one thread to actually trigger a cache refresh update
		c.cacheMutex.Lock()
		if c.cacheWriteTime.Add(c.TTL).Before(time.Now()) {
			isFirstRun := len(c.subnetCache) == 0
			logger.Printf("[%s] Cloud IP cache needs to be refreshed, isFirstRun = %t", self, isFirstRun)

			if isFirstRun {
				// Synchronously refresh the cache because we don't yet have any subnets
				c.refreshCache(true, c.cacheWriteTime)
				c.cacheMutex.Unlock()
				logger.Printf("[%s] Synchronously refreshed cache", self)
			} else {
				// Ensure future checks don't trigger subsequent refreshes
				minModTime := c.cacheWriteTime
				c.cacheWriteTime = time.Now()
				c.cacheMutex.Unlock()

				// Asynchronously refresh the cache because we already have subnets in memory
				logger.Printf("[%s] Asynchronously refreshing cache", self)
				go c.refreshCache(false, minModTime)
			}
		} else {
			logger.Printf("[%s] Another thread has already updated the cache", self)
			c.cacheMutex.Unlock()
		}
	} else {
		// Cache does not need to be refreshed
		c.cacheMutex.RUnlock()
	}

	c.cacheMutex.RLock()
	// Copy data so we don't hold the read-lock too long and prevent async RefreshCache from completing
	subnets := c.subnetCache
	c.cacheMutex.RUnlock()

	for _, subNet := range subnets {
		if subNet.Subnet.Contains(ip) {
			return subNet, nil
		}
	}

	return nil, ErrNotCloudIP
}

// RefreshCache loads the cloud provider subnet data from disk (if available) and then from the web
func (c *Client) RefreshCache() (err error) {
	return c.refreshCache(false, c.cacheWriteTime)
}
func (c *Client) refreshCache(isMutexAlreadyLocked bool, minModTime time.Time) (err error) {
	self := "clouddetect.refreshCache"

	if !isMutexAlreadyLocked {
		c.cacheMutex.Lock()
	}
	if c.cacheRefreshInProgress {
		if !isMutexAlreadyLocked {
			c.cacheMutex.Unlock()
		}

		logger.Printf("[%s] refreshCache called when refresh was already in progress, skipping second run\n", self)
		return ErrCacheRefreshInProgress
	}
	// Refresh in progress is set to false again by the disk/web methods that actually write cache data
	c.cacheRefreshInProgress = true
	if !isMutexAlreadyLocked {
		c.cacheMutex.Unlock()
	}

	logger.Printf("[%s] Refreshing cache of cloud IPs...\n", self)
	if c.CacheFilePath != "" {
		// Always check the local cache first, it may have been updated by another process
		if err = c.refreshCacheFromDisk(isMutexAlreadyLocked, minModTime); err == nil {
			if c.cacheWriteTime.Add(c.TTL).After(time.Now()) {
				// The local cache is still up to date
				logger.Printf("[%s] Local cache is up to date, using cache from disk\n", self)
				return nil
			} else {
				logger.Printf("[%s] Local cache is not up to date, reloading cache from web\n", self)
			}
		} else if err == ErrDiskCacheExpired {
			logger.Printf("[%s] Local cache is not up to date, reloading cache from web\n", self)
		} else {
			logger.Printf("[%s] Could not load cache from disk: %v\n", self, err)
		}

		if stat, err := os.Stat(c.lockFilePath()); err == nil {
			logger.Printf("[%s] Found an existing lock file\n", self)
			// Another process is refreshing the cache, ensure it's not an old lock file
			if stat.ModTime().Add(c.TTL).Before(time.Now()) {
				// The lock file has existed longer than expected
				if err = os.Remove(c.lockFilePath()); err == nil {
					logger.Printf("[%s] Existing lock file was expired, removed lock file, and refreshing cache from web\n", self)
					return c.refreshCacheFromWeb(isMutexAlreadyLocked)
				} else {
					logger.Printf("[%s] Could not remove expired lock file, refreshing cache from web\n", self)
					return c.refreshCacheFromWeb(isMutexAlreadyLocked)
				}
			}

			start := time.Now()
			for start.Add(c.CacheRefreshTimeout).After(time.Now()) {
				time.Sleep(5 * time.Second)
				logger.Printf("[%s] Waiting for another process to finish with lock file\n", self)
				if _, err := os.Stat(c.lockFilePath()); err == nil {
					continue
				} else if os.IsNotExist(err) {
					// Lock file has been removed, refresh the cache from disk, we pass time.Time{} to ensure we always use the disk data after a lock file is removed
					logger.Printf("[%s] Lock file has been removed, refreshing cache from disk\n", self)
					return c.refreshCacheFromDisk(isMutexAlreadyLocked, time.Time{})
				} else {
					// Unexpected error when checking for lock file
					logger.Printf("[%s] Could not check status of lock file (%v), refreshing from web\n", self, err)
					return c.refreshCacheFromWeb(isMutexAlreadyLocked)
				}
			}

			// The other process didn't successfully refresh the cache, await the next interval of refresh cache
			logger.Printf("[%s] Lock file not processed after cache refresh timeout period, refreshing from web\n", self)
			return c.refreshCacheFromWeb(isMutexAlreadyLocked)
		}

		// This process is the one responsible for the lock file refresh.
		if lockFile, err := os.OpenFile(c.lockFilePath(), os.O_RDONLY|os.O_CREATE, os.ModePerm); err == nil {
			// We don't need to interact with the file, so we can close it immediately.
			lockFile.Close()
			logger.Printf("[%s] Created lock file, refreshing cache from web\n", self)
			defer func() {
				if err := os.Remove(lockFile.Name()); err != nil {
					logger.Printf("[%s] Could not remove lock file after completing refresh: %v\n", self, err)
				}
			}()
		} else {
			// Could not create lock file
			logger.Printf("[%s] Could not create lock file, refreshing cache from web\n", self)
		}
	}

	return c.refreshCacheFromWeb(isMutexAlreadyLocked)
}

func (c *Client) lockFilePath() (lfp string) {
	return fmt.Sprintf("%s.lock", c.CacheFilePath)
}

func (c *Client) refreshCacheFromWeb(isMutexAlreadyLocked bool) (err error) {
	// Refresh the cache from the web
	subnetCache := []*Response{}
	self := "clouddetect.refreshCacheFromWeb"

	logger.Printf("[%s] Downloading Amazon CIDRs...\n", self)
	amazon, err := getAmazonCIDRs()
	if err != nil {
		logger.Printf("[%s] Could not download Amazon CIDRs: %v\n", self, err)
		return err
	}
	subnetCache = append(subnetCache, amazon...)

	logger.Printf("[%s] Downloading Google CIDRs...\n", self)
	google, err := getGoogleCIDRs()
	if err != nil {
		logger.Printf("[%s] Could not download Google CIDRs: %v\n", self, err)
		return err
	}
	subnetCache = append(subnetCache, google...)

	logger.Printf("[%s] Downloading Microsoft CIDRs...\n", self)
	microsoft, err := getMicrosoftCIDRs()
	if err != nil {
		logger.Printf("[%s] Could not download Microsoft CIDRs: %v\n", self, err)
		return err
	}
	subnetCache = append(subnetCache, microsoft...)

	if c.CacheFilePath != "" {
		logger.Printf("[%s] Saving subnetCache to disk...\n", self)
		cache := diskCache{
			SubnetCache: subnetCache,
		}
		// The > 2 check is to ensure we're not serializing an empty JSON file, i.e. {}
		if data, err := json.MarshalIndent(cache, "", "  "); err == nil && len(data) > 2 {
			if err = ioutil.WriteFile(c.CacheFilePath, data, os.ModePerm); err != nil {
				logger.Printf("[%s] Could not write cache file (%s): %v\n", self, c.CacheFilePath, err)
			}
		} else {
			logger.Printf("[%s] Could not marshal cache data to JSON: %v\n", self, err)
		}
	}

	logger.Printf("[%s] Updating client cache properties...\n", self)
	if !isMutexAlreadyLocked {
		c.cacheMutex.Lock()
	}
	c.subnetCache = subnetCache
	c.cacheWriteTime = time.Now()
	c.cacheSource = cacheSourceWeb
	c.cacheRefreshInProgress = false
	if !isMutexAlreadyLocked {
		c.cacheMutex.Unlock()
	}
	logger.Printf("[%s] Finished refreshing cache from web\n", self)

	return nil
}

func (c *Client) refreshCacheFromDisk(isMutexAlreadyLocked bool, minModTime time.Time) (err error) {
	self := "clouddetect.refreshCacheFromDisk"

	f, err := os.OpenFile(c.CacheFilePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		if err != os.ErrNotExist {
			logger.Printf("[%s] Could not open cache file path (%s): %v\n", self, c.CacheFilePath, err)
		}
		return err
	}
	defer f.Close()

	logger.Printf("[%s] Checking mod time for cache file...\n", self)
	var modTime time.Time
	if stat, err := f.Stat(); err != nil {
		logger.Printf("[%s] Could not call Stat(): %v\n", self, err)
		return err
	} else if modTime = stat.ModTime(); minModTime.After(modTime) {
		// The local disk cache needs to be refreshed too
		logger.Printf("[%s] Local disk cache needs to be refreshed too, skipping disk refresh\n", self)
		return ErrDiskCacheExpired
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		logger.Printf("[%s] Could not read data from cache file: %v\n", self, err)
		return err
	}

	var cache diskCache
	err = json.Unmarshal(data, &cache)
	if err != nil {
		logger.Printf("[%s] Could not unmarshal cache data: %v\n", self, err)
		return err
	}

	logger.Printf("[%s] Updating client cache properties...\n", self)
	if !isMutexAlreadyLocked {
		c.cacheMutex.Lock()
	}
	c.subnetCache = cache.SubnetCache
	c.cacheWriteTime = modTime
	c.cacheSource = cacheSourceDisk
	c.cacheRefreshInProgress = false
	if !isMutexAlreadyLocked {
		c.cacheMutex.Unlock()
	}
	logger.Printf("[%s] Finished refreshing cache from web\n", self)

	return nil
}

// Count retruns the number of cloud provider subnets loaded in the cache
func (c *Client) Count() (subnetCount int) {
	return len(c.subnetCache)
}

type Logger struct {
	Enabled bool
}

func (this *Logger) Printf(format string, v ...interface{}) {
	if this.Enabled {
		log.Printf(format, v...)
	}
}
