package clouddetect

import (
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	testCases = []struct {
		providerName string
		ip           string
	}{
		{ProviderAmazon, "54.199.144.109"},
		{ProviderGoogle, "146.148.34.2"},
		{ProviderMicrosoft, "168.61.66.2"},
	}
)

func TestDetect(t *testing.T) {
	client := DefaultClient()

	for _, tc := range testCases {
		t.Run(tc.providerName, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			match, err := client.Resolve(ip)
			if err != nil || match.ProviderName != tc.providerName {
				t.Errorf("Expected %v to resolve to %v, got %#v:%#v", ip, tc.providerName, match, err)
			}
		})
	}

	t.Run("No Match", func(t *testing.T) {
		badIP := net.ParseIP("127.0.0.1")
		_, err := client.Resolve(badIP)
		if err != ErrNotCloudIP {
			t.Errorf("%v resolved incorrectly with %v", badIP, err)
		}
	})
}

func TestThatRefreshCacheToDiskWorks(t *testing.T) {
	tempFile, err := ioutil.TempFile(os.TempDir(), "clouddetect_test")
	if err != nil {
		t.Errorf("Could not create temp file for cache output: %v", err)
		return
	}
	// last-in, first-out
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	client := DefaultClient()
	client.CacheFilePath = tempFile.Name()

	if err := client.RefreshCache(); err != nil {
		t.Error(err)
		return
	}

	if len(client.subnetCache) == 0 {
		t.Error("client.subnetCache is empty, expected records.")
		return
	}
	if stat, err := os.Stat(client.CacheFilePath); err != nil {
		t.Errorf("Could not get cache file (%s) stat: %v", client.CacheFilePath, err)
		return
	} else if size := stat.Size(); size < 3 {
		t.Errorf("Cache file is empty, but subnetCache contains %d records", len(client.subnetCache))
		return
	} else {
		t.Logf("Found %d subnet records and saved to disk in %d bytes.", len(client.subnetCache), size)
	}

	for _, tc := range testCases {
		t.Run(tc.providerName, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			match, err := client.Resolve(ip)
			if err != nil || match.ProviderName != tc.providerName {
				t.Errorf("Expected %v to resolve to %v, got %#v:%#v", ip, tc.providerName, match, err)
			}
		})
	}

	t.Logf("Successfully resolved %d test cases", len(testCases))
}

func TestThatMultiProcessRefreshCacheFromDiskWorks(t *testing.T) {
	tempFile, err := ioutil.TempFile(os.TempDir(), "clouddetect_test")
	if err != nil {
		t.Errorf("Could not create temp file for cache output: %v", err)
		return
	}
	// last-in, first-out
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	client1 := NewClient(12 * time.Hour)
	client1.CacheFilePath = tempFile.Name()

	client2 := NewClient(12 * time.Hour)
	client2.CacheFilePath = client1.CacheFilePath

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := client1.RefreshCache(); err != nil {
			t.Errorf("Client1: RefreshCache failed: %v", err)
		}
		wg.Done()
	}()

	// Ensure the lock file exists
	time.Sleep(1 * time.Second)
	if _, err := os.Stat(client1.lockFilePath()); os.IsNotExist(err) {
		t.Errorf("Expected lock file to exist after starting initial RefreshCache gorouting, but file stat returned: %v", err)
	}

	wg.Add(1)
	go func() {
		if err := client2.RefreshCache(); err != nil {
			t.Errorf("Client2: RefreshCache failed: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()
	t.Logf("Finished refreshing cache via 2 goroutines. Found %d subnet records.", len(client1.subnetCache))

	if _, err := os.Stat(client1.lockFilePath()); !os.IsNotExist(err) {
		t.Errorf("Expected lock file IsNotExist err value after refresh cache call, but file stat returned: %v", err)
	}

	// Ensure the first process reloaded from the web
	if client1.cacheSource != cacheSourceWeb {
		t.Errorf("Expected client1 cache source to be %s, but received %s", cacheSourceWeb, client1.cacheSource)
	}
	if client2.cacheSource != cacheSourceDisk {
		t.Errorf("Expected client2 cache source to be %s, but received %s", cacheSourceDisk, client2.cacheSource)
	}
	if len(client1.subnetCache) != len(client2.subnetCache) {
		t.Errorf("Expected client1 subnetCache count (%d) to match client2 subnetCache count (%d), but it didn't", len(client1.subnetCache), len(client2.subnetCache))
	}
}

func TestThatDeleteOldLockFileWorks(t *testing.T) {
	tempFile, err := ioutil.TempFile(os.TempDir(), "clouddetect_test")
	if err != nil {
		t.Errorf("Could not create temp file for cache output: %v", err)
		return
	}
	// last-in, first-out
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	client := DefaultClient()
	client.CacheFilePath = tempFile.Name()

	f, err := os.OpenFile(client.lockFilePath(), os.O_RDONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		t.Error(err)
		return
	}
	f.Close()

	if err = os.Chtimes(client.lockFilePath(), time.Now().Add(-24*time.Hour), time.Now().Add(-24*time.Hour)); err != nil {
		t.Error(err)
		return
	}

	if err := client.RefreshCache(); err != nil {
		t.Error(err)
		return
	}

	if len(client.subnetCache) == 0 {
		t.Error("client.subnetCache is empty, expected records.")
		return
	}
	if stat, err := os.Stat(client.CacheFilePath); err != nil {
		t.Errorf("Could not get cache file (%s) stat: %v", client.CacheFilePath, err)
		return
	} else if size := stat.Size(); size < 3 {
		t.Errorf("Cache file is empty, but subnetCache contains %d records", len(client.subnetCache))
		return
	} else {
		t.Logf("Found %d subnet records and saved to disk in %d bytes.", len(client.subnetCache), size)
	}
}
