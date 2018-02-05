package clouddetect

import (
	"net"
	"testing"
)

func TestDetect(t *testing.T) {
	client := DefaultClient()

	testCases := []struct {
		providerName string
		ip           string
	}{
		{ProviderAmazon, "54.199.144.109"},
		{ProviderGoogle, "146.148.34.2"},
		{ProviderMicrosoft, "168.61.66.2"},
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

	t.Run("No Match", func(t *testing.T) {
		badIP := net.ParseIP("127.0.0.1")
		_, err := client.Resolve(badIP)
		if err != ErrNotCloudIP {
			t.Errorf("%v resolved incorrectly with %v", badIP, err)
		}
	})
}
