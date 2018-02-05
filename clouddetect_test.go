package clouddetect

import (
	"net"
	"testing"
)

func TestAmazonIP(t *testing.T) {
	// 54.199.144.109 was an AWS japan EC2 ip
	goodIP := net.ParseIP("54.199.144.109")
	service, err := Resolve(goodIP)
	if service.ProviderName != "Amazon Web Services" || err != nil {
		t.Errorf("%v resolved incorrectly with %#v:%v", goodIP, service, err)
	}
}

func TestGoogleIP(t *testing.T) {
	// Pulled 146.148.32.0/19 as a test example, expect this to be flaky
	goodIP := net.ParseIP("146.148.34.2")
	service, err := Resolve(goodIP)
	if service.ProviderName != "Google Cloud" || err != nil {
		t.Errorf("%v resolved incorrectly with %#v:%v", goodIP, service, err)
	}
}

func TestNoMatch(t *testing.T) {
	badIP := net.ParseIP("127.0.0.1")
	_, err := Resolve(badIP)
	if err != ErrNotCloudIP {
		t.Errorf("%v resolved incorrectly with %v", badIP, err)
	}
}
