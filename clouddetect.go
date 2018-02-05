package clouddetect

import (
	"errors"
	"net"
)

type Client struct {
	foo int // unexported nothing
}

type Response struct {
	ProviderName string
}

var (
	ErrNotCloudIP = errors.New("not resolved to any known cloud IP range")
)

func DefaultClient() *Client {
	return &Client{}
}

func Resolve(ip net.IP) (*Response, error) {
	return DefaultClient().Resolve(ip)
}

func (c *Client) Resolve(ip net.IP) (*Response, error) {
	return nil, ErrNotCloudIP
}
