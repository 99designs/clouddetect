package clouddetect

import (
	"encoding/xml"
	"net"
	"net/http"
	"regexp"

	"golang.org/x/net/html"
)

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

func getMicrosoftCIDRs() ([]*Response, error) {
	downloadPage := "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"
	res, err := http.Get(downloadPage)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	for _, cookie := range res.Cookies() {
		req.AddCookie(cookie)
	}

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// 	<?xml version="1.0" encoding="utf-8"?>
	// 	<AzurePublicIpAddresses xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	//   	<Region Name="australiaeast">
	//     		<IpRange Subnet="13.70.64.0/18" />
	azure := azureIPRanges{}
	if err := xml.NewDecoder(res.Body).Decode(&azure); err != nil {
		return nil, err
	}

	responses := []*Response{}

	for _, region := range azure.Regions {
		for _, v := range region.IPRanges {
			_, net, err := net.ParseCIDR(v.Subnet)
			if err != nil {
				return nil, err
			}

			response := &Response{
				ProviderName: ProviderMicrosoft,
				Region:       region.Name,
				Subnet:       net,
			}
			responses = append(responses, response)
		}
	}

	return responses, nil
}
