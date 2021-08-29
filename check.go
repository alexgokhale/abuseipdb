package abuseipdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"
)

// CheckResponse represents the AbuseIPDB API response for a specific IP that has been checked.
type CheckResponse struct {
	Data struct {
		IPAddress            string    `json:"ipAddress"`
		IsPublic             bool      `json:"isPublic"`
		IPVersion            int       `json:"ipVersion"`
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		CountryCode          string    `json:"countryCode"`
		CountryName          string    `json:"countryName"`
		UsageType            string    `json:"usageType"`
		ISP                  string    `json:"isp"`
		Domain               string    `json:"domain"`
		Hostnames            []string  `json:"hostnames"`
		TotalReports         int       `json:"totalReports"`
		NumDistinctUsers     int       `json:"numDistinctUsers"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
		Reports              []Report  `json:"reports"`
	} `json:"data"`
}

// CheckBlockResponse represents the AbuseIPDB API response for a specific subnet/netblock that has been checked.
type CheckBlockResponse struct {
	Data struct {
		NetworkAddress   string `json:"networkAddress"`
		Netmask          string `json:"netmask"`
		MinAddress       string `json:"minAddress"`
		MaxAddress       string `json:"maxAddress"`
		NumPossibleHosts int    `json:"numPossibleHosts"`
		AddressSpaceDesc string `json:"addressSpaceDesc"`
		ReportedAddress  []struct {
			IPAddress            string    `json:"ipAddress"`
			NumReports           int       `json:"numReports"`
			MostRecentReport     time.Time `json:"mostRecentReport"`
			AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
			CountryCode          string    `json:"countryCode"`
		} `json:"reportedAddress"`
	} `json:"data"`
}

// Report represents the AbuseIPDB object for a report made about an IP address by a user.
type Report struct {
	ReportedAt          time.Time `json:"reportedAt"`
	Comment             string    `json:"comment"`
	Categories          []int     `json:"categories"`
	ReporterID          int       `json:"reporterId"`
	ReporterCountryCode string    `json:"reporterCountryCode"`
	ReporterCountryName string    `json:"reporterCountryName"`
}

type checkConfig struct {
	verbose      bool
	maxAgeInDays int
}

var defaultCheckConfig = checkConfig{
	verbose:      true,
	maxAgeInDays: 30,
}

var defaultCheckBlockConfig = checkConfig{
	verbose:      true,
	maxAgeInDays: 30,
}

// CheckOption sets an optional parameter for calls to the Check and CheckBlock endpoints.
type CheckOption func(*checkConfig)

// Verbose returns a CheckOption that sets the verbose request parameter.
// If verbose is enabled, the country name and reports are included in the response for an IP address.
// This option is enabled by default.
func Verbose(enabled bool) CheckOption {
	return func(config *checkConfig) {
		config.verbose = enabled
	}
}

// MaxAgeInDays returns a CheckOption that sets the maximum age of reports to fetch when checking an IP address.
// The default value is 30 days, and can be any value between 1 and 365.
// For the CheckBlock endpoint, a subscription is required to use a value for maxAgeInDays that is greater than 30.
// Basic subscribers can use up to 60, and Premium subscribers can use up to 365.
func MaxAgeInDays(days int) CheckOption {
	return func(config *checkConfig) {
		config.maxAgeInDays = days
	}
}

// Check will return the stored information about the IP provided (either v4 or v6).
func (c *Client) Check(ipAddress string, options ...CheckOption) (*CheckResponse, error) {
	config := defaultCheckConfig

	for _, option := range options {
		option(&config)
	}

	params := map[string]string{
		"ipAddress": ipAddress,
	}

	if config.verbose {
		params["verbose"] = fmt.Sprintf("%t", config.verbose)
	}

	if config.maxAgeInDays < 1 || config.maxAgeInDays > 365 {
		return nil, errors.New("maxAgeInDays must be between 1 and 365")
	}

	params["maxAgeInDays"] = strconv.Itoa(config.maxAgeInDays)

	res, err := c.makeRequest("GET", "/check", RequestOptions{
		Params: params,
	})

	if err != nil {
		return nil, err
	}

	responseBody, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	checkResponse := CheckResponse{}

	err = json.Unmarshal(responseBody, &checkResponse)

	if err != nil {
		return nil, err
	}

	return &checkResponse, nil
}

// CheckBlock will return the stored information about the subnet (either v4 or v6) provided, denoted with CIDR notation.
// The maxmimum size of subnets you can check is based on plan tier. Free users are limited to /24 and smaller,
// Basic plan users are limited to /20 and smaller and Premium plan users are limited to /16 and smaller.
func (c *Client) CheckBlock(subnet string, options ...CheckOption) (*CheckBlockResponse, error) {
	config := defaultCheckBlockConfig

	for _, option := range options {
		option(&config)
	}

	params := map[string]string{
		"network": subnet,
	}

	if config.maxAgeInDays < 1 || config.maxAgeInDays > 365 {
		return nil, errors.New("maxAgeInDays must be between 1 and 365")
	}

	params["maxAgeInDays"] = strconv.Itoa(config.maxAgeInDays)

	res, err := c.makeRequest("GET", "/check-block", RequestOptions{
		Params: params,
	})

	if err != nil {
		return nil, err
	}

	responseBody, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	checkBlockResponse := CheckBlockResponse{}

	err = json.Unmarshal(responseBody, &checkBlockResponse)

	if err != nil {
		return nil, err
	}

	return &checkBlockResponse, nil
}
