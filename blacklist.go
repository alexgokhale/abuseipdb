package abuseipdb

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strconv"
	"time"
)

// BlacklistResponse represents the AbuseIPDB API response for the most reported IP addresses.
type BlacklistResponse struct {
	Meta struct {
		GeneratedAt time.Time `json:"generatedAt"`
	} `json:"meta"`
	Data []struct {
		IPAddress            string    `json:"ipAddress"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
	} `json:"data"`
}

type blacklistConfig struct {
	confidenceMinimum int
	limit             int
}

var defaultBlacklistConfig = blacklistConfig{
	confidenceMinimum: -1,
	limit:             10000,
}

// NoBlacklistLimit is a very high number used to retreive the full blacklist.
// See: https://docs.abuseipdb.com/#blacklist-ip-truncation
var NoBlacklistLimit = 9999999

// BlacklistOption sets an optional parameter for calls to the Blacklist endpoint.
type BlacklistOption func(*blacklistConfig)

// Limit returns a BlacklistOption that sets the number of IPs to return.
// The minimum value for the limit is 1, and the maximum value for standard users is 10,000.
// As a subscriber, this value is unlimited.
// The limit is set to 10,000 by default.
func Limit(count int) BlacklistOption {
	return func(config *blacklistConfig) {
		config.limit = count
	}
}

// ConfidenceMinimum returns a BlacklistOption that sets the lowest abuse confidence score to be included in the response.
// This feature is only available to subscribers, and as such all free users should leave this value as -1.
// The confidence minimum can be set anywhere between 25 and 100. The default value is 100.
func ConfidenceMinimum(score int) BlacklistOption {
	return func(config *blacklistConfig) {
		config.confidenceMinimum = score
	}
}

// Blacklist will return a list of the most reported IP addresses.
func (c *Client) Blacklist(options ...BlacklistOption) (*BlacklistResponse, error) {
	config := defaultBlacklistConfig

	for _, option := range options {
		option(&config)
	}

	params := make(map[string]string)

	if (config.confidenceMinimum < 25 || config.confidenceMinimum > 100) && config.confidenceMinimum != -1 {
		return nil, errors.New("confidenceMinimum must be between 25 and 100 as a premium user, or -1 otherwise")
	}

	if config.confidenceMinimum != -1 {
		params["confidenceMinimum"] = strconv.Itoa(config.confidenceMinimum)
	}

	if config.limit < 1 {
		return nil, errors.New("limit must be greater than 1")
	}

	params["limit"] = strconv.Itoa(config.limit)

	res, err := c.makeRequest("GET", "/blacklist", RequestOptions{
		Params: params,
	})

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	blacklistResponse := BlacklistResponse{}

	err = json.Unmarshal(body, &blacklistResponse)

	if err != nil {
		return nil, err
	}

	return &blacklistResponse, nil
}
