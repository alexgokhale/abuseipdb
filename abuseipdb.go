package abuseipdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	version = "0.0.1"
	baseURL = "https://api.abuseipdb.com/api/v2"
)

var (
	userAgent = fmt.Sprintf("AbuseIPDB-Go-Client/%s (+https://gitlab.com/honour/abuseipdb)", version)
)

// Category represents an AbuseIPDB abuse category.
// See: https://www.abuseipdb.com/categories
type Category int

// A list of the categories supported by the AbuseIPDB API.
const (
	CategoryDNSCompromise Category = iota + 1
	CategoryDNSPoisoning
	CategoryFraudOrders
	CategoryDDoSAttack
	CategoryFTPBruteForce
	CategoryPingOfDeath
	CategoryPhishing
	CategoryFraudVOIP
	CategoryOpenProxy
	CategoryWebSpam
	CategoryEmailSpam
	CategoryBlogSpam
	CategoryVPNIP
	CategoryPortScan
	CategoryHacking
	CategorySQLInjection
	CategorySpoofing
	CategoryBruteForce
	CategoryBadWebBot
	CategoryExploitedHost
	CategoryWebAppAttack
	CategorySSH
	CategoryIoTTargeted
)

// Client is used to make requests to the AbuseIPDB API.
// Use CreateClient to initialise a new client.
type Client struct {
	httpClient *http.Client
	APIKey     string
}

// RequestOptions stores additional options used when making requests to the AbuseIPDB API,
// such as query string parameters, additional headers and the request body.
type RequestOptions struct {
	Params  map[string]string
	Headers map[string]string
	Body    []byte
}

// RequestError represents a response from the AbuseIPDB API when a request fails.
type RequestError struct {
	StatusCode int
	Details    []string
	Raw        string
}

type ErrorResponse struct {
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

func (e RequestError) Error() string {
	return fmt.Sprintf("abuseipdb: api request failed with status code %d\n%s", e.StatusCode, e.Raw)
}

// NewClient initialises a new client for making requests.
func NewClient(apiKey string) *Client {
	client := Client{
		httpClient: &http.Client{
			Timeout: time.Minute,
		},
		APIKey: apiKey,
	}

	return &client
}

func (c *Client) makeRequest(method string, endpoint string, options RequestOptions) (*http.Response, error) {
	var body io.Reader

	if options.Body == nil {
		body = nil
	} else {
		body = bytes.NewReader(options.Body)
	}

	reqUrl := fmt.Sprintf("%s%s%s", baseURL, endpoint, buildQueryString(options.Params))
	req, err := http.NewRequest(method, reqUrl, body)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("User-Agent", userAgent)

	for key, value := range options.Headers {
		// Overwrite user agent header if user chooses to set it.
		if http.CanonicalHeaderKey(key) == "User-Agent" {
			req.Header.Set(key, value)
		} else {
			req.Header.Add(key, value)
		}
	}

	res, err := c.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		body, err := ioutil.ReadAll(res.Body)

		requestError := RequestError{
			StatusCode: res.StatusCode,
		}

		if err != nil {
			requestError.Raw = string(body)
		}

		errorResponse := ErrorResponse{}

		err = json.Unmarshal(body, &errorResponse)

		if err != nil {
			details := make([]string, len(errorResponse.Errors))

			for _, e := range errorResponse.Errors {
				details = append(details, e.Detail)
			}

			requestError.Details = details
		}

		return res, requestError
	}

	return res, nil
}

func buildQueryString(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	query := "?"

	for key, value := range params {
		query += fmt.Sprintf("%s=%s&", url.QueryEscape(key), url.QueryEscape(value))
	}

	return strings.TrimSuffix(query, "&")
}

func buildCategoryString(categories []Category) string {
	if len(categories) == 0 {
		return ""
	}

	categoryString := ""

	for i, category := range categories {
		categoryString += strconv.Itoa(int(category))

		if i < len(categories)-1 {
			categoryString += ","
		}
	}

	return categoryString
}
