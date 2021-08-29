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
	version = "1.0.2"
	baseURL = "https://api.abuseipdb.com/api/v2"
)

var (
	userAgent = fmt.Sprintf("AbuseIPDB-Go-Client/%s (+https://gitlab.com/honour/abuseipdb)", version)
)

// Category represents an AbuseIPDB abuse category.
// See: https://www.abuseipdb.com/categories
type Category int

//go:generate stringer -type=Category -trimprefix=Category

// A list of the categories supported by the AbuseIPDB API.
const (
	// CategoryDNSCompromise includes abuse which involves altering DNS records resulting in improper redirection.
	CategoryDNSCompromise Category = iota + 1
	// CategoryDNSPoisoning includes abuse which involves falsifying domain server cache (cache poisoning).
	CategoryDNSPoisoning
	// CategoryFraudOrders includes abuse which involves making fraudulent purchases/orders online.
	CategoryFraudOrders
	// CategoryDDoSAttack includes abuse involving participating in distributed denial-of-service (usually as part of a botnet).
	CategoryDDoSAttack
	// CategoryFTPBruteForce includes abuse involving brute-force credential attacks against FTP servers.
	CategoryFTPBruteForce
	// CategoryPingOfDeath includes abuse involving sending oversized IP packets.
	CategoryPingOfDeath
	// CategoryPhishing includes abuse involving phishing websites or emails.
	CategoryPhishing
	// CategoryFraudVOIP includes abuse involving spam/scam calls from VoIP numbers.
	CategoryFraudVOIP
	// CategoryOpenProxy describes IPs acting as open proxies, relays or Tor exit nodes.
	CategoryOpenProxy
	// CategoryWebSpam includes abuse involving comment/forum spam, HTTP referer spam or other CMS-related spam.
	CategoryWebSpam
	// CategoryEmailSpam includes abuse involving spam email content, infected attachments and phishing.
	CategoryEmailSpam
	// CategoryBlogSpam includes abuse involving comment spam on CMS blogs.
	CategoryBlogSpam
	// CategoryVPNIP is a conjunctive category for VPN servers.
	CategoryVPNIP
	// CategoryPortScan includes abuse involving scanning the internet for open ports/vulnerable devices.
	CategoryPortScan
	// CategoryHacking includes abuse involving all types of unauthorised system access.
	// This should be used in combination with other categories.
	CategoryHacking
	// CategorySQLInjection includes abuse involving any form of SQL injection attempt.
	CategorySQLInjection
	// CategorySpoofing includes abuse involving spoofing email sender information.
	CategorySpoofing
	// CategoryBruteForce includes abuse involving brute-force credential attacks on a variety of protocols.
	// Examples include SSH, FTP, STMP, RDP as well as webpage logins.
	CategoryBruteForce
	// CategoryBadWebBot includes abuse involving website scraping which doesn't honour robots.txt.
	// Excessive requests and spoofed user agents can also be reported under this category.
	CategoryBadWebBot
	// CategoryExploitedHost includes abuse in which the host is likely infected with malware,
	// and is being used for other attacks/hosting malicious content.
	CategoryExploitedHost
	// CategoryWebAppAttack includes abuse involving attempts to probe/exploit web applications.
	// Examples include, CMS' such as WordPress, Drupal, phpMyAdmin, etc.
	CategoryWebAppAttack
	// CategorySSH includes abuse of Secure Shell (SSH).
	//Use this category in combination with more specific categories.
	CategorySSH
	// CategoryIoTTargeted includes abuse targeting IoT devices.
	// Include information about device type in report comments.
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

		if err == nil {
			requestError.Raw = string(body)

			errorResponse := ErrorResponse{}

			err = json.Unmarshal(body, &errorResponse)

			if err == nil {
				details := make([]string, len(errorResponse.Errors))

				for _, e := range errorResponse.Errors {
					details = append(details, e.Detail)
				}

				requestError.Details = details
			}
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
