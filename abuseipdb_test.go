package abuseipdb

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestBuildCategoryString(t *testing.T) {
	got := buildCategoryString(nil)

	if got != "" {
		t.Errorf(`buildCategoryString: expected "", got "%s"`, got)
	}

	got = buildCategoryString([]Category{})

	if got != "" {
		t.Errorf(`buildCategoryString: expected "", got "%s"`, got)
	}

	got = buildCategoryString([]Category{
		CategoryDDoSAttack,
		CategoryBruteForce,
		CategorySSH,
	})

	if got != "4,18,22" {
		t.Errorf(`buildCategoryString: expected "4,18,22", got "%s"`, got)
	}
}

func TestBuildQueryString(t *testing.T) {
	got := buildQueryString(nil)

	if got != "" {
		t.Errorf(`buildQueryString: expected "", got "%s"`, got)
	}

	got = buildQueryString(map[string]string{})

	if got != "" {
		t.Errorf(`buildQueryString: expected "", got "%s"`, got)
	}

	got = buildQueryString(map[string]string{
		"foo": "bar",
	})

	if got != "?foo=bar" {
		t.Errorf(`buildQueryString: expected "?foo=bar", got "%s"`, got)
	}

	got = buildQueryString(map[string]string{
		"apple": "banana",
		"cat":   "dog",
	})

	if got != "?apple=banana&cat=dog" && got != "?cat=dog&apple=banana" {
		t.Errorf(`buildQueryString: expected "?apple=banana&cat=dog", got "%s"`, got)
	}

	got = buildQueryString(map[string]string{
		"email": "hello@example.com",
	})

	if got != "?email=hello%40example.com" {
		t.Errorf(`buildQueryString: expected "?email=hello%%40example.com", got "%s"`, got)
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient("testing123")

	if client.APIKey != "testing123" {
		t.Errorf(`NewClient: expected API key "testing123", got "%s"`, client.APIKey)
	}

	if client.httpClient == nil {
		t.Errorf("NewClient: expected httpClient to be non-nil")
	}

	if client.httpClient.Timeout != time.Minute {
		t.Errorf("NewClient: expected httpClient timeout to be 60 seconds, got %f seconds", client.httpClient.Timeout.Seconds())
	}
}

func TestRequestError_Error(t *testing.T) {
	requestError := RequestError{
		StatusCode: 402,
		Details: []string{
			"example 1",
			"example 2",
		},
		Raw: "{\"errors\":[{\"detail\":\"example 1\",\"status\":402},{\"detail\":\"example 2\",\"status\":402}]}",
	}

	got := requestError.Error()

	if got != "abuseipdb: api request failed with status code 402\n{\"errors\":[{\"detail\":\"example 1\",\"status\":402},{\"detail\":\"example 2\",\"status\":402}]}" {
		t.Errorf(`RequestError.Error(): expected "abuseipdb: api request failed with status code 402\n{\"errors\":[{\"detail\":\"example 1\",\"status\":402},{\"detail\":\"example 2\",\"status\":402}]}", got "%s"`, got)
	}
}

func TestMakeRequest_GET(t *testing.T) {
	client := NewClient("")

	res, err := client.makeRequest("GET", "", RequestOptions{})

	if err != nil {
		t.Logf("makeRequest: expected err to be nil, got %s", err)
		t.FailNow()
	}

	if res.StatusCode != 200 {
		t.Logf("makeRequest: expected response status code to be 200, got %d", res.StatusCode)
		t.FailNow()
	}

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		t.Logf("makeRequest: an error occurred whilst reading the response body: %v", err)
		t.FailNow()
	}

	if string(body) != "AbuseIPDB APIv2 Server." {
		t.Errorf(`makeRequest: expected response body to be "AbuseIPDB APIv2 Server.", got "%s"`, string(body))
	}
}

func TestMakeRequest_POST(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	reqBody := url.Values{
		"ip":         {"172.16.0.4"},
		"categories": {"4"},
		"comment":    {"Test Request for https://gitlab.com/honour/abuseipdb"},
	}

	res, err := client.makeRequest("POST", "/report", RequestOptions{
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   fmt.Sprintf("AbuseIPDB-Go-Client/%s [Unit Tests] (+https://gitlab.com/honour/abuseipdb)", version),
		},
		Body: []byte(reqBody.Encode()),
	})

	if err != nil {
		t.Logf("makeRequest: expected err to be nil, got %s", err)
		t.FailNow()
	}

	if res.StatusCode != 200 {
		t.Logf("makeRequest: expected response status code to be 200, got %d", res.StatusCode)
		t.FailNow()
	}

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		t.Logf("makeRequest: an error occurred whilst reading the response body: %v", err)
		t.FailNow()
	}

	if string(body) != "{\"data\":{\"ipAddress\":\"172.16.0.4\",\"abuseConfidenceScore\":0}}" {
		t.Errorf(`makeRequest: expected response body to be "{"data":{"ipAddress":"172.16.0.4","abuseConfidenceScore":0}}", got "%s"`, string(body))
	}

	client = NewClient("")

	res, err = client.makeRequest("POST", "/report", RequestOptions{
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   fmt.Sprintf("AbuseIPDB-Go-Client/%s [Unit Tests] (+https://gitlab.com/honour/abuseipdb)", version),
		},
		Body: []byte(reqBody.Encode()),
	})

	if err == nil {
		t.Log("makeRequest: expected err to be non-nil")
		t.FailNow()
	}

	if requestError, ok := err.(RequestError); ok {
		if requestError.StatusCode != 401 {
			t.Logf("makeRequest: expected status code to be 401, got %d", requestError.StatusCode)
			t.FailNow()
		}
	} else {
		t.Log("makeRequest: expected err to be of type RequestError")
		t.FailNow()
	}
}
