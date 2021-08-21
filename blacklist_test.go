package abuseipdb

import (
	"os"
	"testing"
)

func TestLimit(t *testing.T) {
	bc := blacklistConfig{
		limit: 500,
	}

	bo := Limit(100)
	bo(&bc)

	if bc.limit != 100 {
		t.Errorf(`Limit: expected 100, got %d`, bc.limit)
	}
}

func TestConfidenceMinimum(t *testing.T) {
	bc := blacklistConfig{
		confidenceMinimum: 75,
	}

	bo := ConfidenceMinimum(-1)
	bo(&bc)

	if bc.confidenceMinimum != -1 {
		t.Errorf(`ConfidenceMinimum: expected -1, got %d`, bc.confidenceMinimum)
	}
}

func TestClient_Blacklist(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	_, err := client.Blacklist(ConfidenceMinimum(10))

	if err == nil {
		t.Logf("Blacklist: expected error to be non-nil, got %v", err)
		t.FailNow()
	} else if err.Error() != "confidenceMinimum must be between 25 and 100 as a premium user, or -1 otherwise" {
		t.Logf(`Blacklist: expected error to be "confidenceMinimum must be between 25 and 100 as a premium user, or -1 otherwise", got "%v"`, err)
		t.FailNow()
	}

	_, err = client.Blacklist(Limit(0))

	if err == nil {
		t.Logf("Blacklist: expected error to be non-nil, got %v", err)
		t.FailNow()
	} else if err.Error() != "limit must be greater than 1" {
		t.Logf(`Blacklist: expected error to be "limit must be greater than 1", got "%v"`, err)
		t.FailNow()
	}

	blacklistResponse, err := client.Blacklist()

	if err != nil {
		t.Logf("Blacklist: expected err to be nil, got %v", err)
		t.FailNow()
	}

	if len(blacklistResponse.Data) != 10000 {
		t.Errorf("Blacklist: expected number of IPs to be 10000, got %d", len(blacklistResponse.Data))
	}
}
