package abuseipdb

import (
	"os"
	"testing"
)

func TestVerbose(t *testing.T) {
	cc := checkConfig{
		verbose: true,
	}

	co := Verbose(false)
	co(&cc)

	if cc.verbose != false {
		t.Errorf(`Verbose: expected false, got %t`, cc.verbose)
	}
}

func TestMaxAgeInDays(t *testing.T) {
	cc := checkConfig{
		maxAgeInDays: 180,
	}

	co := MaxAgeInDays(90)
	co(&cc)

	if cc.maxAgeInDays != 90 {
		t.Errorf(`MaxAgeInDays: expected 90, got %d`, cc.maxAgeInDays)
	}
}

func TestClient_Check(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	_, err := client.Check("1.1.1.1", MaxAgeInDays(0))

	if err == nil {
		t.Logf("Check: expected error to be non-nil, got %v", err)
		t.FailNow()
	} else if err.Error() != "maxAgeInDays must be between 1 and 365" {
		t.Logf(`Check: expected error to be "maxAgeInDays must be between 1 and 365", got "%v"`, err)
		t.FailNow()
	}

	checkResponse, err := client.Check("1.1.1.1", Verbose(true))

	if err != nil {
		t.Logf("Check: expected err to be nil, got %v", err)
		t.FailNow()
	}

	if checkResponse.Data.IPAddress != "1.1.1.1" {
		t.Errorf(`Check: expected IP address to be "1.1.1.1", got "%s"`, checkResponse.Data.IPAddress)
	}
}

func TestClient_CheckBlock(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	_, err := client.CheckBlock("1.1.1.0/24", MaxAgeInDays(0))

	if err == nil {
		t.Logf("CheckBlock: expected error to be non-nil, got %v", err)
		t.FailNow()
	} else if err.Error() != "maxAgeInDays must be between 1 and 365" {
		t.Logf(`CheckBlock: expected error to be "maxAgeInDays must be between 1 and 365", got "%v"`, err)
		t.FailNow()
	}

	checkBlockResponse, err := client.CheckBlock("1.1.1.0/24", Verbose(true))

	if err != nil {
		t.Logf("CheckBlock: expected err to be nil, got %v", err)
		t.FailNow()
	}

	if checkBlockResponse.Data.NumPossibleHosts != 254 {
		t.Errorf("CheckBlock: expected number of possible hosts to be 254, got %d", checkBlockResponse.Data.NumPossibleHosts)
	}
}
