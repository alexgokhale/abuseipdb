package abuseipdb

import (
	"os"
	"testing"
)

func TestComment(t *testing.T) {
	rc := reportConfig{
		comment: "foo",
	}

	ro := Comment("bar")
	ro(&rc)

	if rc.comment != "bar" {
		t.Errorf(`Comment: expected "bar", got "%s"`, rc.comment)
	}
}

func TestClient_Report(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	reportResponse, err := client.Report("172.16.0.5", []Category{CategoryDDoSAttack}, Comment("Test Request for https://gitlab.com/honour/abuseipdb"))

	if err != nil {
		t.Logf("Report: expected err to be nil, got %v", err)
		t.FailNow()
	}

	if reportResponse.Data.IpAddress != "172.16.0.5" {
		t.Errorf(`Report: expected ip address to be "172.16.0.5", got "%s"`, reportResponse.Data.IpAddress)
	}
}

func TestClient_BulkReport(t *testing.T) {
	apiKey := os.Getenv("ABUSEIPDB_TOKEN")

	if apiKey == "" {
		t.Log("abuseipdb: expected value for environment variable ABUSEIPDB_TOKEN, but found none")
		t.FailNow()
	}

	client := NewClient(apiKey)

	bulkReportResponse, err := client.BulkReport("testdata/bulk.csv")

	if err != nil {
		t.Logf("BulkReport: expected err to be nil, got %v", err)
		t.FailNow()
	}

	if bulkReportResponse.Data.SavedReports != 2 {
		t.Logf("BulkReport: expected saved reports to be 2, got %d", bulkReportResponse.Data.SavedReports)
		for _, invalidReport := range bulkReportResponse.Data.InvalidReports {
			t.Logf("Invalid Report: %s", invalidReport.Error)
		}
		t.FailNow()
	}
}
