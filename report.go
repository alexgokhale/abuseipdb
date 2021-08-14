package abuseipdb

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
)

// ReportResponse represents the AbuseIPDB API response when an IP address has been reported for abuse.
type ReportResponse struct {
	Data struct {
		IpAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	} `json:"data"`
}

// BulkReportResponse represents the AbuseIPDB API response when multiple IP addresses are reported for abuse in CSV format.
type BulkReportResponse struct {
	Data struct {
		SavedReports   int `json:"savedReports"`
		InvalidReports []struct {
			Error     string `json:"error"`
			Input     string `json:"input"`
			RowNumber int    `json:"rowNumber"`
		} `json:"invalidReports"`
	} `json:"data"`
}

type reportConfig struct {
	comment string
}

var defaultReportConfig = reportConfig{
	comment: "",
}

// ReportOption sets an optional parameter for calls to the Report endpoint.
type ReportOption func(*reportConfig)

// Comment returns a ReportOption that sets the comment for a report.
// This field should be used for any additional information to be included with the report,
// including server logs, timestamps, packet samples, etc.
func Comment(content string) ReportOption {
	return func(config *reportConfig) {
		config.comment = content
	}
}

// Report will submit a report for the IP provided.
func (c *Client) Report(ip string, categories []Category, options ...ReportOption) (*ReportResponse, error) {
	config := defaultReportConfig

	for _, option := range options {
		option(&config)
	}

	values := url.Values{
		"ip":         {ip},
		"categories": {buildCategoryString(categories)},
	}

	if config.comment != "" {
		values.Set("comment", config.comment)
	}

	res, err := c.makeRequest("POST", "/report", RequestOptions{
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: []byte(values.Encode()),
	})

	if err != nil {
		return nil, err
	}

	responseBody, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	reportResponse := ReportResponse{}

	err = json.Unmarshal(responseBody, &reportResponse)

	if err != nil {
		return nil, err
	}

	return &reportResponse, nil
}

// BulkReport takes a CSV file containing multiple IPs to report in one go.
func (c *Client) BulkReport(filePath string) (*BulkReportResponse, error) {
	file, err := os.Open(filePath)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	filePart, err := writer.CreateFormFile("csv", filepath.Base(filePath))

	if err != nil {
		return nil, err
	}

	_, err = io.Copy(filePart, file)

	if err != nil {
		return nil, err
	}

	err = writer.Close()

	if err != nil {
		return nil, err
	}

	res, err := c.makeRequest("POST", "/bulk-report", RequestOptions{
		Headers: map[string]string{
			"Content-Type": writer.FormDataContentType(),
		},
		Body: body.Bytes(),
	})

	if err != nil {
		return nil, err
	}

	responseBody, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	bulkReportResponse := BulkReportResponse{}

	err = json.Unmarshal(responseBody, &bulkReportResponse)

	if err != nil {
		return nil, err
	}

	return &bulkReportResponse, nil
}
