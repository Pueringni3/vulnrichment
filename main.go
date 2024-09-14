package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

const (
	zipURL    string = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"
	branchURL string = "https://github.com/cisagov/vulnrichment/tree/develop/"
)

func main() {
	bs, err := fetch(zipURL)
	if err != nil {
		panic(err)
	}

	r, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	if err != nil {
		panic(err)
	}

	pathMap := map[string]string{}
	for _, zf := range r.File {
		if !zf.FileInfo().IsDir() {
			parts := strings.SplitN(zf.Name, "/", 2)
			if len(parts) == 0 {
				continue
			}
			fileName := filepath.Base(parts[1])
			cveID := strings.TrimSuffix(fileName, ".json")
			pathMap[cveID] = branchURL + parts[1]
		}
	}
	fmt.Printf("pathmap: %v", pathMap["CVE-2024-8742"])
}

func fetch(url string) (body []byte, err error) {
	httpClient := http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch failed")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed")
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed")
	}

	return buf, nil
}
