package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type sourcePackageCve struct {
	CveId                string `json:"cveId"`
	SourcePackageName    string `json:"sourcePackageName"`
	SourcePackageVersion string `json:"sourcePackageVersion"`
	GardenlinuxVersion   string `json:"gardenlinuxVersion"`
	IsVulnerable         bool   `json:"isVulnerable"`
	CvePublishedDate     string `json:"cvePublishedDate"`
}

func main() {
	resp, err := http.Get("https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/packages/vim")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))

	var results []sourcePackageCve
	err = json.Unmarshal(body, &results)

	if err != nil {
		panic(err)
	}

	fmt.Println(results)
}
