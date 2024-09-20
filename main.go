package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"os"
	"slices"
)

type sourcePackageCve struct {
	CveId                string  `json:"cveId"`
	BaseScore            float32 `json:"baseScore"`
	VectorString         string  `json:"vectorString"`
	SourcePackageName    string  `json:"sourcePackageName"`
	SourcePackageVersion string  `json:"sourcePackageVersion"`
	GardenlinuxVersion   string  `json:"gardenlinuxVersion"`
	IsVulnerable         bool    `json:"isVulnerable"`
	CvePublishedDate     string  `json:"cvePublishedDate"`
}

type dpkgPackage struct {
	Package string
	Status string
	Source string
}

func getDpkgSourcePackages(dpkgStatusFilePath string) []string {
	dat, err := os.ReadFile(dpkgStatusFilePath)
	if err != nil {
		log.Fatal(err)
	}

	var packages []dpkgPackage

	lines := strings.Split(string(dat), "\n")

	for _,line := range lines {
		if strings.HasPrefix(line, "Package: ") {
			pkg := strings.Replace(line, "Package: ", "", 1)
			packages = append(packages, dpkgPackage{Package: pkg})
		}

		if strings.HasPrefix(line, "Status: ") {
			packages[len(packages) -1].Status = strings.Replace(line, "Status: ", "", 1)
		}

		if strings.HasPrefix(line, "Source: ") {
			packages[len(packages) -1].Source = strings.Replace(line, "Source: ", "", 1)
		}
	}

	var pkgs []string

	for _, pkg  := range packages {
		if len(pkg.Source) > 0 {
			pkgs = append(pkgs, `"` + strings.Split(pkg.Source, " ")[0] + `"`)
		} else {
			pkgs = append(pkgs, `"` + pkg.Package + `"`)
		}
	}

	slices.Sort(pkgs)
	return slices.Compact(pkgs)
}

func main() {

	dpkgSourcePackages := getDpkgSourcePackages("/var/lib/dpkg/status")


	client := &http.Client{}
	var data = strings.NewReader(`{"packageNames":[` + strings.Join(dpkgSourcePackages, ",") + `]}`)
	req, err := http.NewRequest("PUT", "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/1592.0/packages?sortBy=cveId&sortOrder=ASC", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Printf("%s\n", bodyText)

	var results []sourcePackageCve
	err = json.Unmarshal(bodyText, &results)

	if err != nil {
		panic(err)
	}

	fmt.Println(results)
}
