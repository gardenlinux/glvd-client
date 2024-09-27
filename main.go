package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
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
	Status  string
	Source  string
}

func buildDpkgStructure(dpkgStatusFileContents string) []dpkgPackage {
	var packages []dpkgPackage

	lines := strings.Split(dpkgStatusFileContents, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "Package: ") {
			pkg := strings.Replace(line, "Package: ", "", 1)
			packages = append(packages, dpkgPackage{Package: pkg})
		}

		if strings.HasPrefix(line, "Status: ") {
			packages[len(packages)-1].Status = strings.Replace(line, "Status: ", "", 1)
		}

		if strings.HasPrefix(line, "Source: ") {
			sourcePackageNameWithPotentialVersion := strings.Replace(line, "Source: ", "", 1)
			sourcePackageName := removePotentialVersionSuffix(sourcePackageNameWithPotentialVersion)
			packages[len(packages)-1].Source = sourcePackageName
		}
	}

	return packages
}

func removePotentialVersionSuffix(input string) string {
	return strings.Split(input, " ")[0]
}

func getDpkgSourcePackages(dpkgStatusFilePath string) []string {
	dat, err := os.ReadFile(dpkgStatusFilePath)
	if err != nil {
		log.Fatal(err)
	}

	packages := buildDpkgStructure(string(dat))

	var pkgs []string

	for _, pkg := range packages {
		if pkg.Status == "install ok installed" {
			if len(pkg.Source) > 0 {
				pkgs = append(pkgs, pkg.Source)
			} else {
				pkgs = append(pkgs, pkg.Package)
			}
		}
	}

	// De-duplicate entries
	slices.Sort(pkgs)
	return slices.Compact(pkgs)
}

type payload struct {
	PackageNames []string `json:"packageNames"`
}

func getCvesForPackageList(dpkgSourcePackages []string, gardenLinuxVersion string) []sourcePackageCve {
	client := &http.Client{}
	requestPayload, _ := json.Marshal(payload{PackageNames: dpkgSourcePackages})
	req, err := http.NewRequest("PUT", "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/"+gardenLinuxVersion+"/packages?sortBy=cveId&sortOrder=ASC", bytes.NewBuffer(requestPayload))
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

	var results []sourcePackageCve
	err = json.Unmarshal(bodyText, &results)
	if err != nil {
		log.Fatal(err)
	}
	return results
}

func readGardenLinuxVersion(osReleaseFilePath string) string {
	dat, err := os.ReadFile(osReleaseFilePath)
	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(dat), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GARDENLINUX_VERSION=") {
			return strings.Replace(line, "GARDENLINUX_VERSION=", "", 1)
		}
	}
	log.Fatal("Could not parse os-release, failed to identify Garden Linux version.")
	return ""
}

func printCves(cves []sourcePackageCve, jsonOutput bool) {
	if jsonOutput {
		output, err := json.MarshalIndent(cves, " ", " ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(output))
	} else {
		for _, cve := range cves {
			fmt.Printf("%-18s %4.1f %-46s %-20s %-20s\n", cve.CveId, cve.BaseScore, cve.VectorString, cve.SourcePackageName, cve.SourcePackageVersion)
		}
	}
}

func main() {
	jsonOutput := strings.ToLower(os.Getenv("GLVD_CLIENT_JSON_OUTPUT")) == "true"

	devMode := os.Getenv("GLVD_CLIENT_DEV_MODE")
	var dpkgStatusFilePath string
	var etcOsReleaseFilePath string

	if len(devMode) > 0 {
		println("Running in dev mode")
		dpkgStatusFilePath = "test-data/var-lib-dpkg-status.txt"
		etcOsReleaseFilePath = "test-data/etc-os-release.txt"
	} else {
		dpkgStatusFilePath = "/var/lib/dpkg/status"
		etcOsReleaseFilePath = "/etc/os-release"
	}

	args := os.Args[1:]
	programName := os.Args[0]

	if len(args) == 0 {
		fmt.Printf("Usage: %s <command> <args>\nCommands: what-if, check, executive-summary\nArgs: List of source packages for command what-if\n", programName)
		os.Exit(0)
	}

	if len(args) >= 1 {
		command := args[0]

		gardenLinuxVersion := readGardenLinuxVersion(etcOsReleaseFilePath)
		var cves []sourcePackageCve

		switch command {
		case "what-if":
			packagesToCheck := args[1:]
			cves = getCvesForPackageList(packagesToCheck, gardenLinuxVersion)
			printCves(cves, jsonOutput)
		case "check":
			dpkgSourcePackages := getDpkgSourcePackages(dpkgStatusFilePath)
			cves = getCvesForPackageList(dpkgSourcePackages, gardenLinuxVersion)
			printCves(cves, jsonOutput)
		case "executive-summary":
			dpkgSourcePackages := getDpkgSourcePackages(dpkgStatusFilePath)
			cves = getCvesForPackageList(dpkgSourcePackages, gardenLinuxVersion)
			fmt.Printf("This machine has %d potential security issues\nRun `%s check` to get the full list\n", len(cves), programName)
		}

	}
}
