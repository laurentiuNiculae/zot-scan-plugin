package main

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"zotregistry.io/zot/pkg/plugins/scan"
)

func ConvertToRPCScanReport(report report.Report) *scan.ScanReport {

	return &scan.ScanReport{
		Image: &scan.Image{
			Name: report.ArtifactName,
		},
		Scanner: &scan.Scanner{
			Name:   "Trivy Cve Scanner",
			Vendor: "Aquasecurity",
		},
		Vulnerabilities: ConvertResultsToRPCVulns(report.Results),
	}
}

func ConvertResultsToRPCVulns(results report.Results) []*scan.ScanVulnerability {
	var vulnerabilities []types.DetectedVulnerability

	for i := range results {
		vulnerabilities = append(vulnerabilities, results[i].Vulnerabilities...)
	}

	var rpcVulns = make([]*scan.ScanVulnerability, len(vulnerabilities))

	for i, vuln := range vulnerabilities {
		rpcVulns[i] = &scan.ScanVulnerability{
			VulnerabilityId: vuln.VulnerabilityID,
			Pkg:             vuln.PkgName,
			Version:         vuln.InstalledVersion,
			FixedVersion:    vuln.FixedVersion,
			Title:           vuln.Title,
			Severity:        toSeverity(vuln.Severity),
			Description:     vuln.Description,
			References:      toLinks(vuln.PrimaryURL, vuln.References),
			Layer: &scan.Layer{
				Digest: vuln.Layer.Digest,
				DiffId: vuln.Layer.DiffID,
			},
			Cvss:   toCVSS(vuln.CVSS),
			CweIds: vuln.CweIDs,
		}
	}
	return rpcVulns
}

func toSeverity(s string) scan.Severity {
	return scan.Severity(scan.Severity_value[s])
}

func toLinks(primary string, refferences []string) []string {
	return append(refferences, primary)
}

func toCVSS(vulnCVSS dbTypes.VendorCVSS) map[string]*scan.CVSS {
	scanCvss := make(map[string]*scan.CVSS)

	for k, v := range vulnCVSS {
		scanCvss[k] = &scan.CVSS{
			V2Vector: v.V2Vector,
			V3Vector: v.V3Vector,
			V2Score:  v.V2Score,
			V3Score:  v.V3Score,
		}
	}

	return scanCvss
}
