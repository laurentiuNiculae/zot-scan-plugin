package main

import (
	"flag"
	"path"
	"strings"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
)

type CveTrivyController struct {
	DefaultCveConfig *TrivyCtx
	SubCveConfig     map[string]*TrivyCtx
}

type TrivyCtx struct {
	Input string
	Ctx   *cli.Context
}

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string) error {
	return operation.DownloadDB("dev", dbDir, false, false, false)
}

type CveInfo struct {
	CveTrivyController CveTrivyController
}

// NewTrivyContext set some trivy configuration value and return a context.
func NewTrivyContextArgs(dir, remote, image string) *TrivyCtx {
	trivyCtx := &TrivyCtx{}

	app := &cli.App{}

	flagSet := &flag.FlagSet{}

	var cacheDir string

	flagSet.StringVar(&cacheDir, "cache-dir", dir, "")

	var vuln string

	flagSet.StringVar(&vuln, "vuln-type", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "")

	var severity string

	flagSet.StringVar(&severity, "severity", strings.Join(dbTypes.SeverityNames, ","), "")

	var securityCheck string

	flagSet.StringVar(&securityCheck, "security-checks", types.SecurityCheckVulnerability, "")

	var reportFormat string

	flagSet.StringVar(&reportFormat, "format", "table", "")

	flagSet.Parse([]string{path.Join(remote, image)})

	ctx := cli.NewContext(app, flagSet, nil)

	trivyCtx.Ctx = ctx
	return trivyCtx
}

func ScanImage(ctx *cli.Context) (report.Report, error) {
	return artifact.TrivyImageRun(ctx)
}
