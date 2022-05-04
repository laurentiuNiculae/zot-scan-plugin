package main

import (
	"context"
	"fmt"
	"path"

	"zotregistry.io/zot/pkg/plugins/scan"
)

type ScanServer struct {
	scan.UnimplementedScanServer
}

func (ss ScanServer) Scan(ctx context.Context, request *scan.ScanRequest) (*scan.ScanResponse, error) {
	image := request.GetImage()
	addr := request.GetRegistry().Url

	// this would be simmilar to calling: > trivy image [flags] localhost:8080/image
	// the library will know how to use the zot oci api and scan the image required.
	trivyCtx := NewTrivyContextArgs("/tmp/zot/trivy-cash", addr, image)

	fmt.Printf("Scaning for image: %v\n", path.Join(addr, image))
	report, err := ScanImage(trivyCtx.Ctx)
	return &scan.ScanResponse{
		Report: ConvertToRPCScanReport(report),
	}, err
}
