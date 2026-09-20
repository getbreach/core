//go:build !darwin || ios

package dashboard

import "context"

type resourceSampler struct{}

func (*resourceSampler) sample(context.Context) resources {
	r := runtimeResources()
	r.Error = "Host CPU/RAM metrics are currently available on macOS."
	return r
}
