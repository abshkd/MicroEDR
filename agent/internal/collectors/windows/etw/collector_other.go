//go:build !windows

package etw

import (
	"context"

	"microedr/pkg/model"
)

type Collector struct{}

func New(string) *Collector {
	return &Collector{}
}

func (c *Collector) Run(ctx context.Context, out chan<- model.Event) error {
	<-ctx.Done()
	return nil
}

