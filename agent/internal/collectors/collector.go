package collectors

import (
	"context"

	"microedr/pkg/model"
)

type Collector interface {
	Run(context.Context, chan<- model.Event) error
}

