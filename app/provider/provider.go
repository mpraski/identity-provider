package provider

import (
	"context"
)

type (
	Provider interface {
		Provide(context.Context, Credentials) (Subject, error)
	}

	Credentials = map[string]string

	Subject = string
)
