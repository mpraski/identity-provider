package provider

import (
	"context"

	"github.com/mpraski/identity-provider/app/gateway/identities"
)

type (
	Subject = string

	Credentials = map[string]string

	Provider interface {
		Provide(context.Context, Credentials) (Subject, error)
	}

	Providers map[string]Provider
)

const Identity = "identity"

func MakeProviders(client *identities.Client) Providers {
	return Providers{Identity: NewAccountProvider(client)}
}
