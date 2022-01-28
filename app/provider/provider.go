package provider

import (
	"context"

	"github.com/mpraski/identity-provider/app/gateway/accounts"
)

type (
	Subject = string

	Credentials = map[string]string

	Provider interface {
		Provide(context.Context, Credentials) (Subject, error)
	}

	Providers map[string]Provider
)

const Account = "account"

func MakeProviders(client *accounts.Client) Providers {
	return Providers{Account: NewAccountProvider(client)}
}
