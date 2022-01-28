package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/mpraski/identity-provider/app/gateway/accounts"
)

type AccountProvider struct {
	client *accounts.Client
}

var (
	ErrEmailMissing    = errors.New("email is missing")
	ErrPasswordMissing = errors.New("password is missing")
	ErrAccountNotFound = errors.New("account not found")
)

const (
	credEmail    = "email"
	credPassword = "password"
)

func NewAccountProvider(client *accounts.Client) *AccountProvider {
	return &AccountProvider{client: client}
}

func (p *AccountProvider) Provide(ctx context.Context, creds Credentials) (Subject, error) {
	email, ok := creds[credEmail]
	if !ok {
		return "", ErrEmailMissing
	}

	password, ok := creds[credPassword]
	if !ok {
		return "", ErrPasswordMissing
	}

	account, err := p.client.Authenticate(ctx, email, password)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	if !account.Active {
		return "", ErrAccountNotFound
	}

	return account.ID.String(), nil
}
