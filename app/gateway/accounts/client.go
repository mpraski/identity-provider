package accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/google/uuid"
)

type (
	Client struct {
		client  *http.Client
		baseURL string
	}

	Account struct {
		ID        uuid.UUID `json:"id"`
		Email     string    `json:"email"`
		FirstName string    `json:"first_name"`
		LastName  string    `json:"last_name"`
		State     string    `json:"state"`
		Roles     []string  `json:"roles"`
		Active    bool      `json:"active"`
	}

	AuthenticateRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
)

const timeout = 15 * time.Second

func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) Authenticate(ctx context.Context, email, password string) (*Account, error) {
	var (
		b = new(bytes.Buffer)
		s = AuthenticateRequest{
			Email:    email,
			Password: password,
		}
	)

	if err := json.NewEncoder(b).Encode(s); err != nil {
		return nil, fmt.Errorf("failed to encode account request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path.Join(c.baseURL, "/authenticate"), b)
	if err != nil {
		return nil, fmt.Errorf("failed to create account request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make account request: %w", err)
	}

	defer resp.Body.Close()

	var account Account
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("failed to decode account response: %w", err)
	}

	return &account, nil
}
