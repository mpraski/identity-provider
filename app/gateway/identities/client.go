package identities

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
		baseURL string
		client  *http.Client
	}

	Identity struct {
		ID uuid.UUID `json:"id"`
	}

	Traits struct {
		Email string `json:"email"`
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

func (c *Client) Authenticate(ctx context.Context, email, password string) (*Identity, error) {
	var (
		b = new(bytes.Buffer)
		s = AuthenticateRequest{
			Email:    email,
			Password: password,
		}
	)

	if err := json.NewEncoder(b).Encode(s); err != nil {
		return nil, fmt.Errorf("failed to encode identity request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path.Join(c.baseURL, "/authenticate/password"), b)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make identity request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"request failed with status: %d %s",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
		)
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("failed to decode identity response: %w", err)
	}

	return &identity, nil
}
