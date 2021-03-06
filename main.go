package main

import (
	"context"
	"embed"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/mpraski/identity-provider/app/gateway/identities"
	"github.com/mpraski/identity-provider/app/provider"
	"github.com/mpraski/identity-provider/app/service"
	"github.com/mpraski/identity-provider/app/template"
	hydra "github.com/ory/hydra-client-go/client"
	log "github.com/sirupsen/logrus"
)

type input struct {
	Server struct {
		Address         string        `default:":8080"`
		ReadTimeout     time.Duration `split_words:"true" default:"5s"`
		WriteTimeout    time.Duration `split_words:"true" default:"10s"`
		IdleTimeout     time.Duration `split_words:"true" default:"15s"`
		ShutdownTimeout time.Duration `split_words:"true" default:"30s"`
	}
	Hydra struct {
		BaseURL string `required:"true" split_words:"true"`
	}
	Observability struct {
		Address string `default:":9090"`
	}
	IdentityManager struct {
		BaseURL string `required:"true" split_words:"true"`
	} `split_words:"true"`
}

//go:embed templates/*.tmpl
var embeds embed.FS

var (
	// Health check
	healthy int32
	app     = "identity_provider"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.WarnLevel)
	log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	var i input
	if err := envconfig.Process(app, &i); err != nil {
		log.Fatalf("failed to load input: %v", err)
	}

	hydraBaseURL, err := url.Parse(i.Hydra.BaseURL)
	if err != nil {
		log.Fatalf("failed to parse hydra base URL: %v", err)
	}

	var (
		done     = make(chan bool)
		quit     = make(chan os.Signal, 1)
		renderer = template.NewRenderer(embeds)
		identity = provider.NewIdentityProvider(identities.New(i.IdentityManager.BaseURL))
		router   = service.New(renderer, identity, hydra.NewHTTPClientWithConfig(nil,
			&hydra.TransportConfig{
				Schemes:  []string{hydraBaseURL.Scheme},
				Host:     hydraBaseURL.Host,
				BasePath: hydraBaseURL.Path,
			},
		).Admin).Router()
	)

	observability := newObservabilityServer(&i)

	go func() {
		log.Println("starting observability server at", i.Observability.Address)

		if errs := observability.ListenAndServe(); errs != nil && errs != http.ErrServerClosed {
			log.Fatalf("failed to start observability server on %s: %v", i.Observability.Address, errs)
		}
	}()

	main := &http.Server{
		Addr:         i.Server.Address,
		ReadTimeout:  i.Server.ReadTimeout,
		WriteTimeout: i.Server.WriteTimeout,
		IdleTimeout:  i.Server.IdleTimeout,
		Handler:      router,
	}

	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		log.Println("server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), i.Server.ShutdownTimeout)
		defer cancel()

		main.SetKeepAlivesEnabled(false)
		observability.SetKeepAlivesEnabled(false)

		if err := main.Shutdown(ctx); err != nil {
			log.Fatalf("failed to gracefully shutdown the server: %v", err)
		}

		if err := observability.Shutdown(ctx); err != nil {
			log.Fatalf("failed to gracefully shutdown observability server: %v", err)
		}

		close(done)
	}()

	log.Println("server is ready to handle requests at", i.Server.Address)
	atomic.StoreInt32(&healthy, 1)

	if err := main.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to listen on %s: %v", i.Server.Address, err)
	}

	<-done
	log.Println("server stopped")
}

func healthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func newObservabilityServer(cfg *input) *http.Server {
	router := http.NewServeMux()
	router.Handle("/healthz", healthz())

	return &http.Server{
		Addr:         cfg.Observability.Address,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		Handler:      router,
	}
}
