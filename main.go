package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	gw "github.com/thebadking/chirpstack-rest-api/api"
	supa "github.com/thebadking/chirpstack-rest-api/supabase"
)

var (
	server = flag.String("server", envString("SERVER", "localhost:8080"), "ChirpStack API endpoint")
	bind   = flag.String("bind", envString("BIND", "0.0.0.0:8090"), "REST API server bind")
	insec  = flag.Bool("insecure", envBool("INSECURE", false), "Use insecure (non‑TLS) connection to server")
	cors   = flag.String("cors", envString("CORS", "0.0.0.0"), "Set AllowedOrigins Header for CORS")
)

func envString(key, defVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defVal
}

func envBool(key string, defVal bool) bool {
	if _, ok := os.LookupEnv(key); ok {
		return true
	}
	return defVal
}

// wrapWithLog returns an http.Handler that logs each request before
// delegating to the real handler.
func wrapWithLog(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s", name, r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Common gRPC dial options
	var opts []grpc.DialOption
	if *insec {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	// Create a unified mux for all API endpoints
	apiMux := runtime.NewServeMux()

	// Register all handlers - all will go through our middleware for access control

	// 1. Division-based access endpoints
	if err := gw.RegisterDeviceServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register DeviceService: %w", err)
	}
	if err := gw.RegisterMulticastGroupServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register MulticastGroupService: %w", err)
	}

	// 2. Organization/tenant-based access endpoints
	if err := gw.RegisterApplicationServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register ApplicationService: %w", err)
	}
	if err := gw.RegisterDeviceProfileServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register DeviceProfileService: %w", err)
	}
	if err := gw.RegisterGatewayServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register GatewayService: %w", err)
	}

	// 3. Endpoints that will be blocked by middleware
	if err := gw.RegisterDeviceProfileTemplateServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register DeviceProfileTemplateService: %w", err)
	}
	if err := gw.RegisterTenantServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register TenantService: %w", err)
	}
	if err := gw.RegisterUserServiceHandlerFromEndpoint(ctx, apiMux, *server, opts); err != nil {
		return fmt.Errorf("register UserService: %w", err)
	}

	// Apply Supabase auth middleware to all API endpoints
	protectedHandler := supa.SupabaseAuth(apiMux)

	// Add logging middleware
	loggedHandler := wrapWithLog("API", protectedHandler)

	// Set up router
	r := mux.NewRouter()

	// All API routes go through the middleware
	r.PathPrefix("/api/").Handler(loggedHandler)

	// UI routes
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[HEALTH] %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// CORS setup
	corsObj := handlers.AllowedOrigins([]string{*cors})
	corsMethods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	corsHeaders := handlers.AllowedHeaders([]string{"Content-Type", "Authorization"})

	log.Printf("Listening on %s (forwarding to %s, insecure=%v)", *bind, *server, *insec)
	return http.ListenAndServe(*bind, handlers.CORS(corsObj, corsMethods, corsHeaders)(r))
}

func main() {
	flag.Parse()
	log.Println("Starting ChirpStack REST API server")
	if err := run(); err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}
