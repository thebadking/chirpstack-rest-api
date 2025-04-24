// supabase/supabase_auth.go
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	supabaseUrl     = os.Getenv("SUPABASE_URL")
	supabaseAnonKey = os.Getenv("SUPABASE_ANON_KEY")
)

// Path regexes for different endpoint types
var (
	// Device endpoints
	devicePathRegex = regexp.MustCompile(`^/api/devices/([^/]+)`)

	// Gateway endpoints
	gatewayRegex      = regexp.MustCompile(`^/api/gateways/([^/]+)`)
	relayGatewayRegex = regexp.MustCompile(`^/api/gateways/relay-gateways/([^/]+)/([^/]+)`)

	// Application endpoints (divisions in our system)
	applicationRegex = regexp.MustCompile(`^/api/applications/([^/]+)`)

	// Device profile endpoints
	deviceProfileRegex = regexp.MustCompile(`^/api/device-profiles/([^/]+)`)

	// Multicast group endpoints
	multicastGroupRegex = regexp.MustCompile(`^/api/multicast-groups/([^/]+)`)

	// List endpoints that need division access validation
	divisionAccessEndpoints = []string{
		"/api/devices",
		"/api/multicast-groups",
	}

	// List endpoints that need organization/tenant access validation
	organizationAccessEndpoints = []string{
		"/api/applications",
		"/api/device-profiles",
		"/api/gateways",
	}

	// Endpoints that should be completely blocked
	blockedEndpoints = []string{
		"/api/device-profile-templates",
		"/api/tenants",
		"/api/users",
	}
)

// SupabaseAuth wraps an http.Handler and enforces authorization based on endpoint type
func SupabaseAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[SUPABASE] incoming request %s %s", r.Method, r.URL.Path)

		// 1) Check if endpoint should be blocked entirely
		if isBlockedEndpoint(r.URL.Path) {
			log.Printf("[SUPABASE] blocked endpoint: %s", r.URL.Path)
			http.Error(w, "this endpoint is not available", http.StatusForbidden)
			return
		}

		// 2) Grab the user's JWT
		tok := r.Header.Get("Authorization")
		if !strings.HasPrefix(tok, "Bearer ") {
			log.Printf("[SUPABASE] missing token")
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		jwt := strings.TrimPrefix(tok, "Bearer ")

		// 3) Determine the endpoint type and validate accordingly
		valid, err := validateAccess(r, jwt)
		if err != nil {
			log.Printf("[SUPABASE] access validation error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !valid {
			log.Printf("[SUPABASE] access denied for request to: %s", r.URL.Path)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		// 4) Scrub user JWT and inject ChirpStack key
		r.Header.Del("Authorization")
		r.Header.Set("Grpc-Metadata-Authorization", "Bearer "+os.Getenv("CHIRPSTACK_API_KEY"))

		// 5) Call the real handler
		next.ServeHTTP(w, r)
	})
}

// Helper function to check if a path is in the blocked list
func isBlockedEndpoint(path string) bool {
	for _, blockedPath := range blockedEndpoints {
		if strings.HasPrefix(path, blockedPath) {
			return true
		}
	}
	return false
}

// Helper function to check if a path matches any in the endpoint list
func isEndpointMatch(path string, endpoints []string) bool {
	for _, endpoint := range endpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	return false
}

// validateAccess checks if the user has access for the given request
func validateAccess(r *http.Request, jwt string) (bool, error) {
	path := r.URL.Path

	// Division access check endpoints
	if isEndpointMatch(path, divisionAccessEndpoints) {
		divisionID, err := extractDivisionID(r)
		if err != nil {
			return false, err
		}

		if divisionID == "" {
			return false, errors.New("could not determine division ID")
		}

		return checkDivisionAccess(divisionID, jwt)
	}

	// Organization/tenant access check endpoints
	if isEndpointMatch(path, organizationAccessEndpoints) {
		organizationID, err := extractOrganizationID(r)
		if err != nil {
			return false, err
		}

		if organizationID == "" {
			return false, errors.New("could not determine organization ID")
		}

		return checkOrganizationAccess(organizationID, jwt)
	}

	// Default: deny access to unrecognized endpoints
	return false, fmt.Errorf("unrecognized endpoint pattern: %s", path)
}

// extractDivisionID extracts the division/application ID from the request
func extractDivisionID(r *http.Request) (string, error) {
	path := r.URL.Path

	// For device endpoints
	if matches := devicePathRegex.FindStringSubmatch(path); matches != nil {
		// For device API, we need to get the division ID from the device details
		devEUI := matches[1]
		log.Printf("[SUPABASE] extracted device EUI from path: %s", devEUI)

		// For a device, we need to make an RPC call to get its division ID
		return getDeviceDivisionID(devEUI, getAuthToken(r))
	}

	// For multicast group endpoints
	if matches := multicastGroupRegex.FindStringSubmatch(path); matches != nil {
		id := matches[1]
		log.Printf("[SUPABASE] extracted multicast group ID from path: %s", id)

		// For multicast API, we need to get the application ID (our division ID)
		// from the request body or additional API call for existing groups
		if r.Method == http.MethodPost {
			// Reading & saving body for creation
			body, err := readBody(r)
			if err != nil {
				return "", err
			}

			var payload struct {
				MulticastGroup struct {
					ApplicationID string `json:"applicationId"`
				} `json:"multicastGroup"`
			}

			if err := json.Unmarshal(body, &payload); err != nil {
				return "", fmt.Errorf("invalid JSON: %v", err)
			}

			if payload.MulticastGroup.ApplicationID != "" {
				log.Printf("[SUPABASE] extracted application/division ID from body: %s", payload.MulticastGroup.ApplicationID)
				return payload.MulticastGroup.ApplicationID, nil
			}
		}

		// For GET we need to get the application ID from query params
		query := r.URL.Query()
		if appID := query.Get("applicationId"); appID != "" {
			log.Printf("[SUPABASE] extracted application/division ID from query: %s", appID)
			return appID, nil
		}

		// This is a complex case - we might need to do an additional API call
		return "", errors.New("unable to determine division ID for multicast group")
	}

	// Check query parameters for list endpoints
	query := r.URL.Query()
	if appID := query.Get("applicationId"); appID != "" {
		log.Printf("[SUPABASE] extracted application/division ID from query: %s", appID)
		return appID, nil
	}

	// For POST requests, try to extract from the body
	if r.Method == http.MethodPost {
		body, err := readBody(r)
		if err != nil {
			return "", err
		}

		// Try to find applicationId in various body structures
		var genericPayload map[string]interface{}
		if err := json.Unmarshal(body, &genericPayload); err != nil {
			return "", fmt.Errorf("invalid JSON: %v", err)
		}

		// Look for applicationId in common structures
		for _, key := range []string{"device", "multicastGroup"} {
			if obj, ok := genericPayload[key].(map[string]interface{}); ok {
				if appID, ok := obj["applicationId"].(string); ok && appID != "" {
					log.Printf("[SUPABASE] extracted application/division ID from body: %s", appID)
					return appID, nil
				}
			}
		}
	}

	return "", errors.New("could not determine division ID from request")
}

// extractOrganizationID extracts the organization/tenant ID from the request
func extractOrganizationID(r *http.Request) (string, error) {
	path := r.URL.Path

	// For application endpoints (our divisions)
	if matches := applicationRegex.FindStringSubmatch(path); matches != nil {
		// The application ID is our division ID - we need to get the tenant ID
		divisionID := matches[1]
		log.Printf("[SUPABASE] extracted application/division ID from path: %s", divisionID)

		// For our application, we can get the organization ID from query or hardcode
		// a placeholder value since we're doing division access check
		return "placeholder", nil
	}

	// For device profile endpoints
	if matches := deviceProfileRegex.FindStringSubmatch(path); matches != nil {
		id := matches[1]
		log.Printf("[SUPABASE] extracted device profile ID from path: %s", id)

		// For GET requests, we need to check tenant_id
		// But in this case, we can just use the division check
		return "placeholder", nil
	}

	// For gateway endpoints
	if matches := gatewayRegex.FindStringSubmatch(path); matches != nil {
		id := matches[1]
		log.Printf("[SUPABASE] extracted gateway ID from path: %s", id)

		// For gateway, check tenant ID
		return "placeholder", nil
	}

	// For relay gateway endpoints
	if matches := relayGatewayRegex.FindStringSubmatch(path); matches != nil {
		tenantID := matches[1]
		log.Printf("[SUPABASE] extracted tenant ID from path: %s", tenantID)
		return tenantID, nil
	}

	// Check query parameters for list endpoints
	query := r.URL.Query()
	if tenantID := query.Get("tenantId"); tenantID != "" {
		log.Printf("[SUPABASE] extracted tenant ID from query: %s", tenantID)
		return tenantID, nil
	}

	// For POST requests, try to extract from the body
	if r.Method == http.MethodPost {
		body, err := readBody(r)
		if err != nil {
			return "", err
		}

		// Try to find tenantId in various body structures
		var genericPayload map[string]interface{}
		if err := json.Unmarshal(body, &genericPayload); err != nil {
			return "", fmt.Errorf("invalid JSON: %v", err)
		}

		// Look for tenantId in common structures
		for _, key := range []string{"gateway", "deviceProfile", "application"} {
			if obj, ok := genericPayload[key].(map[string]interface{}); ok {
				if tenantID, ok := obj["tenantId"].(string); ok && tenantID != "" {
					log.Printf("[SUPABASE] extracted tenant ID from body: %s", tenantID)
					return tenantID, nil
				}
			}
		}
	}

	return "", errors.New("could not determine organization ID from request")
}

// Helper to get the auth token from request
func getAuthToken(r *http.Request) string {
	tok := r.Header.Get("Authorization")
	return strings.TrimPrefix(tok, "Bearer ")
}

// Helper to read and reset request body
func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	// Reset body for downstream handlers
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

// getDeviceDivisionID makes an RPC call to get a device's division ID
func getDeviceDivisionID(devEUI string, jwt string) (string, error) {
	// Use the get_device_details RPC to get information including the application_id
	payload, _ := json.Marshal(map[string]string{
		"p_dev_eui": devEUI,
	})

	req, _ := http.NewRequestWithContext(context.Background(),
		"POST",
		supabaseUrl+"/rest/v1/rpc/get_device_details",
		bytes.NewBuffer(payload),
	)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("apikey", supabaseAnonKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get device details, status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Device struct {
			ApplicationID string `json:"application_id"`
		} `json:"device"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if result.Device.ApplicationID == "" {
		return "", errors.New("division ID not found in device details")
	}

	return result.Device.ApplicationID, nil
}

// Check division access using the user_division_access RPC
func checkDivisionAccess(divisionID string, jwt string) (bool, error) {
	payload, _ := json.Marshal(map[string]string{
		"p_division_id": divisionID,
	})

	req, _ := http.NewRequestWithContext(context.Background(),
		"POST",
		supabaseUrl+"/rest/v1/rpc/get_user_division_access",
		bytes.NewBuffer(payload),
	)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("apikey", supabaseAnonKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// Check organization access using the user_organization_access RPC
func checkOrganizationAccess(organizationID string, jwt string) (bool, error) {
	payload, _ := json.Marshal(map[string]string{
		"p_organization_id": organizationID,
	})

	req, _ := http.NewRequestWithContext(context.Background(),
		"POST",
		supabaseUrl+"/rest/v1/rpc/get_user_organization_access",
		bytes.NewBuffer(payload),
	)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("apikey", supabaseAnonKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
