package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
)

type LoadSwaggerFunc func() (*openapi3.T, error)

type OpenAPIValidationOptions struct {
	BasePath string
}

func OpenAPIValidation(loadSwagger LoadSwaggerFunc) (func(http.Handler) http.Handler, error) {
	return OpenAPIValidationWithOptions(loadSwagger, OpenAPIValidationOptions{})
}

func OpenAPIValidationWithOptions(loadSwagger LoadSwaggerFunc, opts OpenAPIValidationOptions) (func(http.Handler) http.Handler, error) {
	swagger, err := loadSwagger()
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded openapi spec: %w", err)
	}

	swagger.Servers = nil

	router, err := legacyrouter.NewRouter(swagger)
	if err != nil {
		return nil, fmt.Errorf("failed to create openapi router: %w", err)
	}

	basePath := normalizeBasePath(opts.BasePath)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			request := requestForValidation(r, basePath)

			if statusCode, err := validateRequest(request, router); err != nil {
				writeValidationError(w, statusCode, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func normalizeBasePath(raw string) string {
	basePath := strings.TrimSpace(raw)
	if basePath == "" || basePath == "/" {
		return ""
	}

	return "/" + strings.Trim(basePath, "/")
}

func requestForValidation(r *http.Request, basePath string) *http.Request {
	if basePath == "" {
		return r
	}

	clonedRequest := r.Clone(r.Context())
	clonedURL := *r.URL
	clonedRequest.URL = &clonedURL
	clonedRequest.RequestURI = stripBasePath(basePath, r.RequestURI)
	clonedRequest.URL.Path = stripBasePath(basePath, r.URL.Path)

	return clonedRequest
}

func stripBasePath(basePath, value string) string {
	if value == "" || basePath == "" {
		return value
	}

	if value == basePath {
		return "/"
	}

	if strings.HasPrefix(value, basePath+"/") {
		return strings.TrimPrefix(value, basePath)
	}

	return value
}

func validateRequest(r *http.Request, router routers.Router) (int, error) {
	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		return http.StatusNotFound, err
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	}

	if err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput); err != nil {
		if shouldIgnoreOptionalFormNullableError(r, err) {
			return http.StatusOK, nil
		}

		me := openapi3.MultiError{}
		if errors.As(err, &me) {
			return http.StatusBadRequest, me
		}

		switch validationError := err.(type) {
		case *openapi3filter.RequestError:
			errorLines := strings.Split(validationError.Error(), "\n")
			return http.StatusBadRequest, errors.New(errorLines[0])
		case *openapi3filter.SecurityRequirementsError:
			return http.StatusUnauthorized, validationError
		default:
			return http.StatusInternalServerError, fmt.Errorf("error validating request: %w", err)
		}
	}

	return http.StatusOK, nil
}

func shouldIgnoreOptionalFormNullableError(r *http.Request, err error) bool {
	contentType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if parseErr != nil || contentType != "application/x-www-form-urlencoded" {
		return false
	}

	multiError := openapi3.MultiError{}
	if errors.As(err, &multiError) {
		if len(multiError) == 0 {
			return false
		}

		for _, item := range multiError {
			if !isOptionalFormNullableError(r, item) {
				return false
			}
		}

		return true
	}

	return isOptionalFormNullableError(r, err)
}

func isOptionalFormNullableError(r *http.Request, err error) bool {
	requestError := &openapi3filter.RequestError{}
	if !errors.As(err, &requestError) || requestError.RequestBody == nil {
		return false
	}

	schemaError := &openapi3.SchemaError{}
	if !errors.As(err, &schemaError) || schemaError.Reason != "Value is not nullable" {
		return false
	}

	contentType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if parseErr != nil {
		return false
	}

	mediaType := requestError.RequestBody.Content.Get(contentType)
	if mediaType == nil || mediaType.Schema == nil || mediaType.Schema.Value == nil {
		return false
	}

	jsonPointer := schemaError.JSONPointer()
	if len(jsonPointer) == 0 {
		return false
	}

	fieldName := jsonPointer[len(jsonPointer)-1]
	propertySchema, ok := mediaType.Schema.Value.Properties[fieldName]
	if !ok || propertySchema == nil {
		return false
	}

	for _, requiredField := range mediaType.Schema.Value.Required {
		if requiredField == fieldName {
			return false
		}
	}

	if err := r.ParseForm(); err != nil {
		return false
	}

	_, present := r.PostForm[fieldName]
	return !present
}

type validationErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func writeValidationError(w http.ResponseWriter, statusCode int, err error) {
	response := validationErrorResponse{
		Error:            validationErrorCode(statusCode),
		ErrorDescription: err.Error(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func validationErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusNotFound:
		return "not_found"
	default:
		return "validation_error"
	}
}
