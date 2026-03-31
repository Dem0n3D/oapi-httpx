package security

import (
	"net/http"

	"github.com/Dem0n3D/oapi-httpx/render"
)

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func WriteError(w http.ResponseWriter, statusCode int, code string, description string) {
	render.WriteJSON(w, statusCode, ErrorResponse{
		Error:            code,
		ErrorDescription: description,
	})
}

func WriteUnauthorized(w http.ResponseWriter, description string) {
	WriteError(w, http.StatusUnauthorized, "unauthorized", description)
}

func WriteForbidden(w http.ResponseWriter, description string) {
	WriteError(w, http.StatusForbidden, "forbidden", description)
}
