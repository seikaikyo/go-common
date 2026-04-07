// Package response provides a standard JSON API response envelope.
//
// All Go services share this format so frontends see a consistent shape:
//
//	{"success": true, "data": ...}
//	{"success": false, "error": "..."}
package response

import (
	"encoding/json"
	"net/http"
)

// Body is the standard API response envelope.
type Body struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
	Total   int    `json:"total,omitempty"`
	Page    int    `json:"page,omitempty"`
}

// OK writes a 200 success response.
func OK(w http.ResponseWriter, data any) {
	write(w, http.StatusOK, Body{Success: true, Data: data})
}

// OKPage writes a 200 success response with pagination.
func OKPage(w http.ResponseWriter, data any, total, page int) {
	write(w, http.StatusOK, Body{Success: true, Data: data, Total: total, Page: page})
}

// Err writes an error response with the given HTTP status.
func Err(w http.ResponseWriter, status int, msg string) {
	write(w, status, Body{Success: false, Error: msg})
}

func write(w http.ResponseWriter, status int, body Body) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
