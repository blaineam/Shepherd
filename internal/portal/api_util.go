// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"unicode"
)

// Request body limits. The portal reads JSON only, never forms or uploads.
const (
	smallBody = 1 << 16 // most requests
	listBody  = 2 << 20 // a pasted custom list may be up to 1 MiB of text
)

// decode reads one JSON object from the body into v. Unknown fields, trailing
// data and oversized bodies are rejected. It writes the error and returns false
// on failure.
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		var extra json.RawMessage
		if e := dec.Decode(&extra); !errors.Is(e, io.EOF) {
			err = errors.New("unexpected data after the JSON object")
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		}
		return false
	}
	return true
}

func bad(w http.ResponseWriter, msg string)      { http.Error(w, msg, http.StatusBadRequest) }
func notFound(w http.ResponseWriter, msg string) { http.Error(w, msg, http.StatusNotFound) }
func conflict(w http.ResponseWriter, msg string) { http.Error(w, msg, http.StatusConflict) }

// serverFault answers 500 without echoing the underlying error to the client.
func serverFault(w http.ResponseWriter, what string) {
	http.Error(w, what, http.StatusInternalServerError)
}

// isIOError reports whether err came from the file system rather than from
// validation, so a failed save is a 500 and not a 400.
func isIOError(err error) bool {
	var pe *fs.PathError
	var le *os.LinkError
	return errors.As(err, &pe) || errors.As(err, &le)
}

func hasControl(s string) bool {
	for _, c := range s {
		if unicode.IsControl(c) {
			return true
		}
	}
	return false
}

// intParam reads a non-negative integer query parameter.
func intParam(r *http.Request, name string, def int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
