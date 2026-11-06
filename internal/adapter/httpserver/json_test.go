package httpserver

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestJSONSerializerReadsExactJSONOnly(t *testing.T) {
	e := echo.NewWithConfig(echo.Config{JSONSerializer: jsonSerializer{}})
	type body struct {
		BlobSize int64 `json:"blob_size"`
	}
	bind := func(raw string) (body, error) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		var b body
		err := e.NewContext(req, httptest.NewRecorder()).Bind(&b)
		return b, err
	}

	if b, err := bind(`{"blob_size":5,"unknown":1}`); err != nil || b.BlobSize != 5 {
		t.Errorf("exact names: %+v, %v", b, err)
	}
	for name, raw := range map[string]string{
		"a name in another case": `{"Blob_Size":5}`,
		"a repeated name":        `{"blob_size":5,"blob_size":6}`,
		"invalid UTF-8":          "{\"x\":\"\xff\",\"blob_size\":5}",
		"trailing data":          `{"blob_size":5} {}`,
	} {
		b, err := bind(raw)
		var he *echo.HTTPError
		if name == "a name in another case" {
			// Not an error, but the field stays unset.
			if err != nil || b.BlobSize != 0 {
				t.Errorf("%s: %+v, %v", name, b, err)
			}
			continue
		}
		if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
	}
}

func TestJSONSerializerWritesSortedKeys(t *testing.T) {
	e := echo.NewWithConfig(echo.Config{JSONSerializer: jsonSerializer{}})
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	if err := c.JSON(http.StatusOK, map[string]any{"z": 1, "a": "<&>", "m": []string(nil)}); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Body.String(), `{"a":"<&>","m":[],"z":1}`+"\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
