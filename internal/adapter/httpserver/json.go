package httpserver

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"

	"github.com/labstack/echo/v5"
)

// jsonSerializer is Echo's JSON with encoding/json/v2: request bodies match
// field names exactly and refuse duplicate names and invalid UTF-8; answers
// keep their keys sorted, as encoding/json wrote them, and end in a newline.
type jsonSerializer struct{}

func (jsonSerializer) Serialize(c *echo.Context, target any, indent string) error {
	opts := []json.Options{json.Deterministic(true)}
	if indent != "" {
		opts = append(opts, jsontext.WithIndent(indent))
	}
	return json.MarshalEncode(jsontext.NewEncoder(c.Response()), target, opts...)
}

func (jsonSerializer) Deserialize(c *echo.Context, target any) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		// A body over the limit comes with its own status.
		if echo.StatusCode(err) != 0 {
			return err
		}
		return echo.ErrBadRequest.Wrap(err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return echo.ErrBadRequest.Wrap(err)
	}
	return nil
}
