package api

import (
	"fmt"
	"net/http"
	"testing"

	"miracache/controller/bundle"
	"miracache/controller/publish"
)

// F02: a *bundle.Error is a client error only when it carries publish.ErrBadEdit.
func TestPublishStatusBundleErrors(t *testing.T) {
	be := &bundle.Error{Reason: "drop_before_future", Msg: "x"}
	cases := []struct {
		name string
		err  error
		code int
		why  string
	}{
		{"bad edit", fmt.Errorf("%w: %w", publish.ErrBadEdit, be), http.StatusBadRequest, "bad_bundle"},
		{"own trust refuses", fmt.Errorf("the controller built a bundle its own trust file refuses: %w", be), http.StatusInternalServerError, "publish_failed"},
		{"corrupt stored envelope", fmt.Errorf("store: last envelope: %w", be), http.StatusInternalServerError, "publish_failed"},
	}
	for _, c := range cases {
		code, why := publishStatus(c.err)
		if code != c.code || why != c.why {
			t.Errorf("%s: got %d %s, want %d %s", c.name, code, why, c.code, c.why)
		}
	}
}
