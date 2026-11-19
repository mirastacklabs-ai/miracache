package bundle

import (
	"encoding/hex"
	"strconv"
)

func strconvItoa(n int) string { return strconv.Itoa(n) }
func hexLower(b []byte) string { return hex.EncodeToString(b) }
