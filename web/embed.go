// Package web embeds the browser front end.
package web

import "embed"

//go:embed index.html admin.html static
var FS embed.FS
