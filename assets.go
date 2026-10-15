// Package assets embeds the built login page (public/) so the auth centre can
// serve /auth and /assets/* itself without a separate static file server. The
// directory is still kept at the repository root so a deployment can let nginx
// serve it directly, exactly like the legacy layout.
package assets

import "embed"

// Public holds the login page build output (index.html + assets/*).
//
//go:embed public
var Public embed.FS

// PublicDir is the directory inside Public that contains index.html.
const PublicDir = "public"
