package httpapi

import (
	"net/http"
	"strings"
	"time"

	"auth-server-go/internal/jwt"
	"auth-server-go/internal/oidc"
	"auth-server-go/internal/totp"
)

// resetBody is the shared two-phase reset response body.
type resetBody struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
	ExpiresIn  int    `json:"expiresIn"`
}

// confirmError is the failed two-phase confirm body.
type confirmError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// performTotpReset is the single implementation behind both the public and the
// internal reset endpoints. It only writes the pending secret (5 minutes) and
// never touches the formal secret.
func (s *Server) performTotpReset() (int, resetBody) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		s.log().Error("生成 pending TOTP secret 失败", "error", err)
		return http.StatusInternalServerError, resetBody{}
	}
	if err := s.pending.Save(secret); err != nil {
		s.log().Error("写入 pending TOTP secret 失败", "error", err)
		return http.StatusInternalServerError, resetBody{}
	}
	return http.StatusOK, resetBody{Secret: secret, OtpauthURI: s.otpauthURI(secret), ExpiresIn: 300}
}

// performTotpConfirm is the single implementation behind both confirm
// endpoints: the pending code must verify before the formal secret is replaced.
func (s *Server) performTotpConfirm(rawCode any) (int, any) {
	pending, ok := s.pending.Load()
	if !ok {
		return http.StatusBadRequest, confirmError{Code: "no_pending", Message: "没有待确认的 TOTP 重置"}
	}
	code := ""
	if str, isStr := rawCode.(string); isStr {
		code = strings.TrimSpace(str)
	}
	if !totp.Verify(pending.Secret, code, totp.DefaultWindow) {
		s.pending.Delete()
		return http.StatusBadRequest, confirmError{Code: "invalid_code", Message: "验证码错误"}
	}
	if err := s.secrets.Save(pending.Secret); err != nil {
		s.log().Error("写入正式 TOTP secret 失败", "error", err)
		return http.StatusInternalServerError, confirmError{Code: "server_error", Message: "写入失败"}
	}
	s.pending.Delete()
	return http.StatusOK, map[string]any{"ok": true}
}

// otpauthURI builds the enrolment URI; the label is the display name.
func (s *Server) otpauthURI(secret string) string {
	label := oidc.EncodeURIComponent(s.cfg.DisplayName)
	return "otpauth://totp/" + label + ":" + label + "?secret=" + secret + "&issuer=" + label +
		"&period=30&digits=6&algorithm=SHA1"
}

// handleAppTotpReset is the session-authenticated reset endpoint.
func (s *Server) handleAppTotpReset(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(r.Context(), r); !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "未登录或会话已过期"})
		return
	}
	status, body := s.performTotpReset()
	writeJSON(w, status, body)
}

// handleAppTotpConfirm is the session-authenticated confirm endpoint.
func (s *Server) handleAppTotpConfirm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(r.Context(), r); !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "未登录或会话已过期"})
		return
	}
	status, body := s.performTotpConfirm(anyBodyString(readJSONBody(r), "code"))
	writeJSON(w, status, body)
}

// anyBodyString returns a body field as a string without trimming.
func anyBodyString(body map[string]any, key string) any {
	if v, ok := body[key]; ok {
		return v
	}
	return nil
}

/* ---------------- 旧 TOTP 模块路由（零构建 js 模块的等价实现） ---------------- */

// moduleSecret is the shared secret accessor mirroring the module's loadSecret.
func (s *Server) moduleSecret() (string, bool) { return s.secrets.Load() }

// handleModuleSetup serves POST /api/totp/setup and /api/setup: it only works
// while no secret is configured.
func (s *Server) handleModuleSetup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.moduleSecret(); ok {
		writeJSON(w, http.StatusConflict, errorBody{Code: "totp_already_setup", Message: "TOTP already configured"})
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "secret 生成失败"})
		return
	}
	if err := s.secrets.Save(secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "secret 写入失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauthUri": s.otpauthURI(secret)})
}

// handleModuleReset serves POST /api/reset and /api/totp/reset via the module
// when not shadowed: it requires a legacy HS256 Bearer token.
func (s *Server) handleModuleReset(w http.ResponseWriter, r *http.Request) {
	if !s.moduleAuthOK(w, r) {
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "secret 生成失败"})
		return
	}
	if err := s.secrets.Save(secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "secret 写入失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauthUri": s.otpauthURI(secret)})
}

// moduleAuthOK enforces the module's Bearer HS256 requirement.
func (s *Server) moduleAuthOK(w http.ResponseWriter, r *http.Request) bool {
	header := r.Header.Get("Authorization")
	fields := strings.SplitN(header, " ", 2)
	if len(fields) != 2 || fields[0] != "Bearer" || fields[1] == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "Missing Bearer token"})
		return false
	}
	if _, err := jwt.VerifyHS256(fields[1], s.cfg.JWTSecret); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "invalid_token", Message: "Invalid or expired token"})
		return false
	}
	return true
}

// handleModuleLogin serves the legacy module login: it issues an HS256 JWT and
// rate-limits by the direct peer address (the module never read proxy headers)
// plus the shared device dimension.
func (s *Server) handleModuleLogin(w http.ResponseWriter, r *http.Request) {
	body := readJSONBody(r)
	ip := remoteIP(r)
	dev := DeviceIdentityFromRequest(w, r)
	if locked, retryAfter := s.loginLockStatus(s.moduleLimiter, ip, dev); locked {
		writeJSON(w, http.StatusTooManyRequests, newRateLimitBody(retryAfter))
		return
	}
	secret, ok := s.moduleSecret()
	if !ok {
		writeJSON(w, http.StatusForbidden, errorBody{Code: "totp_setup_required", Message: "TOTP is not configured yet"})
		return
	}
	code := strings.TrimSpace(bodyString(body, "code"))
	if !totp.Verify(secret, code, totp.DefaultWindow) {
		s.recordLoginFailure(s.moduleLimiter, ip, dev)
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "invalid_code", Message: "Invalid TOTP code"})
		return
	}
	s.clearLoginFailures(s.moduleLimiter, ip, dev)
	token, err := jwt.SignHS256(map[string]any{"sub": s.cfg.DisplayName, "ip": ip}, s.cfg.JWTSecret, 12*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "签发失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expiresIn": "12h"})
}
