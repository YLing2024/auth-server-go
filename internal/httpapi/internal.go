package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// internalTokenMatches compares the shared internal token in constant time over
// fixed-length digests, so length and timing differences cannot leak.
func (s *Server) internalTokenMatches(r *http.Request) bool {
	provided := strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	if provided == "" {
		return false
	}
	a := sha256.Sum256([]byte(provided))
	b := sha256.Sum256([]byte(s.cfg.InternalToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// internalAuthOK enforces the internal token; client credentials never apply.
func (s *Server) internalAuthOK(w http.ResponseWriter, r *http.Request) bool {
	if s.internalTokenMatches(r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "Invalid internal token"})
	return false
}

func internalSub(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("sub"))
}

// internalTotpSub validates the ?sub= assertion for the internal TOTP routes.
func (s *Server) internalTotpSub(w http.ResponseWriter, r *http.Request) bool {
	sub := internalSub(r)
	if sub == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "invalid_sub", Message: "缺少 sub 参数"})
		return false
	}
	if s.normalizeSubject(sub) != s.subject {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "not_found", Message: "用户不存在"})
		return false
	}
	return true
}

// handleInternalSessions lists a user's sessions. The body shape is identical to
// GET /api/sessions.
func (s *Server) handleInternalSessions(w http.ResponseWriter, r *http.Request) {
	if !s.internalAuthOK(w, r) {
		return
	}
	sub := internalSub(r)
	if sub == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "invalid_sub", Message: "缺少 sub 参数"})
		return
	}
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	sessions, err := s.collectSessions(r.Context(), "", sub)
	if err != nil {
		s.log().Error("internal sessions list error", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "会话列表查询失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// handleInternalRename renames a device session for the asserted user.
func (s *Server) handleInternalRename(w http.ResponseWriter, r *http.Request) {
	if !s.internalAuthOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if !tokenIDRe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "invalid_id", Message: "无效的会话标识"})
		return
	}
	raw := strings.TrimSpace(bodyString(readJSONBody(r), "deviceName"))
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "invalid_name", Message: "设备名称不能为空"})
		return
	}
	deviceName := truncateRunes(raw, 64)
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	ctx := r.Context()
	c := s.store.Client()
	exists, err := c.Exists(ctx, id).Result()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "重命名失败"})
		return
	}
	if exists != 1 {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "not_found", Message: "会话不存在或已过期"})
		return
	}
	hashKey := sessionHashKey(id)
	meta, _ := c.HGetAll(ctx, hashKey).Result()
	sub := internalSub(r)
	if len(meta) > 0 && sub != "" && s.normalizeSubject(meta["user"]) != sub {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "not_found", Message: "会话不存在或已过期"})
		return
	}
	if len(meta) == 0 {
		now := nowMillisStr()
		user := sub
		if user == "" {
			user = s.subject
		}
		_ = c.SAdd(ctx, sessionIndexKey, id).Err()
		_ = c.HSet(ctx, hashKey, map[string]any{
			"user": user, "deviceName": "", "ip": "", "location": "",
			"isLocal": "1", "userAgent": "", "createdAt": now, "lastSeenAt": now,
		}).Err()
	}
	_ = c.HSet(ctx, hashKey, "deviceName", deviceName).Err()
	_ = c.Expire(ctx, hashKey, sessionTTL(s.cfg)).Err()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deviceName": deviceName})
}

// handleInternalDelete revokes a device session for the asserted user.
func (s *Server) handleInternalDelete(w http.ResponseWriter, r *http.Request) {
	if !s.internalAuthOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if !tokenIDRe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "invalid_id", Message: "无效的会话标识"})
		return
	}
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	ctx := r.Context()
	if sub := internalSub(r); sub != "" {
		meta, _ := s.store.Client().HGetAll(ctx, sessionHashKey(id)).Result()
		if len(meta) > 0 && s.normalizeSubject(meta["user"]) != sub {
			writeJSON(w, http.StatusNotFound, errorBody{Code: "not_found", Message: "会话不存在或已过期"})
			return
		}
	}
	s.revokeSession(ctx, id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleInternalTotpReset shares performTotpReset with the public endpoint.
func (s *Server) handleInternalTotpReset(w http.ResponseWriter, r *http.Request) {
	if !s.internalAuthOK(w, r) {
		return
	}
	if !s.internalTotpSub(w, r) {
		return
	}
	status, body := s.performTotpReset()
	writeJSON(w, status, body)
}

// handleInternalTotpConfirm shares performTotpConfirm with the public endpoint.
func (s *Server) handleInternalTotpConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.internalAuthOK(w, r) {
		return
	}
	if !s.internalTotpSub(w, r) {
		return
	}
	status, body := s.performTotpConfirm(anyBodyString(readJSONBody(r), "code"))
	writeJSON(w, status, body)
}

func nowMillisStr() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}
