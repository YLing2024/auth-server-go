package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

type sessionsBody struct {
	Sessions []sessionInfo `json:"sessions"`
}

// handleSessionList returns the device sessions for the authenticated user.
func (s *Server) handleSessionList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(r.Context(), r); !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "未登录或会话已过期"})
		return
	}
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	sessions, err := s.collectSessions(r.Context(), tokenFrom(r), "")
	if err != nil {
		s.log().Error("sessions list error", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "server_error", Message: "会话列表查询失败"})
		return
	}
	writeJSON(w, http.StatusOK, sessionsBody{Sessions: sessions})
}

// handleSessionRename renames the authenticated user's own session.
func (s *Server) handleSessionRename(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(r.Context(), r); !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "未登录或会话已过期"})
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
	if len(meta) == 0 {
		ip := clientIP(r)
		local := "0"
		if isPrivateIP(ip) {
			local = "1"
		}
		now := strconv.FormatInt(time.Now().UnixMilli(), 10)
		_ = c.SAdd(ctx, sessionIndexKey, id).Err()
		_ = c.HSet(ctx, hashKey, map[string]any{
			"user": s.subject, "deviceName": "", "ip": ip, "location": "",
			"isLocal": local, "userAgent": truncateRunes(r.Header.Get("User-Agent"), 300),
			"createdAt": now, "lastSeenAt": now, "remember": "1",
		}).Err()
	}
	_ = c.HSet(ctx, hashKey, "deviceName", deviceName).Err()
	if metaRemember(meta) {
		_ = c.Expire(ctx, hashKey, sessionTTL(s.cfg)).Err()
	}
	writeJSON(w, http.StatusOK, okDeviceBody{OK: true, DeviceName: deviceName})
}

// handleSessionDelete revokes a session token. It is idempotent.
func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(r.Context(), r); !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "未登录或会话已过期"})
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
	s.revokeSession(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
