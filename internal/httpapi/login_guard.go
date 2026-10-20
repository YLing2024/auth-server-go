package httpapi

import "auth-server-go/internal/totp"

// rateLimitBody is the single 429 shape for both login endpoints. It never
// reveals which dimension (IP or device) triggered the lock.
type rateLimitBody struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retryAfter"`
}

// newRateLimitBody builds the shared 429 payload.
func newRateLimitBody(retryAfter int) rateLimitBody {
	return rateLimitBody{Code: "rate_limited", Message: "Too many attempts", RetryAfter: retryAfter}
}

// combineLockStatus merges the IP and device dimensions. Either dimension may
// reject the request; retryAfter follows the longer remaining lock.
func combineLockStatus(ipStatus, deviceStatus totp.Status, hasDevice bool) (bool, int) {
	locked := ipStatus.Locked
	retry := 0
	if ipStatus.Locked {
		retry = ipStatus.RetryAfter
	}
	if hasDevice && deviceStatus.Locked {
		locked = true
		if deviceStatus.RetryAfter > retry {
			retry = deviceStatus.RetryAfter
		}
	}
	return locked, retry
}

// loginLockStatus reports whether the IP or device dimension currently blocks
// the request and how many seconds the longer lock has left.
func (s *Server) loginLockStatus(limiter *totp.RateLimiter, ip, deviceKey string) (bool, int) {
	deviceStatus := totp.Status{}
	if deviceKey != "" {
		deviceStatus = s.deviceLimiter.Status(deviceKey)
	}
	return combineLockStatus(limiter.Status(ip), deviceStatus, deviceKey != "")
}

// recordLoginFailure charges one failed attempt to both dimensions. The global
// counter observes the same failure but never blocks; when the device
// dimension locks for the first time, only its eight-character prefix is
// logged so full device keys never reach the log stream.
func (s *Server) recordLoginFailure(limiter *totp.RateLimiter, ip, deviceKey string) {
	limiter.RecordFailure(ip)
	if deviceKey != "" {
		wasLocked := s.deviceLimiter.Status(deviceKey).Locked
		status := s.deviceLimiter.RecordFailure(deviceKey)
		if !wasLocked && status.Locked {
			s.log().Warn("login: 设备维度锁定", "device", deviceKeyPrefix(deviceKey), "retryAfter", status.RetryAfter)
		}
	}
	if alert, ok := s.globalLimiter.RecordFailure(); ok {
		s.log().Warn("login: 全局失败计数达到阈值，仅告警不拒绝",
			"windowFailures", alert.WindowFailures,
			"threshold", alert.Threshold,
			"totalFailures", alert.TotalFailures)
	}
}

// clearLoginFailures wipes both dimensions after a successful login.
func (s *Server) clearLoginFailures(limiter *totp.RateLimiter, ip, deviceKey string) {
	limiter.RecordSuccess(ip)
	if deviceKey != "" {
		s.deviceLimiter.RecordSuccess(deviceKey)
	}
}
