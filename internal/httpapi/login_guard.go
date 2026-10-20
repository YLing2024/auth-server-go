package httpapi

import "auth-server-go/internal/totp"

// rateLimitBody is the single 429 shape for both login endpoints. It never
// reveals which dimension (IP, device or fingerprint rotation) triggered the
// lock.
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

// loginLockStatus reports whether the IP, device or fingerprint-rotation
// dimension currently blocks the request and how many seconds the longest lock
// has left.
func (s *Server) loginLockStatus(limiter *totp.RateLimiter, ip string, dev deviceIdentity) (bool, int) {
	deviceStatus := totp.Status{}
	if dev.key != "" {
		deviceStatus = s.deviceLimiter.Status(dev.key)
	}
	locked, retry := combineLockStatus(limiter.Status(ip), deviceStatus, dev.key != "")
	if fpLocked, fpRetry := s.fpRotator.Status(dev.cookieID); fpLocked {
		locked = true
		if fpRetry > retry {
			retry = fpRetry
		}
	}
	return locked, retry
}

// recordLoginFailure charges one failed attempt to the IP and device
// dimensions plus fingerprint rotation. The global counter observes the same
// failure but never blocks; when a dimension locks for the first time, only the
// device-key prefix is logged so full keys and visitorIds never reach the log
// stream.
func (s *Server) recordLoginFailure(limiter *totp.RateLimiter, ip string, dev deviceIdentity) {
	limiter.RecordFailure(ip)
	if dev.key != "" {
		wasLocked := s.deviceLimiter.Status(dev.key).Locked
		status := s.deviceLimiter.RecordFailure(dev.key)
		if !wasLocked && status.Locked {
			s.log().Warn("login: 设备维度锁定", "device", deviceKeyPrefix(dev.key), "retryAfter", status.RetryAfter)
		}
	}
	if dev.fingerprint != "" {
		wasLocked, _ := s.fpRotator.Status(dev.cookieID)
		locked, retryAfter := s.fpRotator.Record(dev.cookieID, dev.fingerprint)
		if !wasLocked && locked {
			s.log().Warn("login: 指纹轮换锁定", "device", deviceKeyPrefix(dev.key), "retryAfter", retryAfter)
		}
	}
	if alert, ok := s.globalLimiter.RecordFailure(); ok {
		s.log().Warn("login: 全局失败计数达到阈值，仅告警不拒绝",
			"windowFailures", alert.WindowFailures,
			"threshold", alert.Threshold,
			"totalFailures", alert.TotalFailures)
	}
}

// clearLoginFailures wipes both dimensions after a successful login. The
// fingerprint rotation set is intentionally left intact: a successful code
// must not let a cookie reset its observed visitorId history.
func (s *Server) clearLoginFailures(limiter *totp.RateLimiter, ip string, dev deviceIdentity) {
	limiter.RecordSuccess(ip)
	if dev.key != "" {
		s.deviceLimiter.RecordSuccess(dev.key)
	}
}
