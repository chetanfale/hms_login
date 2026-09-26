package middleware

import (
	"net/http"
	"sync"
	"time"

	"hms_login/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// IPRateLimiter manages per-IP rate limiters using the Token Bucket algorithm.
type IPRateLimiter struct {
	ips map[string]*visitor
	mu  sync.RWMutex
	r   rate.Limit
	b   int
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter constructs a new rate limiter manager.
// r: limit of events per second (e.g. rate.Every(time.Minute / 5) for 5 req/min)
// b: burst capacity
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*visitor),
		r:   r,
		b:   b,
	}

	// Launch background cleanup goroutine to prevent memory leaks from inactive IPs
	go i.cleanupVisitors()

	return i
}

func (i *IPRateLimiter) getVisitor(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	v, exists := i.ips[ip]
	if !exists {
		limiter := rate.NewLimiter(i.r, i.b)
		i.ips[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (i *IPRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(3 * time.Minute)
		i.mu.Lock()
		for ip, v := range i.ips {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(i.ips, ip)
			}
		}
		i.mu.Unlock()
	}
}

// RateLimitMiddleware returns a Gin middleware enforcing IP rate limiting.
func RateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		vLimiter := limiter.getVisitor(ip)

		if !vLimiter.Allow() {
			utils.SendError(c, http.StatusTooManyRequests, "Rate limit exceeded", "TOO_MANY_REQUESTS", "You have made too many requests in a short time. Please wait before trying again.")
			c.Abort()
			return
		}

		c.Next()
	}
}
