package traefik_cluster_ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/ip"
	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/redis"
	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/utils"
)

// Config the plugin configuration.
type Config struct {
	// RedisAddress is the address of the redis server, as "host:port"
	// the default is "redis:6379"
	RedisAddress string `json:"redisAddress,omitempty" yaml:"redisAddress,omitempty"`
	// if needed you can choose the redis db. By default we use the first (aka '0') db
	RedisDB uint `json:"redisDb,omitempty" yaml:"redisDb,omitempty"`
	// RedisPassword holds the password used to AUTH against a redis server, if it
	// is protected by a AUTH
	// if you dont want to put the password in clear text in the config definition
	// you can use an environment variable, and put the name of the env variable here
	// prefixed with '$'. For example '$REDIS_AUTH_PASSWORD'
	RedisPassword string `json:"redisPassword,omitempty" yaml:"redisPassword,omitempty"`
	// Average is the maximum rate, by default in requests/s, allowed for the given source.
	// It defaults to 0, which means no rate limiting.
	// The rate is actually defined by dividing Average by Period. So for a rate below 1req/s,
	// one needs to define a Period larger than a second.
	Average int64 `json:"average" yaml:"average"`
	// Burst is the maximum number of requests allowed to arrive in the same arbitrarily small period of time.
	// It defaults to 1.
	Burst int64 `json:"burst" yaml:"burst"`
	// Period, in combination with Average, defines the actual maximum rate, such as:
	// r = Average / Period. It defaults to a second.
	Period int64 `json:"period,omitempty" yaml:"period,omitempty"`
	// SourceCriterion defines what criterion is used to group requests as originating from a common source.
	// If several strategies are defined at the same time, an error will be raised.
	// If none are set, the default is to use the request's remote address field (as an ipStrategy).
	SourceCriterion *utils.SourceCriterion `json:"sourceCriterion,omitempty" yaml:"sourceCriterion,omitempty"`
	// BreakerThreshold is how many consecutive time a redis connection is failing before we
	// stop talking to it (default is 3)
	BreakerThreshold int64 `json:"breakerThreshold,omitempty" yaml:"breakerThreshold,omitempty"`
	// BreakerReattempt is the number of seconds to wait (after stopping to Redis) before
	// trying to talk again to Redis (default is 15)
	BreakerReattempt int64 `json:"breakerReattempt,omitempty" yaml:"breakerReattempt,omitempty"`
	// ConnectionTimeout is the read and write connection timeout to redis.
	// By default it is 2 seconds
	RedisConnectionTimeout int64 `json:"redisConnectionTimeout,omitempty" yaml:"redisConnectionTimeout,omitempty"`
	// WhitelistIPs is a list of IP addresses or CIDR ranges that will bypass rate limiting.
	// If an IP matches any entry in this list, the rate limit check is skipped entirely.
	WhitelistIPs []string `json:"whitelistIPs,omitempty" yaml:"whitelistIPs,omitempty"`
	// RedisUsername, when set, selects the two-argument `AUTH <username> <password>`
	// form introduced with Redis 6 ACLs. Left empty, the existing single-argument
	// `AUTH <password>` form is used, so existing deployments are unaffected.
	// Like RedisPassword it accepts a '$'-prefixed environment variable name.
	RedisUsername string `json:"redisUsername,omitempty" yaml:"redisUsername,omitempty"`
	// RedisTLS connects over TLS with no trust material of our own — what a
	// managed endpoint presenting a publicly-rooted certificate needs. It is
	// also implied by any of the four settings below.
	RedisTLS bool `json:"redisTls,omitempty" yaml:"redisTls,omitempty"`
	// RedisCaCertFile is a PEM bundle the server certificate is verified against.
	RedisCaCertFile string `json:"redisCaCertFile,omitempty" yaml:"redisCaCertFile,omitempty"`
	// RedisClientCertFile and RedisClientKeyFile are an optional client keypair
	// for mutual TLS. They must be set together.
	RedisClientCertFile string `json:"redisClientCertFile,omitempty" yaml:"redisClientCertFile,omitempty"`
	RedisClientKeyFile  string `json:"redisClientKeyFile,omitempty" yaml:"redisClientKeyFile,omitempty"`
	// RedisServerName is the name verified against the server certificate.
	// Derived from RedisAddress when empty.
	RedisServerName string `json:"redisServerName,omitempty" yaml:"redisServerName,omitempty"`
	// FailureMode decides what happens when the limiter cannot reach Redis:
	// the breaker is open, the connection failed, or the script errored.
	//
	//   "closed" (default) — reject with 503 and a Retry-After. The limit holds
	//                        as a guarantee; a Redis outage is an outage.
	//   "open"             — let the request through, unlimited. Availability
	//                        wins; whoever can take Redis down removes the limit.
	//
	// NOTE: this fork DEFAULTS TO CLOSED, where upstream fails open. A limiter
	// used as a security control should not stop limiting because its store
	// blinked, and a config that omits this field should not silently pick the
	// weaker posture. Set it to "open" explicitly for upstream behaviour.
	FailureMode string `json:"failureMode,omitempty" yaml:"failureMode,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

const (
	// FailureModeOpen lets requests through when the limiter cannot reach Redis.
	FailureModeOpen = "open"
	// FailureModeClosed rejects them with 503. This fork's default.
	FailureModeClosed = "closed"
)

type ClusterRateLimit struct {
	next             http.Handler
	limiter          *Limiter
	name             string
	average          int64
	burst            int64
	period           int64
	sourceMatcher    utils.SourceExtractor
	whitelistChecker *ip.Checker
	ipStrategy       ip.Strategy
	failureMode      string
	// retryAfter is what a fail-closed rejection advertises. The breaker's
	// reattempt period is the honest answer: it is when we will next try Redis,
	// so it is the earliest moment the answer could change.
	retryAfter int64
}

// New created a new ClusterRateLimit plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisAddress == "" {
		config.RedisAddress = "redis:6379"
	}
	if config.Average < 0 {
		return nil, fmt.Errorf("average must be >=0. 0 means unlimited")
	}
	if config.Burst < 1 {
		return nil, fmt.Errorf("burst must be >=1")
	}
	if config.Period < 1 {
		config.Period = 1
	}
	if config.BreakerThreshold < 1 {
		config.BreakerThreshold = 3
	}
	if config.BreakerReattempt < 1 {
		config.BreakerReattempt = 15
	}
	if config.RedisConnectionTimeout < 1 {
		config.RedisConnectionTimeout = 2
	}
	switch config.FailureMode {
	case "":
		config.FailureMode = FailureModeClosed
	case FailureModeOpen, FailureModeClosed:
	default:
		return nil, fmt.Errorf("failureMode must be %q or %q, got %q",
			FailureModeOpen, FailureModeClosed, config.FailureMode)
	}

	// if the redis password starts with '$' like $REDIS_PASSWORD
	// we read it from the environment variable
	if len(config.RedisPassword) > 1 && config.RedisPassword[0] == '$' {
		config.RedisPassword = os.Getenv(config.RedisPassword[1:])
	}
	// same indirection for the ACL username
	if len(config.RedisUsername) > 1 && config.RedisUsername[0] == '$' {
		config.RedisUsername = os.Getenv(config.RedisUsername[1:])
	}

	sourceMatcher, err := utils.GetSourceExtractor(config.SourceCriterion)
	if err != nil {
		return nil, err
	}

	// Initialize whitelist checker if whitelistIPs is provided
	var whitelistChecker *ip.Checker
	if len(config.WhitelistIPs) > 0 {
		whitelistChecker, err = ip.NewChecker(config.WhitelistIPs)
		if err != nil {
			return nil, fmt.Errorf("unable to create IP whitelist checker: %v", err)
		}
	}

	// Initialize IP strategy for whitelist checking
	var ipStrategy ip.Strategy
	if config.SourceCriterion != nil && config.SourceCriterion.IPStrategy != nil {
		ipStrategy, err = config.SourceCriterion.IPStrategy.Get()
		if err != nil {
			return nil, fmt.Errorf("unable to create IP strategy: %v", err)
		}
	} else {
		ipStrategy = &ip.RemoteAddrStrategy{}
	}

	client, err := redis.NewClient(redis.Options{
		Addr:              config.RedisAddress,
		DB:                config.RedisDB,
		Username:          config.RedisUsername,
		Password:          config.RedisPassword,
		ConnectionTimeout: time.Duration(config.RedisConnectionTimeout) * time.Second,
		TLS:               config.RedisTLS,
		CACertFile:        config.RedisCaCertFile,
		ClientCertFile:    config.RedisClientCertFile,
		ClientKeyFile:     config.RedisClientKeyFile,
		ServerName:        config.RedisServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create redis client: %v", err)
	}

	// err = client.Ping()
	// if err != nil {
	// 	return nil, fmt.Errorf("error connecting to Redis: %v", err)
	// }

	return &ClusterRateLimit{
		next:             next,
		limiter:          NewLimiter(client, name, config.BreakerThreshold, config.BreakerReattempt),
		name:             name,
		average:          config.Average,
		burst:            config.Burst,
		period:           config.Period,
		sourceMatcher:    sourceMatcher,
		whitelistChecker: whitelistChecker,
		ipStrategy:       ipStrategy,
		failureMode:      config.FailureMode,
		retryAfter:       config.BreakerReattempt,
	}, nil
}

func (rl *ClusterRateLimit) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// cf https://medium.com/@bingolbalihasan/redis-rate-limiting-in-go-d342bab3d930

	// average = 0 means unlimited
	if rl.average == 0 {
		rl.next.ServeHTTP(rw, req)
		return
	}

	// Check if IP is whitelisted - if so, bypass rate limiting entirely
	if rl.whitelistChecker != nil {
		clientIP := rl.ipStrategy.GetIP(req)
		if clientIP != "" {
			contains, err := rl.whitelistChecker.Contains(clientIP)
			if err == nil && contains {
				rl.next.ServeHTTP(rw, req)
				return
			}
		}
	}

	source, _, err := rl.sourceMatcher.Extract(req)
	if err != nil {
		//logger.Error().Err(err).Msg("Could not extract source of request")
		http.Error(rw, "could not extract source of request", http.StatusInternalServerError)
		return
	}

	res, err := rl.limiter.Allow(source, Limit{
		Rate:   rl.average,
		Burst:  rl.burst,
		Period: time.Duration(rl.period) * time.Second,
	})
	if err != nil {
		// The limiter could not reach its store. Either posture is defensible;
		// neither is a non-decision, so the mode is explicit.
		if rl.failureMode == FailureModeOpen {
			rl.next.ServeHTTP(rw, req)
			return
		}
		// 503, not 429 and not 500: the client is not over its rate, and this
		// is not an internal error in handling THIS request — the dependency is
		// unavailable. Retry-After advertises when the breaker will next probe,
		// which is the earliest the answer could change.
		rw.Header().Set("retry-after", fmt.Sprintf("%d", rl.retryAfter))
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	} else {
		if res.Allowed <= 0 {
			retryAfter := int64(res.RetryAfter/time.Second) + 1
			rw.Header().Set("retry-after", fmt.Sprintf("%d", retryAfter))
			http.Error(rw, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		rl.next.ServeHTTP(rw, req)
	}
}
