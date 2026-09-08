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
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

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

	// if the redis password starts with '$' like $REDIS_PASSWORD
	// we read it from the environment variable
	if len(config.RedisPassword) > 1 && config.RedisPassword[0] == '$' {
		config.RedisPassword = os.Getenv(config.RedisPassword[1:])
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

	client, err := redis.NewClient(
		config.RedisAddress,
		config.RedisDB,
		config.RedisPassword,
		time.Duration(config.RedisConnectionTimeout)*time.Second,
	)
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
		rl.next.ServeHTTP(rw, req)
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
