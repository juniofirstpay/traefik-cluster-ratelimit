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
	// TrustedProxies is the set of addresses and CIDRs that are our own
	// infrastructure. Setting it selects the trusted-proxy walk: anchor on the
	// socket peer, walk X-Forwarded-For right to left skipping anything in this
	// set, and take the first address that is not.
	//
	// It sits at the top level rather than under sourceCriterion because the
	// derived address has more than one consumer — the rate-limit bucket key,
	// the whitelistIPs bypass check, and (once published) the headers offered
	// to downstream services. sourceCriterion describes only the first of
	// those, so nesting it there would misdescribe what it configures.
	//
	// Mutually exclusive with sourceCriterion.ipStrategy: setting both is an
	// error at load rather than a silent precedence rule.
	//
	// CIDRs, not addresses, for anything elastic. A load balancer runs a node
	// per subnet and the provider adds and removes them without notice, so an
	// enumerated list of node addresses rots silently.
	TrustedProxies []string `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	// IPv6Subnet is the prefix length an IPv6 client address is aggregated to
	// before it becomes a rate-limit key. Defaults to 64.
	//
	// Aggregation is UNCONDITIONAL — there is no mode and no off switch. An
	// IPv6 client is allocated a network, not an address, and OS privacy
	// extensions rotate the low bits by default, so per-address limiting does
	// not constrain it at all. Accepted range is 32-64: 128 would mean the
	// address itself, which is the bypass this closes.
	//
	// IPv4 is never aggregated regardless. CGNAT already puts many unrelated
	// subscribers behind one address.
	IPv6Subnet int `json:"ipv6Subnet,omitempty" yaml:"ipv6Subnet,omitempty"`
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

	if config.IPv6Subnet == 0 {
		config.IPv6Subnet = ip.DefaultIPv6Subnet
	}
	if config.IPv6Subnet < ip.MinIPv6Subnet || config.IPv6Subnet > ip.MaxIPv6Subnet {
		return nil, fmt.Errorf("ipv6Subnet must be between %d and %d, got %d: %d would disable "+
			"aggregation entirely, which is the bypass it exists to close",
			ip.MinIPv6Subnet, ip.MaxIPv6Subnet, config.IPv6Subnet, config.IPv6Subnet)
	}

	hasIPStrategy := config.SourceCriterion != nil && config.SourceCriterion.IPStrategy != nil
	if len(config.TrustedProxies) > 0 && hasIPStrategy {
		return nil, fmt.Errorf("trustedProxies and sourceCriterion.ipStrategy are mutually exclusive: " +
			"set one or the other, not both")
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

	// Initialize the IP strategy. It derives the client address for the
	// whitelist check and, when trustedProxies is set, for the rate-limit key
	// too — so both stop depending on where in the chain the reader sits.
	var ipStrategy ip.Strategy
	switch {
	case len(config.TrustedProxies) > 0:
		checker, cerr := ip.NewChecker(config.TrustedProxies)
		if cerr != nil {
			return nil, fmt.Errorf("unable to parse trustedProxies: %v", cerr)
		}
		walk := &ip.TrustedProxyStrategy{Checker: checker}
		ipStrategy = walk
		// The bucket key follows the same derivation, unless the operator
		// explicitly buckets by something that is not an IP at all.
		if config.SourceCriterion == nil ||
			(config.SourceCriterion.RequestHeaderName == "" && !config.SourceCriterion.RequestHost) {
			ipv6Prefix := config.IPv6Subnet
			sourceMatcher = utils.ExtractorFunc(func(req *http.Request) (string, int64, error) {
				// The bucket key is the AGGREGATE. Identity stays the full
				// address — the whitelist check below still uses it, and it is
				// what an audit trail wants.
				return ip.Subnet(walk.GetIP(req), ipv6Prefix), 1, nil
			})
		}
	case hasIPStrategy:
		ipStrategy, err = config.SourceCriterion.IPStrategy.Get()
		if err != nil {
			return nil, fmt.Errorf("unable to create IP strategy: %v", err)
		}
	default:
		// No silent fallback. Upstream defaults an absent sourceCriterion to
		// RemoteAddr, which behind any proxy resolves every client to the
		// proxy's own address and collapses them into one bucket — a defect
		// that is invisible from the outside and can sit unnoticed for months.
		//
		// Requiring the choice means deleting trustedProxies is loud: the
		// middleware fails to build and the router is dropped at deploy time,
		// rather than quietly degrading. `sourceCriterion.ipStrategy: {}` is
		// the explicit way to ask for RemoteAddr.
		return nil, fmt.Errorf("a client-IP derivation must be configured explicitly: set " +
			"trustedProxies, or sourceCriterion.ipStrategy (an empty ipStrategy means RemoteAddr)")
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

// destroyedHeaders are removed from every request, unconditionally, before any
// other decision this middleware makes.
//
// Forwarded  RFC 7239, and the one that bites hardest: frameworks that resolve
//
//	a client address commonly prefer it OVER X-Forwarded-For — Falcon
//	does — so a client sending `Forwarded: for=1.2.3.4` overrides the
//	real chain. An edge that filters only `X-Forwarded-For` does not
//	cover it.
//
// X-Real-IP  commonly consulted as a fallback, and a reverse proxy sets it to
//
//	its own socket peer — a load-balancer node, never the client. It
//	is wrong AND client-settable, which is the worst pair.
//
// X-Forwarded-For is deliberately LEFT INTACT. Downstream services read it and
// the derivation depends on it; removing it would break both.
//
// Underscore and dot aliases (X_Forwarded_For, X.Real.IP) cannot be handled
// here — Go canonicalises header keys on the way in, and a WSGI/CGI backend
// folds them onto the same variable as the canonical form. That belongs at the
// proxy's entrypoint; in Traefik it is http.aliasHeadersStrategy: delete.
var destroyedHeaders = []string{
	"Forwarded",
	"X-Real-IP",
}

func (rl *ClusterRateLimit) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// cf https://medium.com/@bingolbalihasan/redis-rate-limiting-in-go-d342bab3d930

	// FIRST, before anything can read them and before any early return. An
	// unlimited route (average = 0) still gets the destruction: whether a route
	// is rate limited says nothing about whether its backend should be handed a
	// client-settable address header.
	for _, h := range destroyedHeaders {
		req.Header.Del(h)
	}

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
