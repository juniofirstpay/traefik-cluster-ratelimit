package utils

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/ip"
)

// IPStrategy holds the IP strategy configuration used by Traefik to determine the client IP.
// More info: https://doc.traefik.io/traefik/v3.1/middlewares/http/ipallowlist/#ipstrategy
type IPStrategy struct {
	// Depth tells Traefik to use the X-Forwarded-For header and take the IP located at the depth position (starting from the right).
	Depth int `json:"depth,omitempty" toml:"depth,omitempty" yaml:"depth,omitempty" export:"true"`
	// ExcludedIPs configures Traefik to scan the X-Forwarded-For header and select the first IP not in the list.
	ExcludedIPs []string `json:"excludedIPs,omitempty" toml:"excludedIPs,omitempty" yaml:"excludedIPs,omitempty"`
	// TODO(mpl): I think we should make RemoteAddr an explicit field. For one thing, it would yield better documentation.
}

// Get an IP selection strategy.
// If nil return the RemoteAddr strategy
// else return a strategy based on the configuration using the X-Forwarded-For Header.
// Depth override the ExcludedIPs.
func (s *IPStrategy) Get() (ip.Strategy, error) {
	if s == nil {
		return &ip.RemoteAddrStrategy{}, nil
	}

	if s.Depth > 0 {
		return &ip.DepthStrategy{
			Depth: s.Depth,
		}, nil
	}

	if len(s.ExcludedIPs) > 0 {
		checker, err := ip.NewChecker(s.ExcludedIPs)
		if err != nil {
			return nil, err
		}
		return &ip.PoolStrategy{
			Checker: checker,
		}, nil
	}

	return &ip.RemoteAddrStrategy{}, nil
}

type SourceCriterion struct {
	IPStrategy *IPStrategy `json:"ipStrategy,omitempty" toml:"ipStrategy,omitempty" yaml:"ipStrategy,omitempty" export:"true"`
	// RequestHeaderName defines the name of the header used to group incoming requests.
	RequestHeaderName string `json:"requestHeaderName,omitempty" toml:"requestHeaderName,omitempty" yaml:"requestHeaderName,omitempty" export:"true"`
	// RequestHost defines whether to consider the request Host as the source.
	RequestHost bool `json:"requestHost,omitempty" toml:"requestHost,omitempty" yaml:"requestHost,omitempty" export:"true"`
}

// GetSourceExtractor returns the SourceExtractor function corresponding to the given sourceMatcher.
// It defaults to a RemoteAddrStrategy IPStrategy if need be.
// It returns an error if more than one source criterion is provided.
func GetSourceExtractor(sourceMatcher *SourceCriterion) (SourceExtractor, error) {
	if sourceMatcher != nil {
		if sourceMatcher.IPStrategy != nil && sourceMatcher.RequestHeaderName != "" {
			return nil, errors.New("iPStrategy and RequestHeaderName are mutually exclusive")
		}
		if sourceMatcher.IPStrategy != nil && sourceMatcher.RequestHost {
			return nil, errors.New("iPStrategy and RequestHost are mutually exclusive")
		}
		if sourceMatcher.RequestHeaderName != "" && sourceMatcher.RequestHost {
			return nil, errors.New("requestHost and RequestHeaderName are mutually exclusive")
		}
	}

	if sourceMatcher == nil ||
		sourceMatcher.IPStrategy == nil &&
			sourceMatcher.RequestHeaderName == "" && !sourceMatcher.RequestHost {
		sourceMatcher = &SourceCriterion{
			IPStrategy: &IPStrategy{},
		}
	}

	//	logger := log.Ctx(ctx)
	if sourceMatcher.IPStrategy != nil {
		strategy, err := sourceMatcher.IPStrategy.Get()
		if err != nil {
			return nil, err
		}

		//		logger.Debug().Msg("Using IPStrategy")
		return ExtractorFunc(func(req *http.Request) (string, int64, error) {
			return strategy.GetIP(req), 1, nil
		}), nil
	}

	if sourceMatcher.RequestHeaderName != "" {
		//logger.Debug().Msg("Using RequestHeaderName")
		return NewExtractor(fmt.Sprintf("request.header.%s", sourceMatcher.RequestHeaderName))
	}

	if sourceMatcher.RequestHost {
		//logger.Debug().Msg("Using RequestHost")
		return NewExtractor("request.host")
	}

	return nil, errors.New("no SourceCriterion criterion defined")
}
