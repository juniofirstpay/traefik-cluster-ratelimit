package redis

import (
	"fmt"
	"time"
)

type ScriptWithBreaker struct {
	script           Script
	errorCount       int64
	nextAttempt      time.Time
	breakerThreshold int64
	reattemptPeriod  int64
}

func NewScriptWithBreaker(script Script, breakerThreshold int64, reattemptPeriod int64) Script {
	return &ScriptWithBreaker{
		script:           script,
		errorCount:       0,
		nextAttempt:      time.Now(),
		breakerThreshold: breakerThreshold,
		reattemptPeriod:  reattemptPeriod,
	}
}

func (swb *ScriptWithBreaker) Run(keys []string, args ...interface{}) (interface{}, error) {
	if swb.errorCount < 3 || time.Now().After(swb.nextAttempt) {
		res, err := swb.script.Run(keys, args...)

		if err != nil {
			swb.errorCount++
			// `>=`, not `==`. With `==` this fired exactly once: after the first
			// reattempt window elapsed, the probe call failed, errorCount moved
			// past the threshold, and nextAttempt was never refreshed again. It
			// stayed in the past, so `time.Now().After(nextAttempt)` was
			// permanently true and every subsequent request dialled Redis afresh
			// — the breaker protected for one window and was then inert.
			if swb.errorCount >= swb.breakerThreshold {
				swb.nextAttempt = time.Now().Add(time.Duration(swb.reattemptPeriod) * time.Second)
			}
		} else {
			swb.errorCount = 0
		}

		return res, err
	} else {
		return nil, fmt.Errorf("breaker opened")
	}
}
