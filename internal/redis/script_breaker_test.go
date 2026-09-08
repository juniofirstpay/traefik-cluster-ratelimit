package redis

import (
	"fmt"
	"testing"
	"time"
)

// alwaysFailingScript is a Script that never succeeds, and counts how many
// times it was actually invoked.
type alwaysFailingScript struct{ calls int }

func (s *alwaysFailingScript) Run(keys []string, args ...interface{}) (interface{}, error) {
	s.calls++
	return nil, fmt.Errorf("redis unreachable")
}

// TestBreakerReArmsAfterReattemptWindow is the regression test for the breaker
// re-arming. Before the fix, `errorCount == breakerThreshold` fired exactly
// once: the probe call after the first window pushed errorCount past the
// threshold, nextAttempt was never refreshed, and every later call reached
// Redis. The breaker protected for a single window and was then inert.
func TestBreakerReArmsAfterReattemptWindow(t *testing.T) {
	script := &alwaysFailingScript{}
	breaker := NewScriptWithBreaker(script, 3, 1)

	// Three failures trip the breaker.
	for i := 0; i < 3; i++ {
		if _, err := breaker.Run(nil); err == nil {
			t.Fatalf("call %d: expected the underlying failure to surface", i+1)
		}
	}
	if script.calls != 3 {
		t.Fatalf("expected 3 calls through to the script, got %d", script.calls)
	}

	// Breaker is open: the script must not be reached.
	if _, err := breaker.Run(nil); err == nil || err.Error() != "breaker opened" {
		t.Fatalf("expected the breaker to be open, got err=%v", err)
	}
	if script.calls != 3 {
		t.Fatalf("breaker was open but the script was still called: %d", script.calls)
	}

	// Let the reattempt window elapse; exactly one probe should get through.
	time.Sleep(1100 * time.Millisecond)
	if _, err := breaker.Run(nil); err == nil {
		t.Fatal("expected the probe call to surface the underlying failure")
	}
	if script.calls != 4 {
		t.Fatalf("expected exactly one probe through the open breaker, got %d calls", script.calls)
	}

	// THE REGRESSION: the failed probe must re-arm the breaker. Before the fix
	// nextAttempt was stale, so this call — and every one after it — reached
	// Redis again.
	if _, err := breaker.Run(nil); err == nil || err.Error() != "breaker opened" {
		t.Fatalf("breaker did not re-arm after the failed probe, got err=%v", err)
	}
	if script.calls != 4 {
		t.Fatalf("breaker did not re-arm: script called %d times, want 4", script.calls)
	}
}

// TestBreakerResetsOnSuccess guards the other direction: a successful call
// clears the error count, so a later failure run starts from zero.
func TestBreakerResetsOnSuccess(t *testing.T) {
	flaky := &flakyScript{failUntil: 2}
	breaker := NewScriptWithBreaker(flaky, 3, 1)

	breaker.Run(nil) // fail 1
	breaker.Run(nil) // fail 2
	if _, err := breaker.Run(nil); err != nil {
		t.Fatalf("expected success on the third call, got %v", err)
	}

	// Error count is back to zero, so two more failures must not trip a
	// threshold of three.
	flaky.failFrom = 4
	breaker.Run(nil)
	if _, err := breaker.Run(nil); err != nil && err.Error() == "breaker opened" {
		t.Fatal("breaker opened early: the success did not reset the count")
	}
}

type flakyScript struct {
	calls     int
	failUntil int
	failFrom  int
}

func (s *flakyScript) Run(keys []string, args ...interface{}) (interface{}, error) {
	s.calls++
	if s.calls <= s.failUntil || (s.failFrom > 0 && s.calls >= s.failFrom) {
		return nil, fmt.Errorf("redis unreachable")
	}
	return "ok", nil
}
