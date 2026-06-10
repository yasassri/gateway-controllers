/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package fixedwindow

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// DefaultSyncInterval is the flush cadence used when none is configured. 50ms keeps the
// overshoot small (≈0 in our 2-replica tests) at a negligible flush rate; raise it via
// config for very high key cardinality where flush load (active_keys × replicas /
// interval) matters more than tight accuracy.
const DefaultSyncInterval = 50 * time.Millisecond

// failClosedThreshold is the number of consecutive failed flush ticks after which a
// fail-closed limiter starts denying traffic (until a flush succeeds again). A small
// threshold (>1) avoids flapping on a single transient Redis error.
const failClosedThreshold = 2

// localState is the per-key counting state for the CURRENT window on this replica.
type localState struct {
	windowStart time.Time
	globalBase  int64 // last authoritative count read back from Redis (incl. our flushed deltas)
	localDelta  int64 // requests counted locally since the last successful flush
	blocked     bool  // true once the global count is known to have reached the limit this window
}

// RedisLocalAsyncLimiter implements fixed-window rate limiting with an in-memory hot
// path and asynchronous reconciliation against Redis.
//
// Every request is decided locally (no Redis round-trip) from an estimate of the global
// count, globalBase+localDelta. A background goroutine flushes the accumulated local
// deltas to the SAME Redis key the pure-redis backend uses (atomic INCRBY) every
// syncInterval and reads back the authoritative count, so all replicas converge on the
// shared quota with bounded overshoot (≈ limit + (replicas-1)·rate·syncInterval).
//
// Only the commutative counting path (Allow/AllowN) is local. The cost-extraction
// methods (GetAvailable/ConsumeOrClampN/ConsumeN) are inherited from the embedded
// *RedisLimiter and remain synchronous so their atomic Lua/CAS semantics are unchanged.
type RedisLocalAsyncLimiter struct {
	*RedisLimiter // backing limiter: Redis client, policy, key scheme, clock, cost methods

	syncEvery time.Duration
	failOpen  bool

	mu     sync.Mutex
	states map[string]*localState
	dirty  map[string]struct{} // keys with an un-flushed localDelta

	failStreak int  // consecutive failed flush ticks
	redisDown  bool // fail-closed: Redis considered down -> deny on the hot path

	ticker    *time.Ticker
	done      chan struct{}
	closeOnce sync.Once
}

// NewRedisLocalAsyncLimiter wraps a fixed-window RedisLimiter with a local-first,
// async-reconcile counting path. backing supplies the Redis client, policy, key prefix
// and clock. It starts the background flusher; callers MUST Close() it (the policy's
// limiter cache does this on reload/teardown) to stop the goroutine and drain.
func NewRedisLocalAsyncLimiter(backing *RedisLimiter, syncEvery time.Duration, failOpen bool) *RedisLocalAsyncLimiter {
	if syncEvery <= 0 {
		syncEvery = DefaultSyncInterval
	}
	r := &RedisLocalAsyncLimiter{
		RedisLimiter: backing,
		syncEvery:    syncEvery,
		failOpen:     failOpen,
		states:       make(map[string]*localState),
		dirty:        make(map[string]struct{}),
		done:         make(chan struct{}),
	}
	r.ticker = time.NewTicker(syncEvery)
	go r.flushLoop()
	return r
}

// WithClock sets a custom clock (for testing). It updates the embedded RedisLimiter's
// clock, which the local hot path and flusher also read.
func (r *RedisLocalAsyncLimiter) WithClock(clock limiter.Clock) *RedisLocalAsyncLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.RedisLimiter.WithClock(clock)
	return r
}

// Allow checks if a single request is allowed for the given key.
func (r *RedisLocalAsyncLimiter) Allow(ctx context.Context, key string) (*limiter.Result, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN decides locally whether N requests are allowed, from the current estimate of
// the global count (globalBase + localDelta). It never touches Redis.
func (r *RedisLocalAsyncLimiter) AllowN(_ context.Context, key string, n int64) (*limiter.Result, error) {
	if n < 0 {
		n = 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock.Now()
	windowStart := r.policy.WindowStart(now)
	windowEnd := r.policy.WindowEnd(now)
	limit := r.policy.Limit

	st, ok := r.states[key]
	if !ok || !st.windowStart.Equal(windowStart) {
		// New key, or a new window for an existing key: start fresh. Any residual
		// un-flushed delta from a now-closed window is dropped (bounded by one sync
		// interval of traffic and only affects an already-expired window).
		st = &localState{windowStart: windowStart}
		r.states[key] = st
	}

	allowed := false
	switch {
	case st.blocked:
		// Local deny cache: global count already reached the limit this window.
	case !r.failOpen && r.redisDown:
		// Fail-closed and Redis is down: block rather than admit un-reconciled traffic.
	case st.globalBase+st.localDelta+n > limit:
		// Estimate would exceed the limit; latch the deny cache for this window.
		st.blocked = true
	default:
		allowed = true
		st.localDelta += n
		if n > 0 {
			r.dirty[key] = struct{}{}
		}
	}

	remaining := limit - (st.globalBase + st.localDelta)
	if remaining < 0 {
		remaining = 0
	}

	result := &limiter.Result{
		Allowed:   allowed,
		Requested: n,
		Consumed:  boolToCount(allowed && n > 0, n),
		Overflow:  boolToCount(!allowed && n > 0, n),
		Limit:     limit,
		Remaining: remaining,
		Reset:     windowEnd,
		Duration:  r.policy.Duration,
		Policy:    r.policy,
	}
	if !allowed {
		result.RetryAfter = time.Until(windowEnd)
		if result.RetryAfter < 0 {
			result.RetryAfter = 0
		}
	}
	return result, nil
}

// flushLoop runs the background reconciliation until Close().
func (r *RedisLocalAsyncLimiter) flushLoop() {
	for {
		select {
		case <-r.ticker.C:
			r.flushPending()
		case <-r.done:
			return
		}
	}
}

// pendingFlush is a snapshot of one key's un-flushed delta and the window it belongs to.
type pendingFlush struct {
	key    string
	flushN int64
	ws     time.Time
}

// flushPending pushes accumulated local deltas to Redis and reconciles globalBase.
// Each dirty key's delta is written to the key for the window it was counted in (NOT
// "now"), so a flush that lands just after a window roll updates the correct (old) key.
func (r *RedisLocalAsyncLimiter) flushPending() {
	// 1. Snapshot dirty keys under lock; evict fully-flushed expired states.
	r.mu.Lock()
	batch := make([]pendingFlush, 0, len(r.dirty))
	for k := range r.dirty {
		st := r.states[k]
		if st == nil || st.localDelta == 0 {
			delete(r.dirty, k)
			continue
		}
		batch = append(batch, pendingFlush{key: k, flushN: st.localDelta, ws: st.windowStart})
		delete(r.dirty, k) // re-added below on failure
	}
	r.evictExpiredLocked()
	r.mu.Unlock()

	// 2. Reconcile each key against Redis outside the lock.
	tickErr := false
	for _, p := range batch {
		redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, p.key, p.ws.UnixNano())
		ctx := context.Background() // bounded by the client's read/write timeouts

		newGlobal, err := r.client.IncrBy(ctx, redisKey, p.flushN).Result()
		if err == nil && newGlobal == p.flushN {
			// First creator of this window key: set TTL with 0-5s jitter to spread
			// expirations (mirrors the pure-redis backend).
			jitter := time.Duration(rand.Int63n(int64(5 * time.Second)))
			ttl := time.Until(p.ws.Add(r.policy.Duration)) + jitter
			if ttl > 0 {
				if expErr := r.client.Expire(ctx, redisKey, ttl).Err(); expErr != nil {
					slog.Warn("FixedWindow(redis-local-async): EXPIRE failed", "redisKey", redisKey, "error", expErr)
				}
			}
		}

		r.mu.Lock()
		st := r.states[p.key]
		if err != nil {
			tickErr = true
			slog.Warn("FixedWindow(redis-local-async): flush INCRBY failed", "redisKey", redisKey, "error", err)
			if st != nil {
				r.dirty[p.key] = struct{}{} // keep the delta for retry next tick
			}
			r.mu.Unlock()
			continue
		}
		if st != nil && st.windowStart.Equal(p.ws) {
			st.globalBase = newGlobal
			st.localDelta -= p.flushN
			if st.localDelta < 0 {
				st.localDelta = 0
			}
			if newGlobal >= r.policy.Limit {
				st.blocked = true
			}
			if st.localDelta != 0 {
				r.dirty[p.key] = struct{}{} // more arrived during the flush
			}
		}
		// If the window rolled over (st.windowStart != p.ws), the INCRBY already updated
		// the correct old-window key in Redis; the new window's state is independent.
		r.mu.Unlock()
	}

	// 3. Update the fail streak (drives fail-closed blocking).
	r.mu.Lock()
	if tickErr {
		r.failStreak++
		if !r.failOpen && r.failStreak >= failClosedThreshold {
			r.redisDown = true
		}
	} else {
		r.failStreak = 0
		r.redisDown = false
	}
	r.mu.Unlock()
}

// evictExpiredLocked removes states for windows that ended over a minute ago and have no
// un-flushed delta. Caller must hold r.mu.
func (r *RedisLocalAsyncLimiter) evictExpiredLocked() {
	now := r.clock.Now()
	for k, st := range r.states {
		windowEnd := st.windowStart.Add(r.policy.Duration)
		if st.localDelta == 0 && now.After(windowEnd.Add(time.Minute)) {
			delete(r.states, k)
			delete(r.dirty, k)
		}
	}
}

// Close stops the flusher, drains any remaining local deltas to Redis, and releases the
// backing limiter. Safe to call multiple times.
func (r *RedisLocalAsyncLimiter) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		if r.ticker != nil {
			r.ticker.Stop()
		}
		// Final drain so un-flushed local deltas are not lost on shutdown.
		r.flushPending()
	})
	return r.RedisLimiter.Close()
}
