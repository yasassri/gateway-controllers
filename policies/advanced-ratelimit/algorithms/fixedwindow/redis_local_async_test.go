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
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// A sync interval long enough that the background flusher never fires during a test;
// tests drive reconciliation deterministically by calling flushPending() directly.
const testNoAutoFlush = time.Hour

func runMiniredis(t *testing.T) (*miniredis.Miniredis, redis.UniversalClient) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func newAsyncLimiter(t *testing.T, client redis.UniversalClient, limit int64, failOpen bool, clk limiter.Clock) *RedisLocalAsyncLimiter {
	t.Helper()
	backing := NewRedisLimiter(client, NewPolicy(limit, time.Minute), "ratelimit:v1:")
	lim := NewRedisLocalAsyncLimiter(backing, testNoAutoFlush, failOpen)
	if clk != nil {
		lim.WithClock(clk)
	}
	t.Cleanup(func() { _ = lim.Close() })
	return lim
}

// redisCount returns the integer value stored at the rate-limit key for (key, window).
func redisCount(t *testing.T, client redis.UniversalClient, key string, ws time.Time) int64 {
	t.Helper()
	redisKey := fmt.Sprintf("ratelimit:v1:%s:%d", key, ws.UnixNano())
	v, err := client.Get(context.Background(), redisKey).Int64()
	if err == redis.Nil {
		return 0
	}
	if err != nil {
		t.Fatalf("redis GET %s: %v", redisKey, err)
	}
	return v
}

func mustAllow(t *testing.T, lim *RedisLocalAsyncLimiter, key string) bool {
	t.Helper()
	res, err := lim.Allow(context.Background(), key)
	if err != nil {
		t.Fatalf("Allow(%s): %v", key, err)
	}
	return res.Allowed
}

// TestRedisLocalAsync_OptimisticAllowNoRedis: the hot path decides locally and issues
// NO Redis op until a flush; the flush then writes the accumulated delta.
func TestRedisLocalAsync_OptimisticAllowNoRedis(t *testing.T) {
	mr, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(1000, 0))
	lim := newAsyncLimiter(t, client, 10, true, clk)
	ws := NewPolicy(10, time.Minute).WindowStart(clk.Now())

	for i := 0; i < 5; i++ {
		if !mustAllow(t, lim, "k") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected no Redis keys before flush, got %v", keys)
	}

	lim.flushPending()

	if got := redisCount(t, client, "k", ws); got != 5 {
		t.Fatalf("after flush, Redis count = %d, want 5", got)
	}
}

// TestRedisLocalAsync_FlushReconcile: globalBase is updated from Redis after a flush so
// remaining reflects the authoritative count.
func TestRedisLocalAsync_FlushReconcile(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(2000, 0))
	lim := newAsyncLimiter(t, client, 10, true, clk)

	for i := 0; i < 4; i++ {
		mustAllow(t, lim, "k")
	}
	lim.flushPending()

	avail, err := lim.GetAvailable(context.Background(), "k")
	if err != nil {
		t.Fatalf("GetAvailable: %v", err)
	}
	if avail != 6 {
		t.Fatalf("available after 4 allowed of 10 = %d, want 6", avail)
	}
}

// TestRedisLocalAsync_TwoInstancesConverge: two replicas sharing one Redis each admit up
// to the limit before any reconcile (worst-case overshoot ≈ R×limit), then BOTH block
// once a flush makes the shared count reach the limit.
func TestRedisLocalAsync_TwoInstancesConverge(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(3000, 0))
	a := newAsyncLimiter(t, client, 10, true, clk)
	b := newAsyncLimiter(t, client, 10, true, clk)

	// Before any reconcile each replica counts independently: 10 + 10 admitted.
	for i := 0; i < 10; i++ {
		if !mustAllow(t, a, "k") {
			t.Fatalf("A request %d should be allowed pre-reconcile", i)
		}
		if !mustAllow(t, b, "k") {
			t.Fatalf("B request %d should be allowed pre-reconcile", i)
		}
	}

	// Reconcile: shared Redis count becomes 20 (>= limit) -> both latch blocked.
	a.flushPending()
	b.flushPending()

	if mustAllow(t, a, "k") {
		t.Fatal("A should be blocked after reconcile (global >= limit)")
	}
	if mustAllow(t, b, "k") {
		t.Fatal("B should be blocked after reconcile (global >= limit)")
	}

	ws := NewPolicy(10, time.Minute).WindowStart(clk.Now())
	if got := redisCount(t, client, "k", ws); got != 20 {
		t.Fatalf("shared Redis count = %d, want 20", got)
	}
}

// TestRedisLocalAsync_DenyCacheNoRedis: once a key is known over-limit, denied requests
// short-circuit locally and never touch Redis (no further INCRBY).
func TestRedisLocalAsync_DenyCacheNoRedis(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(4000, 0))
	lim := newAsyncLimiter(t, client, 10, true, clk)
	ws := NewPolicy(10, time.Minute).WindowStart(clk.Now())

	for i := 0; i < 10; i++ {
		mustAllow(t, lim, "k")
	}
	lim.flushPending() // global = 10 -> blocked latched
	countAfterLimit := redisCount(t, client, "k", ws)
	if countAfterLimit != 10 {
		t.Fatalf("Redis count = %d, want 10", countAfterLimit)
	}

	// Denied requests must not increment Redis.
	for i := 0; i < 5; i++ {
		if mustAllow(t, lim, "k") {
			t.Fatalf("request %d past limit should be denied", i)
		}
	}
	lim.flushPending()
	if got := redisCount(t, client, "k", ws); got != countAfterLimit {
		t.Fatalf("denied requests changed Redis count: %d -> %d", countAfterLimit, got)
	}
}

// TestRedisLocalAsync_WindowRollover: a new window resets local counting and writes a new
// (distinct) Redis key.
func TestRedisLocalAsync_WindowRollover(t *testing.T) {
	mr, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(5000, 0))
	lim := newAsyncLimiter(t, client, 10, true, clk)
	p := NewPolicy(10, time.Minute)
	ws1 := p.WindowStart(clk.Now())

	for i := 0; i < 10; i++ {
		mustAllow(t, lim, "k")
	}
	lim.flushPending()
	if mustAllow(t, lim, "k") {
		t.Fatal("request past limit in window 1 should be denied")
	}

	// Advance into the next window.
	clk.Set(clk.Now().Add(time.Minute))
	ws2 := p.WindowStart(clk.Now())
	if ws1.Equal(ws2) {
		t.Fatal("expected a new window after advancing the clock")
	}
	if !mustAllow(t, lim, "k") {
		t.Fatal("first request in the new window should be allowed")
	}
	lim.flushPending()

	if got := redisCount(t, client, "k", ws2); got != 1 {
		t.Fatalf("new-window Redis count = %d, want 1", got)
	}
	if len(mr.Keys()) != 2 {
		t.Fatalf("expected 2 distinct window keys, got %v", mr.Keys())
	}
}

// TestRedisLocalAsync_FailOpenDegradesToPerReplica: when Redis is down and failOpen=true,
// the limiter keeps serving from the LOCAL estimate (per-replica enforcement) rather than
// admitting unlimited traffic.
func TestRedisLocalAsync_FailOpenDegradesToPerReplica(t *testing.T) {
	mr, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(6000, 0))
	lim := newAsyncLimiter(t, client, 10, true, clk)

	// Redis goes away.
	mr.Close()

	// Local estimate still enforces the per-replica limit: 10 allowed, 11th denied.
	allowed := 0
	for i := 0; i < 15; i++ {
		if mustAllow(t, lim, "k") {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("fail-open should still enforce per-replica limit: allowed %d, want 10", allowed)
	}
	// Flush fails but must not panic or block; limiter stays usable.
	lim.flushPending()
}

// TestRedisLocalAsync_FailClosedBlocks: when Redis is down and failOpen=false, sustained
// flush failures flip the limiter to deny.
func TestRedisLocalAsync_FailClosedBlocks(t *testing.T) {
	mr, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(7000, 0))
	lim := newAsyncLimiter(t, client, 100, false, clk) // high limit so local never blocks

	if !mustAllow(t, lim, "k") {
		t.Fatal("first request should be allowed while Redis is up")
	}

	mr.Close() // Redis down; the dirty key now fails to flush.
	for i := 0; i < failClosedThreshold; i++ {
		lim.flushPending()
	}

	if mustAllow(t, lim, "k") {
		t.Fatal("fail-closed: request should be denied after sustained flush failures")
	}
}

// TestRedisLocalAsync_CloseDrains: Close() flushes remaining local deltas (graceful
// shutdown) and is safe to call twice.
func TestRedisLocalAsync_CloseDrains(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(8000, 0))
	backing := NewRedisLimiter(client, NewPolicy(10, time.Minute), "ratelimit:v1:")
	lim := NewRedisLocalAsyncLimiter(backing, testNoAutoFlush, true)
	lim.WithClock(clk)
	ws := NewPolicy(10, time.Minute).WindowStart(clk.Now())

	for i := 0; i < 3; i++ {
		mustAllow(t, lim, "k")
	}
	if got := redisCount(t, client, "k", ws); got != 0 {
		t.Fatalf("expected nothing flushed before Close, Redis count = %d", got)
	}

	if err := lim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := redisCount(t, client, "k", ws); got != 3 {
		t.Fatalf("Close should drain 3 to Redis, count = %d", got)
	}
	if err := lim.Close(); err != nil { // idempotent
		t.Fatalf("second Close: %v", err)
	}
}

// TestRedisLocalAsync_Factory: the factory wires redis-local-async, and rejects a missing
// Redis client.
func TestRedisLocalAsync_Factory(t *testing.T) {
	_, client := runMiniredis(t)

	lim, err := NewLimiter(limiter.Config{
		Algorithm:   "fixed-window",
		Backend:     "redis-local-async",
		Limits:      []limiter.LimitConfig{{Limit: 5, Duration: time.Minute}},
		RedisClient: client,
		KeyPrefix:   "ratelimit:v1:",
		AlgorithmConfig: map[string]interface{}{
			"syncInterval": testNoAutoFlush,
			"failOpen":     true,
		},
	})
	if err != nil {
		t.Fatalf("NewLimiter(redis-local-async): %v", err)
	}
	if _, ok := lim.(*RedisLocalAsyncLimiter); !ok {
		t.Fatalf("expected *RedisLocalAsyncLimiter, got %T", lim)
	}
	_ = lim.Close()

	if _, err := NewLimiter(limiter.Config{
		Algorithm: "fixed-window",
		Backend:   "redis-local-async",
		Limits:    []limiter.LimitConfig{{Limit: 5, Duration: time.Minute}},
	}); err == nil {
		t.Fatal("expected error when redis client is missing")
	}
}

// TestRedisLocalAsync_Concurrent exercises the hot path and the flusher concurrently
// (run with -race).
func TestRedisLocalAsync_Concurrent(t *testing.T) {
	_, client := runMiniredis(t)
	backing := NewRedisLimiter(client, NewPolicy(100000, time.Minute), "ratelimit:v1:")
	lim := NewRedisLocalAsyncLimiter(backing, 5*time.Millisecond, true)
	defer lim.Close()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", g%3)
			for i := 0; i < 500; i++ {
				if _, err := lim.Allow(context.Background(), key); err != nil {
					t.Errorf("Allow: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
