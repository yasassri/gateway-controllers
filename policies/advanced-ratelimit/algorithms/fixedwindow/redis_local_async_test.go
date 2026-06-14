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
	"sync/atomic"
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
	// Fast-fail timeouts so the Redis-down tests don't spend seconds on dial retries.
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func newAsyncLimiter(t *testing.T, client redis.UniversalClient, limit int64, failOpen bool, clk limiter.Clock) *RedisLocalAsyncLimiter {
	t.Helper()
	backing := NewRedisLimiter(client, NewPolicy(limit, time.Minute), "ratelimit:v1:")
	lim := NewRedisLocalAsyncLimiter(backing, LocalAsyncConfig{SyncInterval: testNoAutoFlush, FailOpen: failOpen})
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
	lim := NewRedisLocalAsyncLimiter(backing, LocalAsyncConfig{SyncInterval: testNoAutoFlush, FailOpen: true})
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
	lim := NewRedisLocalAsyncLimiter(backing, LocalAsyncConfig{SyncInterval: 5 * time.Millisecond, FailOpen: true})
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

func inActiveSet(c *flushCoordinator, shard int, l *RedisLocalAsyncLimiter) bool {
	c.shards[shard].mu.Lock()
	defer c.shards[shard].mu.Unlock()
	_, ok := c.shards[shard].active[l]
	return ok
}

// TestRedisLocalAsync_Coordinator drives a non-started coordinator manually and checks
// the active-set lifecycle: inactive until traffic, flushed + removed by a due tick,
// re-activated by new traffic.
func TestRedisLocalAsync_Coordinator(t *testing.T) {
	_, client := runMiniredis(t)
	coord := newFlushCoordinator(1, false) // not started; we call tickShard directly
	clk := limiter.NewFixedClock(time.Unix(9000, 0))
	backing := NewRedisLimiter(client, NewPolicy(100, time.Minute), "ratelimit:v1:")
	lim := newRedisLocalAsyncLimiterWith(backing, LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: true}, coord)
	lim.WithClock(clk)
	defer lim.Close()
	ws := NewPolicy(100, time.Minute).WindowStart(clk.Now())

	if inActiveSet(coord, 0, lim) {
		t.Fatal("limiter should be inactive before any traffic")
	}
	mustAllow(t, lim, "k")
	mustAllow(t, lim, "k")
	if !inActiveSet(coord, 0, lim) {
		t.Fatal("limiter should be active after traffic")
	}
	if redisCount(t, client, "k", ws) != 0 {
		t.Fatal("no flush should have happened before a tick")
	}

	// A due tick flushes and removes the limiter from the active set.
	coord.tickShard(0, time.Now().Add(time.Hour))
	if got := redisCount(t, client, "k", ws); got != 2 {
		t.Fatalf("tick should flush 2, got %d", got)
	}
	if inActiveSet(coord, 0, lim) {
		t.Fatal("limiter should be inactive after a clean flush")
	}

	// New traffic re-activates it.
	mustAllow(t, lim, "k")
	if !inActiveSet(coord, 0, lim) {
		t.Fatal("new traffic should re-activate the limiter")
	}
}

// TestRedisLocalAsync_PipelineSpill: with a small MaxPipelineCommands, one flush cannot
// drain all dirty keys; it reports more=true and subsequent flushes finish without
// losing any counts.
func TestRedisLocalAsync_PipelineSpill(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(11000, 0))
	backing := NewRedisLimiter(client, NewPolicy(100000, time.Minute), "ratelimit:v1:")
	lim := newRedisLocalAsyncLimiterWith(backing,
		LocalAsyncConfig{SyncInterval: testNoAutoFlush, FailOpen: true, MaxPipelineCommands: 8},
		newFlushCoordinator(1, false))
	lim.WithClock(clk)
	defer lim.Close()
	ws := NewPolicy(100000, time.Minute).WindowStart(clk.Now())

	const n = 20
	for i := 0; i < n; i++ {
		mustAllow(t, lim, fmt.Sprintf("k%d", i))
	}
	if !lim.flushPending() {
		t.Fatal("first flush should report more=true (budget 8 < 20 keys)")
	}
	for lim.flushPending() { // drain the spill
	}
	total := 0
	for i := 0; i < n; i++ {
		total += int(redisCount(t, client, fmt.Sprintf("k%d", i), ws))
	}
	if total != n {
		t.Fatalf("spill lost counts: total %d, want %d", total, n)
	}
}

// TestRedisLocalAsync_EvictionCarriesDelta: when a key is evicted to bound local state,
// its un-flushed delta is carried to Redis (not lost). stripeCap=1 forces an eviction.
func TestRedisLocalAsync_EvictionCarriesDelta(t *testing.T) {
	_, client := runMiniredis(t)
	clk := limiter.NewFixedClock(time.Unix(13000, 0))
	backing := NewRedisLimiter(client, NewPolicy(100000, time.Minute), "ratelimit:v1:")
	lim := newRedisLocalAsyncLimiterWith(backing,
		LocalAsyncConfig{SyncInterval: testNoAutoFlush, FailOpen: true, MaxLocalEntries: 16}, // stripeCap = 1
		newFlushCoordinator(1, false))
	lim.WithClock(clk)
	defer lim.Close()
	ws := NewPolicy(100000, time.Minute).WindowStart(clk.Now())

	a := "key-a"
	// Find a key b in the same stripe as a, so allowing b evicts a.
	var b string
	for i := 0; b == ""; i++ {
		cand := fmt.Sprintf("key-b-%d", i)
		if cand != a && lim.stripeFor(cand) == lim.stripeFor(a) {
			b = cand
		}
	}
	mustAllow(t, lim, a) // a: localDelta 1
	mustAllow(t, lim, b) // evicts a (delta carried to evictedPending); b: localDelta 1
	lim.flushPending()

	if got := redisCount(t, client, a, ws); got != 1 {
		t.Fatalf("evicted key's delta was lost: a count = %d, want 1", got)
	}
	if got := redisCount(t, client, b, ws); got != 1 {
		t.Fatalf("b count = %d, want 1", got)
	}
}

// pipeCounter is a go-redis Hook that counts pipeline executions (== Redis round-trips on
// a single-node client) and the commands within them.
type pipeCounter struct {
	pipelines atomic.Int64
	commands  atomic.Int64
}

func (h *pipeCounter) DialHook(next redis.DialHook) redis.DialHook       { return next }
func (h *pipeCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (h *pipeCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.pipelines.Add(1)
		h.commands.Add(int64(len(cmds)))
		return next(ctx, cmds)
	}
}

// TestRedisLocalAsync_BatchSingleRoundTrip is the v3 regression guard: two limiters
// sharing one Redis client flush in ONE pipeline per shard tick (not one per limiter).
func TestRedisLocalAsync_BatchSingleRoundTrip(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	hook := &pipeCounter{}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DisableIdentity: true})
	client.AddHook(hook)
	t.Cleanup(func() { _ = client.Close() })

	coord := newFlushCoordinator(1, false)
	clk := limiter.NewFixedClock(time.Unix(15000, 0)) // far past -> no EXPIRE pipeline
	mk := func() *RedisLocalAsyncLimiter {
		b := NewRedisLimiter(client, NewPolicy(1000, time.Minute), "ratelimit:v1:")
		l := newRedisLocalAsyncLimiterWith(b, LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: true}, coord)
		l.WithClock(clk)
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	a, b := mk(), mk()
	ws := NewPolicy(1000, time.Minute).WindowStart(clk.Now())
	for i := 0; i < 3; i++ {
		mustAllow(t, a, "ka")
	}
	for i := 0; i < 4; i++ {
		mustAllow(t, b, "kb")
	}

	hook.pipelines.Store(0)
	hook.commands.Store(0)
	coord.tickShard(0, time.Now().Add(time.Hour))

	if p := hook.pipelines.Load(); p != 1 {
		t.Fatalf("two limiters should flush in ONE pipeline, got %d", p)
	}
	if c := hook.commands.Load(); c != 2 {
		t.Fatalf("one INCRBY per limiter expected (2), got %d", c)
	}
	if got := redisCount(t, client, "ka", ws); got != 3 {
		t.Fatalf("a count = %d, want 3", got)
	}
	if got := redisCount(t, client, "kb", ws); got != 4 {
		t.Fatalf("b count = %d, want 4", got)
	}
}

// TestRedisLocalAsync_BatchFailIsolation: in a batch spanning two Redis clients, a limiter
// on a dead client fails (fail-closed denies) while a limiter on a healthy client flushes
// cleanly and keeps serving.
func TestRedisLocalAsync_BatchFailIsolation(t *testing.T) {
	mr1, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr1.Close)
	mr2, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	fast := func(addr string) *redis.Client {
		return redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	}
	c1, c2 := fast(mr1.Addr()), fast(mr2.Addr())
	t.Cleanup(func() { _ = c1.Close() })
	t.Cleanup(func() { _ = c2.Close() })

	coord := newFlushCoordinator(1, false)
	clk := limiter.NewFixedClock(time.Unix(16000, 0))
	a := newRedisLocalAsyncLimiterWith(NewRedisLimiter(c1, NewPolicy(1000, time.Minute), "ratelimit:v1:"),
		LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: true}, coord)
	a.WithClock(clk)
	t.Cleanup(func() { _ = a.Close() })
	b := newRedisLocalAsyncLimiterWith(NewRedisLimiter(c2, NewPolicy(100, time.Minute), "ratelimit:v1:"),
		LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: false}, coord)
	b.WithClock(clk)
	t.Cleanup(func() { _ = b.Close() })
	wsA := NewPolicy(1000, time.Minute).WindowStart(clk.Now())

	mustAllow(t, a, "ka")
	mustAllow(t, b, "kb")
	mr2.Close() // B's Redis goes down; A's stays up

	// Two ticks so B's fail streak reaches the fail-closed threshold.
	for i := 0; i < failClosedThreshold; i++ {
		coord.tickShard(0, time.Now().Add(time.Duration(i+1)*time.Hour))
	}

	if got := redisCount(t, c1, "ka", wsA); got != 1 {
		t.Fatalf("A (healthy client) should have flushed: count = %d", got)
	}
	if !mustAllow(t, a, "ka") {
		t.Fatal("A on a healthy client should still allow")
	}
	if mustAllow(t, b, "kb") {
		t.Fatal("B on a dead client (fail-closed) should deny")
	}
}

// TestRedisLocalAsync_BatchPerLimiterSpill: a per-limiter MaxPipelineCommands bounds each
// limiter's contribution to the shared batch; the rest spills to later ticks with no loss.
func TestRedisLocalAsync_BatchPerLimiterSpill(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	hook := &pipeCounter{}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DisableIdentity: true})
	client.AddHook(hook)
	t.Cleanup(func() { _ = client.Close() })

	coord := newFlushCoordinator(1, false)
	clk := limiter.NewFixedClock(time.Unix(17000, 0))
	a := newRedisLocalAsyncLimiterWith(NewRedisLimiter(client, NewPolicy(100000, time.Minute), "ratelimit:v1:"),
		LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: true, MaxPipelineCommands: 8}, coord)
	a.WithClock(clk)
	t.Cleanup(func() { _ = a.Close() })
	b := newRedisLocalAsyncLimiterWith(NewRedisLimiter(client, NewPolicy(100000, time.Minute), "ratelimit:v1:bb:"),
		LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: true}, coord)
	b.WithClock(clk)
	t.Cleanup(func() { _ = b.Close() })
	wsA := NewPolicy(100000, time.Minute).WindowStart(clk.Now())

	const na = 20
	for i := 0; i < na; i++ {
		mustAllow(t, a, fmt.Sprintf("ka%d", i))
	}
	mustAllow(t, b, "kb")

	hook.pipelines.Store(0)
	hook.commands.Store(0)
	coord.tickShard(0, time.Now().Add(time.Hour))

	// One pipeline carrying A's budget (8) + B's 1 = 9 commands.
	if p := hook.pipelines.Load(); p != 1 {
		t.Fatalf("first tick pipelines = %d, want 1", p)
	}
	if c := hook.commands.Load(); c != 9 {
		t.Fatalf("first tick commands = %d, want 9 (8+1)", c)
	}
	if !inActiveSet(coord, 0, a) {
		t.Fatal("A should be re-enqueued (spill)")
	}
	if inActiveSet(coord, 0, b) {
		t.Fatal("B should be done (no spill)")
	}

	// Drain the rest of A.
	for i := 0; i < 6 && inActiveSet(coord, 0, a); i++ {
		coord.tickShard(0, time.Now().Add(time.Duration(i+2)*time.Hour))
	}
	total := 0
	for i := 0; i < na; i++ {
		total += int(redisCount(t, client, fmt.Sprintf("ka%d", i), wsA))
	}
	if total != na {
		t.Fatalf("spill lost or double-counted: total %d, want %d", total, na)
	}
}

// TestRedisLocalAsync_FailClosedRecoversAfterRedisOutage is the regression guard for the
// fail-closed stuck-deny bug: after a Redis outage that spans a window boundary, a
// fail-closed limiter must resume serving once Redis recovers — it must NOT stay latched in
// permanent denial. Reproduces the production (coordinator) path deterministically:
// miniredis.SetError simulates Redis down/up, the fixed clock rolls the window, and the
// non-started coordinator is driven by tickShard at future times (always due). On the
// unfixed code the final Allow stays denied (limiter de-enqueued + redisDown never cleared).
func TestRedisLocalAsync_FailClosedRecoversAfterRedisOutage(t *testing.T) {
	mr, client := runMiniredis(t)
	coord := newFlushCoordinator(1, false) // not started; we drive tickShard directly
	clk := limiter.NewFixedClock(time.Unix(20000, 0))
	// limit 100 >> the few requests below, so the LOCAL deny-cache ("blocked") never latches:
	// the only path that can deny here is the fail-closed redisDown latch — exactly what we test.
	backing := NewRedisLimiter(client, NewPolicy(100, time.Minute), "ratelimit:v1:")
	lim := newRedisLocalAsyncLimiterWith(backing,
		LocalAsyncConfig{SyncInterval: 10 * time.Millisecond, FailOpen: false}, coord)
	lim.WithClock(clk)
	defer lim.Close()

	// ft returns an always-due tick time (far past every limiter's nextFlushAt deadline).
	ft := func(i int) time.Time { return time.Now().Add(time.Duration(i) * time.Hour) }

	// Phase 1 — healthy: one allow flushes cleanly to Redis.
	mustAllow(t, lim, "k")
	coord.tickShard(0, ft(1))

	// Phase 2 — Redis down: a fresh delta plus a streak of failed flushes latches redisDown.
	mr.SetError("redis down")
	mustAllow(t, lim, "k") // redisDown not set yet -> allowed, marks the key dirty
	for i := 0; i <= failClosedThreshold; i++ {
		coord.tickShard(0, ft(2+i))
	}
	if mustAllow(t, lim, "k") {
		t.Fatal("fail-closed should deny while Redis is down")
	}

	// Phase 3 — window rollover during the outage: the stale dirty delta is dropped, so the
	// limiter's subsequent flush snapshots are empty (the trigger for the stuck state).
	clk.Set(clk.Now().Add(2 * time.Minute))
	mustAllow(t, lim, "k") // rolls local state to the new window; still denied (redisDown)
	for i := 0; i < 3; i++ {
		coord.tickShard(0, ft(10+i))
	}
	if mustAllow(t, lim, "k") {
		t.Fatal("still denied while Redis is down")
	}

	// Phase 4 — Redis recovers. A healthy limiter must re-evaluate connectivity and resume,
	// even though it has no pending deltas to flush.
	mr.SetError("")
	for i := 0; i < 3; i++ {
		coord.tickShard(0, ft(20+i))
	}

	// The pin: with the bug the limiter is de-enqueued with redisDown stuck true, so this
	// stays denied forever; with the fix the empty-batch probe clears redisDown and it allows.
	if !mustAllow(t, lim, "k") {
		t.Fatal("REGRESSION: fail-closed limiter stuck denying after Redis recovered")
	}
}
