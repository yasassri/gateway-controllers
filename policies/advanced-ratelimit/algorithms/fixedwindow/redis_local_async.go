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
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// DefaultSyncInterval is the flush cadence used when none is configured. 50ms keeps the
// overshoot small (≈0 in our 2-replica tests) at a negligible flush rate; raise it via
// config for very high key cardinality where flush load (active_keys × replicas /
// interval) matters more than tight accuracy.
const DefaultSyncInterval = 50 * time.Millisecond

// probePingTimeout bounds the liveness PING a fail-closed limiter issues when it has no
// deltas to flush but redisDown is latched (see probeRedisLocked). There is no useful work
// to wait on, so keep it short: fail fast and stay latched until Redis is actually reachable.
const probePingTimeout = time.Second

// DefaultMaxLocalEntries bounds the per-limiter local key-state map (across all stripes)
// to cap memory under high/adversarial key cardinality (per-IP / per-user keys).
const DefaultMaxLocalEntries = 100000

// DefaultMaxPipelineCommands bounds how many INCRBYs one flush issues in a single Redis
// pipeline; excess dirty keys spill to the next flush tick.
const DefaultMaxPipelineCommands = 5000

// failClosedThreshold is the number of consecutive failed flush ticks after which a
// fail-closed limiter starts denying traffic (until a flush succeeds again). A small
// threshold (>1) avoids flapping on a single transient Redis error.
const failClosedThreshold = 2

// numStripes shards a limiter's local state to remove single-mutex serialization of a
// route's keys. Power of two for mask indexing.
const numStripes = 16

// LocalAsyncConfig configures a RedisLocalAsyncLimiter. Zero values take the defaults.
type LocalAsyncConfig struct {
	SyncInterval        time.Duration // <=0 -> DefaultSyncInterval
	FailOpen            bool
	MaxLocalEntries     int // <=0 -> DefaultMaxLocalEntries (per-limiter, across stripes)
	FlushWorkers        int // 0 -> auto (GOMAXPROCS/2, cap 8); only the FIRST registrant wins
	MaxPipelineCommands int // <=0 -> DefaultMaxPipelineCommands
}

func (c LocalAsyncConfig) withDefaults() LocalAsyncConfig {
	if c.SyncInterval <= 0 {
		c.SyncInterval = DefaultSyncInterval
	}
	if c.MaxLocalEntries <= 0 {
		c.MaxLocalEntries = DefaultMaxLocalEntries
	}
	if c.MaxPipelineCommands <= 0 {
		c.MaxPipelineCommands = DefaultMaxPipelineCommands
	}
	return c
}

// localState is the per-key counting state for the CURRENT window on this replica.
type localState struct {
	windowStart time.Time
	globalBase  int64 // last authoritative count read back from Redis (incl. our flushed deltas)
	localDelta  int64 // requests counted locally since the last successful flush
	blocked     bool  // true once the global count is known to have reached the limit this window
}

// pendingFlush is a snapshot of one key's un-flushed delta and the window it belongs to.
type pendingFlush struct {
	key      string
	redisKey string // keyPrefix+key+windowStart; filled at snapshot/evict so a
	// limiter-agnostic batch exec can format-free. The limiter's keyPrefix is private.
	flushN  int64
	ws      time.Time
	evicted bool // delta came from an evicted state; do not deduct localDelta on apply
}

// expireEntry is a freshly-created window key that needs a TTL set.
type expireEntry struct {
	redisKey  string
	windowEnd time.Time
}

// stripe holds one shard of a limiter's local state.
type stripe struct {
	mu             sync.Mutex
	states         map[string]*localState
	dirty          map[string]struct{}
	evictedPending []pendingFlush // deltas carried out of evicted states, owed to Redis
}

// RedisLocalAsyncLimiter implements fixed-window rate limiting with an in-memory hot
// path and asynchronous reconciliation against Redis.
//
// Every request is decided locally (no Redis round-trip) from an estimate of the global
// count, globalBase+localDelta. A shared flush coordinator periodically flushes the
// accumulated local deltas to the SAME Redis key the pure-redis backend uses (atomic
// INCRBY, batched in a pipeline) every syncInterval and reads back the authoritative
// count, so all replicas converge on the shared quota with bounded overshoot
// (≈ limit + (replicas-1)·rate·syncInterval).
//
// State is sharded across numStripes stripes (no single-mutex serialization) and capped
// at MaxLocalEntries (LRU-ish eviction carries any unflushed delta to Redis). A single
// process-wide coordinator with a small worker pool drives all limiters' flushes instead
// of a goroutine+client per limiter, and within a shard tick it batches every due
// limiter's deltas into ONE INCRBY pipeline per Redis client (plus one EXPIRE pipeline) —
// so Redis round-trips are O(shards·clients) per interval, not O(active limiters).
//
// Only the commutative counting path (Allow/AllowN) is local. The cost-extraction
// methods (GetAvailable/ConsumeOrClampN/ConsumeN) are inherited from the embedded
// *RedisLimiter and remain synchronous so their atomic Lua/CAS semantics are unchanged.
//
// Concurrency invariants:
//  1. Lock order: flushMu -> one stripe.mu at a time (never two). coordShard.mu is never
//     held together with flushMu or stripe.mu. coordinator.mu (intervals) is never held
//     while calling limiter methods. A batched flush holds several limiters' flushMu at
//     once, but only ever from one shard worker, acquired with no other lock held, and a
//     shard never ticks concurrently with itself (timer reset after work) — so there is no
//     cycle regardless of acquisition order. No cycles.
//  2. Lost-wakeup prevention: AllowN marks a stripe dirty BEFORE the `enqueued` CAS;
//     tickShard removes the limiter from its shard's active set and clears `enqueued`
//     (under coordShard.mu) BEFORE snapshotPendingLocked drains it. `enqueued` is cleared
//     nowhere else. So every delta is either snapshotted now or re-enqueued for next tick.
//  3. flushMu serializes all flushes for a limiter (coordinator worker, Close drain,
//     tests) so out-of-order INCRBY results cannot regress globalBase. failStreak and
//     flushCursor are guarded by flushMu.
//  4. cfg/coord/shard are immutable after the constructor returns.
type RedisLocalAsyncLimiter struct {
	*RedisLimiter // backing limiter: Redis client, policy, key scheme, clock, cost methods

	cfg       LocalAsyncConfig
	stripeCap int

	stripes [numStripes]stripe

	enqueued    atomic.Bool  // member of the coordinator shard's active set
	nextFlushAt atomic.Int64 // unix nanos; when this limiter is next due to flush
	redisDown   atomic.Bool  // fail-closed: Redis considered down -> deny on the hot path

	flushMu     sync.Mutex // serializes flushPending
	failStreak  int        // guarded by flushMu
	flushCursor int        // rotating stripe start for the pipeline budget; guarded by flushMu

	coord     *flushCoordinator
	shard     int
	closeOnce sync.Once
}

// NewRedisLocalAsyncLimiter wraps a fixed-window RedisLimiter with a local-first,
// async-reconcile counting path, registering it with the process-wide flush coordinator.
// Callers MUST Close() it (the policy's limiter cache does this on reload/teardown) to
// deregister and drain.
func NewRedisLocalAsyncLimiter(backing *RedisLimiter, cfg LocalAsyncConfig) *RedisLocalAsyncLimiter {
	return newRedisLocalAsyncLimiterWith(backing, cfg, defaultFlushCoordinator(resolveFlushWorkers(cfg.FlushWorkers)))
}

// newRedisLocalAsyncLimiterWith is the testable constructor: it accepts an explicit
// coordinator (e.g. a non-started one tests drive via tickShard).
func newRedisLocalAsyncLimiterWith(backing *RedisLimiter, cfg LocalAsyncConfig, coord *flushCoordinator) *RedisLocalAsyncLimiter {
	cfg = cfg.withDefaults()
	r := &RedisLocalAsyncLimiter{
		RedisLimiter: backing,
		cfg:          cfg,
		stripeCap:    max(1, cfg.MaxLocalEntries/numStripes),
		coord:        coord,
	}
	for i := range r.stripes {
		r.stripes[i].states = make(map[string]*localState)
		r.stripes[i].dirty = make(map[string]struct{})
	}
	r.shard = coord.register(r)
	// Not due until one interval from now, so a freshly registered limiter is never
	// flushed by the coordinator before it has any traffic (keeps tests deterministic).
	r.nextFlushAt.Store(coord.now().Add(cfg.SyncInterval).UnixNano())
	return r
}

// WithClock sets a custom clock (for testing). Set before first use; not safe to call
// concurrently with traffic (matches the embedded RedisLimiter contract).
func (r *RedisLocalAsyncLimiter) WithClock(clock limiter.Clock) *RedisLocalAsyncLimiter {
	r.RedisLimiter.WithClock(clock)
	return r
}

func (r *RedisLocalAsyncLimiter) stripeFor(key string) *stripe {
	// FNV-1a, no allocation.
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &r.stripes[h&(numStripes-1)]
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

	now := r.clock.Now()
	windowStart := r.policy.WindowStart(now)
	windowEnd := r.policy.WindowEnd(now)
	limit := r.policy.Limit

	s := r.stripeFor(key)
	s.mu.Lock()

	st, ok := s.states[key]
	if !ok || !st.windowStart.Equal(windowStart) {
		if !ok {
			r.ensureCapacityLocked(s, now) // evict before inserting a new key
		}
		st = &localState{windowStart: windowStart}
		s.states[key] = st
	}

	needEnqueue := len(s.evictedPending) > 0
	allowed := false
	switch {
	case st.blocked:
		// Local deny cache: global count already reached the limit this window.
	case !r.cfg.FailOpen && r.redisDown.Load():
		// Fail-closed and Redis is down: block rather than admit un-reconciled traffic.
		// Stay enqueued so the coordinator keeps probing for recovery — redisDown only
		// clears via a flush/probe, which only runs while the limiter is enqueued. Without
		// this, a denied request would add no work and never re-arm the limiter.
		needEnqueue = true
	case st.globalBase+st.localDelta+n > limit:
		// Estimate would exceed the limit; latch the deny cache for this window.
		st.blocked = true
	default:
		allowed = true
		st.localDelta += n
		if n > 0 {
			s.dirty[key] = struct{}{}
			needEnqueue = true
		}
	}

	remaining := limit - (st.globalBase + st.localDelta)
	if remaining < 0 {
		remaining = 0
	}
	s.mu.Unlock()

	// Enqueue with the coordinator on the clean->dirty transition (idempotent CAS).
	if needEnqueue && r.enqueued.CompareAndSwap(false, true) {
		r.coord.markActive(r)
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

// ensureCapacityLocked evicts an entry if the stripe is at capacity, carrying any
// unflushed delta to evictedPending so the count is not lost. Caller holds s.mu.
func (r *RedisLocalAsyncLimiter) ensureCapacityLocked(s *stripe, now time.Time) {
	if len(s.states) < r.stripeCap {
		return
	}
	// 1. Expired sweep first.
	r.evictExpiredLocked(s, now)
	if len(s.states) < r.stripeCap {
		return
	}
	// 2. Approximate-random victim (Go map iteration is randomized); prefer a
	//    fully-flushed (localDelta==0) entry, else the first scanned.
	var vk string
	var vst *localState
	scanned := 0
	for k, st := range s.states {
		if vk == "" {
			vk, vst = k, st
		}
		if st.localDelta == 0 {
			vk, vst = k, st
			break
		}
		if scanned++; scanned >= 8 {
			break
		}
	}
	if vk != "" {
		r.evictLocked(s, vk, vst)
	}
}

func (r *RedisLocalAsyncLimiter) evictLocked(s *stripe, k string, st *localState) {
	if st.localDelta > 0 {
		if len(s.evictedPending) < 2*r.stripeCap {
			s.evictedPending = append(s.evictedPending, pendingFlush{
				key: k, redisKey: r.redisKeyFor(k, st.windowStart),
				flushN: st.localDelta, ws: st.windowStart, evicted: true,
			})
		} else {
			slog.Warn("FixedWindow(redis-local-async): evictedPending full, dropping delta",
				"key", k, "delta", st.localDelta)
		}
	}
	delete(s.states, k)
	delete(s.dirty, k)
}

// evictExpiredLocked removes states for windows that ended over a minute ago and have no
// un-flushed delta. Caller holds s.mu.
func (r *RedisLocalAsyncLimiter) evictExpiredLocked(s *stripe, now time.Time) {
	for k, st := range s.states {
		if st.localDelta == 0 && now.After(st.windowStart.Add(r.policy.Duration).Add(time.Minute)) {
			delete(s.states, k)
			delete(s.dirty, k)
		}
	}
}

// redisKeyFor formats the per-window Redis key for a logical key.
func (r *RedisLocalAsyncLimiter) redisKeyFor(key string, ws time.Time) string {
	return fmt.Sprintf("%s%s:%d", r.keyPrefix, key, ws.UnixNano())
}

// flushPending pushes this limiter's accumulated local deltas to Redis and reconciles
// globalBase. It is the single synchronous flush, called by Close()'s drain and by tests;
// the coordinator composes the same phases across many limiters (one pipeline per client).
// Returns more=true if a budget spill or error residue leaves work for the next tick.
func (r *RedisLocalAsyncLimiter) flushPending() (more bool) {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	batch, more := r.snapshotPendingLocked(r.cfg.MaxPipelineCommands)
	if len(batch) == 0 {
		// No deltas to flush. If we're fail-closed and latched down, still probe Redis so
		// redisDown can clear after recovery even with nothing to flush (the coordinator's
		// flushDue does the same — see its empty-batch branch).
		if !r.cfg.FailOpen && r.redisDown.Load() {
			r.probeRedisLocked()
		}
		return more
	}
	cmds, execErrs := execIncrBatch(r.client, batch, 0) // chunkSize 0 = single Exec, as before
	applyMore, creators, tickErr := r.applyResultsLocked(batch, cmds, execErrs)
	if applyMore {
		more = true
	}
	execExpire(r.client, r.expireEntries(batch, creators))
	r.noteFlushOutcomeLocked(tickErr)
	return more
}

// probeRedisLocked re-checks Redis connectivity for a fail-closed limiter that has latched
// redisDown but currently has no pending deltas to flush (e.g. its dirty delta was dropped
// on a window rollover during the outage). Without it, such a limiter would never issue
// another Redis op, so redisDown could never clear after Redis recovered — stranding the
// limiter in permanent denial. The verdict is routed through noteFlushOutcomeLocked so
// failStreak/redisDown stay flushMu-guarded (invariant 3). PING is a *connectivity* probe,
// not a *writeability* one: partial failures (read-only replica, OOM, ACL) will flap rather
// than stick, which the failClosedThreshold anti-flap already tolerates. Caller holds flushMu.
func (r *RedisLocalAsyncLimiter) probeRedisLocked() {
	ctx, cancel := context.WithTimeout(context.Background(), probePingTimeout)
	defer cancel()
	r.noteFlushOutcomeLocked(r.client.Ping(ctx).Err() != nil)
}

// snapshotPendingLocked drains up to `budget` pending entries (evicted first, then dirty,
// across stripes from a rotating cursor), filling each entry's redisKey, and evicts
// expired states. Caller must hold r.flushMu.
func (r *RedisLocalAsyncLimiter) snapshotPendingLocked(budget int) (batch []pendingFlush, more bool) {
	now := r.clock.Now()
	batch = make([]pendingFlush, 0, 64)
	for i := 0; i < numStripes; i++ {
		if budget <= 0 {
			more = true
			break
		}
		s := &r.stripes[(r.flushCursor+i)%numStripes]
		s.mu.Lock()
		// Evicted deltas are already owed to Redis (redisKey already set): drain first.
		if len(s.evictedPending) > 0 {
			take := len(s.evictedPending)
			if take > budget {
				take = budget
			}
			batch = append(batch, s.evictedPending[:take]...)
			s.evictedPending = append(s.evictedPending[:0], s.evictedPending[take:]...)
			budget -= take
			if len(s.evictedPending) > 0 {
				more = true
			}
		}
		for k := range s.dirty {
			if budget <= 0 {
				more = true
				break
			}
			st := s.states[k]
			if st == nil || st.localDelta == 0 {
				delete(s.dirty, k)
				continue
			}
			batch = append(batch, pendingFlush{
				key: k, redisKey: r.redisKeyFor(k, st.windowStart),
				flushN: st.localDelta, ws: st.windowStart,
			})
			delete(s.dirty, k)
			budget--
		}
		r.evictExpiredLocked(s, now)
		s.mu.Unlock()
	}
	r.flushCursor = (r.flushCursor + 1) % numStripes
	return batch, more
}

// execIncrBatch issues the batch's INCRBYs in one pipeline (chunked at chunkSize; <=0 =
// single Exec). It returns each command and a PER-ENTRY exec error: execErrs[i] is the
// Exec error of entry i's chunk (nil on success). On a chunk failure the remaining chunks
// are NOT executed and inherit the same error — so an already-applied earlier chunk is
// never mistaken for failed (which would double-count its deltas on retry).
func execIncrBatch(client redis.UniversalClient, batch []pendingFlush, chunkSize int) (cmds []*redis.IntCmd, execErrs []error) {
	n := len(batch)
	cmds = make([]*redis.IntCmd, n)
	execErrs = make([]error, n)
	step := chunkSize
	if step <= 0 || step > n {
		step = n
	}
	ctx := context.Background() // bounded by the client's read/write timeouts
	var aborted error
	for start := 0; start < n; start += step {
		end := start + step
		if end > n {
			end = n
		}
		if aborted != nil { // a prior chunk failed; these never executed
			for i := start; i < end; i++ {
				execErrs[i] = aborted
			}
			continue
		}
		pipe := client.Pipeline()
		for i := start; i < end; i++ {
			cmds[i] = pipe.IncrBy(ctx, batch[i].redisKey, batch[i].flushN)
		}
		_, err := pipe.Exec(ctx)
		for i := start; i < end; i++ {
			execErrs[i] = err
		}
		if err != nil {
			aborted = err
		}
	}
	return cmds, execErrs
}

// applyResultsLocked reconciles each entry's INCRBY result into local state (one stripe
// lock at a time). Caller must hold r.flushMu. Returns whether work remains, the batch
// indices that created their window key, and whether any command failed.
func (r *RedisLocalAsyncLimiter) applyResultsLocked(batch []pendingFlush, cmds []*redis.IntCmd, execErrs []error) (more bool, creators []int, tickErr bool) {
	for i, p := range batch {
		var newGlobal int64
		var err error
		switch {
		case execErrs[i] != nil:
			err = execErrs[i]
		case cmds[i] != nil:
			newGlobal, err = cmds[i].Result()
		default:
			err = fmt.Errorf("redis-local-async: missing result for %s", p.redisKey)
		}

		s := r.stripeFor(p.key)
		if err != nil {
			tickErr = true
			more = true
			s.mu.Lock()
			if p.evicted {
				if len(s.evictedPending) < 2*r.stripeCap {
					s.evictedPending = append(s.evictedPending, p)
				}
			} else if st := s.states[p.key]; st != nil && st.windowStart.Equal(p.ws) {
				s.dirty[p.key] = struct{}{} // keep the delta for retry
			}
			s.mu.Unlock()
			continue
		}
		if newGlobal == p.flushN {
			creators = append(creators, i)
		}
		s.mu.Lock()
		if st := s.states[p.key]; st != nil && st.windowStart.Equal(p.ws) {
			st.globalBase = newGlobal
			if !p.evicted {
				st.localDelta -= p.flushN
				if st.localDelta < 0 {
					st.localDelta = 0
				}
			}
			if newGlobal >= r.policy.Limit {
				st.blocked = true
			}
			if st.localDelta != 0 {
				s.dirty[p.key] = struct{}{} // more arrived during the flush
				more = true
			}
		}
		s.mu.Unlock()
	}
	return more, creators, tickErr
}

// expireEntries builds the TTL-set list for the freshly-created window keys (creators).
func (r *RedisLocalAsyncLimiter) expireEntries(batch []pendingFlush, creators []int) []expireEntry {
	if len(creators) == 0 {
		return nil
	}
	out := make([]expireEntry, 0, len(creators))
	for _, i := range creators {
		out = append(out, expireEntry{redisKey: batch[i].redisKey, windowEnd: batch[i].ws.Add(r.policy.Duration)})
	}
	return out
}

// execExpire sets the (jittered) TTL on freshly-created window keys in one pipeline.
// TTLs already in the past are skipped (preserves the FixedClock test behaviour). Failures
// are log-only.
func execExpire(client redis.UniversalClient, entries []expireEntry) {
	if len(entries) == 0 {
		return
	}
	ctx := context.Background()
	pipe := client.Pipeline()
	issued := false
	for _, e := range entries {
		jitter := time.Duration(rand.Int63n(int64(5 * time.Second)))
		ttl := time.Until(e.windowEnd) + jitter
		if ttl > 0 {
			pipe.Expire(ctx, e.redisKey, ttl)
			issued = true
		}
	}
	if issued {
		if _, err := pipe.Exec(ctx); err != nil {
			slog.Warn("FixedWindow(redis-local-async): EXPIRE pipeline failed", "error", err)
		}
	}
}

// noteFlushOutcomeLocked updates the fail streak / fail-closed flag from a flush outcome.
// Caller must hold r.flushMu.
func (r *RedisLocalAsyncLimiter) noteFlushOutcomeLocked(tickErr bool) {
	if tickErr {
		r.failStreak++
		r.redisDown.Store(!r.cfg.FailOpen && r.failStreak >= failClosedThreshold)
	} else {
		r.failStreak = 0
		r.redisDown.Store(false)
	}
}

// Close deregisters the limiter from the coordinator, drains remaining local deltas to
// Redis, and releases the backing limiter. Safe to call multiple times.
func (r *RedisLocalAsyncLimiter) Close() error {
	r.closeOnce.Do(func() {
		r.coord.deregister(r)
		// Final drain. Bounded so a Redis outage (persistent more=true) can't spin.
		for i := 0; i <= numStripes && r.flushPending(); i++ {
		}
	})
	return r.RedisLimiter.Close()
}
