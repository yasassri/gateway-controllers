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
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// flushCoordinator drives the flushes of ALL RedisLocalAsyncLimiters in the process from
// a small worker pool, instead of one goroutine+ticker per limiter. Each worker owns one
// shard; a limiter is assigned a shard at registration and enqueues itself on its shard's
// active set on the clean->dirty transition. A worker wakes on the base tick (the min
// registered sync interval, clamped) and flushes only the limiters whose per-limiter
// deadline (nextFlushAt) has passed — O(active), not O(registered).
type flushCoordinator struct {
	mu        sync.Mutex            // guards intervals, nextShard, started
	intervals map[time.Duration]int // refcount per registered sync interval
	nextShard int                   // round-robin shard assignment
	started   bool

	baseTick atomic.Int64 // nanos; clamp(min interval, 10ms, 1s); 1s when empty

	shards []coordShard
	stopCh chan struct{} // closed by stop() (manual/test coordinators only)
}

type coordShard struct {
	mu     sync.Mutex
	active map[*RedisLocalAsyncLimiter]struct{}
}

const (
	baseTickMin = 10 * time.Millisecond
	baseTickMax = time.Second
)

var (
	defaultCoordOnce sync.Once
	defaultCoord     *flushCoordinator
)

// resolveFlushWorkers maps a configured worker count (0 = auto) to a concrete count.
// Flushing is I/O-bound, so cap the pool small.
func resolveFlushWorkers(configured int) int {
	if configured > 0 {
		return configured
	}
	w := runtime.GOMAXPROCS(0) / 2
	if w < 1 {
		w = 1
	}
	if w > 8 {
		w = 8
	}
	return w
}

// defaultFlushCoordinator returns the process-wide singleton, started on first use with
// the given worker count. Later callers requesting a different count are warned and
// ignored (a restart is required to change flush_workers).
func defaultFlushCoordinator(workers int) *flushCoordinator {
	defaultCoordOnce.Do(func() {
		defaultCoord = newFlushCoordinator(workers, true)
	})
	if got := len(defaultCoord.shards); got != workers {
		slog.Warn("FixedWindow(redis-local-async): flush coordinator already started; ignoring conflicting flushWorkers (restart to change)",
			"running", got, "requested", workers)
	}
	return defaultCoord
}

// newFlushCoordinator creates a coordinator with the given worker count. When start is
// true it launches the worker goroutines; tests pass start=false and drive tickShard.
func newFlushCoordinator(workers int, start bool) *flushCoordinator {
	if workers < 1 {
		workers = 1
	}
	c := &flushCoordinator{
		intervals: make(map[time.Duration]int),
		shards:    make([]coordShard, workers),
		stopCh:    make(chan struct{}),
	}
	for i := range c.shards {
		c.shards[i].active = make(map[*RedisLocalAsyncLimiter]struct{})
	}
	c.baseTick.Store(int64(baseTickMax))
	if start {
		c.started = true
		for i := range c.shards {
			go c.workerLoop(i)
		}
	}
	return c
}

// now returns the coordinator's notion of wall-clock time (real time; the limiter's
// injectable clock is only for window math, not flush scheduling).
func (c *flushCoordinator) now() time.Time { return time.Now() }

func (c *flushCoordinator) register(l *RedisLocalAsyncLimiter) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.intervals[l.cfg.SyncInterval]++
	c.recomputeBaseTickLocked()
	if len(c.shards) == 1 {
		return 0
	}
	shard := c.nextShard % len(c.shards)
	c.nextShard++
	return shard
}

func (c *flushCoordinator) deregister(l *RedisLocalAsyncLimiter) {
	c.mu.Lock()
	if n := c.intervals[l.cfg.SyncInterval]; n <= 1 {
		delete(c.intervals, l.cfg.SyncInterval)
	} else {
		c.intervals[l.cfg.SyncInterval] = n - 1
	}
	c.recomputeBaseTickLocked()
	c.mu.Unlock()

	sh := &c.shards[l.shard]
	sh.mu.Lock()
	delete(sh.active, l)
	sh.mu.Unlock()
	l.enqueued.Store(false)
}

// markActive adds the limiter to its shard's active set. Called from AllowN on the
// clean->dirty transition (after the enqueued CAS), so it runs at most once per active
// period.
func (c *flushCoordinator) markActive(l *RedisLocalAsyncLimiter) {
	sh := &c.shards[l.shard]
	sh.mu.Lock()
	sh.active[l] = struct{}{}
	sh.mu.Unlock()
}

func (c *flushCoordinator) recomputeBaseTickLocked() {
	mn := baseTickMax
	for d := range c.intervals {
		if d < mn {
			mn = d
		}
	}
	if mn < baseTickMin {
		mn = baseTickMin
	}
	if mn > baseTickMax {
		mn = baseTickMax
	}
	c.baseTick.Store(int64(mn))
}

func (c *flushCoordinator) workerLoop(i int) {
	bt := time.Duration(c.baseTick.Load())
	// Stagger workers so Redis sees a smooth stream of small pipelines, not a burst.
	stagger := time.Duration(int64(bt) * int64(i) / int64(len(c.shards)))
	timer := time.NewTimer(bt + stagger)
	defer timer.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-timer.C:
			c.tickShard(i, time.Now())
			timer.Reset(time.Duration(c.baseTick.Load())) // reset AFTER work: single in-flight flush
		}
	}
}

// tickShard flushes all due limiters in shard i. Removing a limiter from the active set
// and clearing enqueued BEFORE flushing (invariant 2) ensures a concurrently-arriving
// delta re-enqueues the limiter rather than being stranded.
func (c *flushCoordinator) tickShard(i int, now time.Time) {
	sh := &c.shards[i]
	nowNanos := now.UnixNano()

	// Step 1 (lost-wakeup invariant): remove due limiters from the active set and clear
	// `enqueued` BEFORE snapshotting, so a concurrently-arriving delta re-enqueues.
	var due []*RedisLocalAsyncLimiter
	sh.mu.Lock()
	for l := range sh.active {
		if nowNanos >= l.nextFlushAt.Load() {
			delete(sh.active, l)
			l.enqueued.Store(false)
			due = append(due, l)
		}
	}
	sh.mu.Unlock()

	if len(due) > 0 {
		c.flushDue(sh, due, now)
	}
}

// limFlush is one limiter's contribution to a batched flush.
type limFlush struct {
	l     *RedisLocalAsyncLimiter
	batch []pendingFlush
	off   int             // offset into its client group's flat slice
	cmds  []*redis.IntCmd // demuxed view of the group's results
	errs  []error         // demuxed view of the group's per-entry exec errors
	more  bool
}

// clientGroup batches all due limiters that share one Redis client into one pipeline.
type clientGroup struct {
	client  redis.UniversalClient
	members []*limFlush
	flat    []pendingFlush
	exp     []expireEntry
}

// flushDue flushes all `due` limiters with one INCRBY pipeline (and one EXPIRE pipeline)
// PER Redis client, instead of one pipeline per limiter — collapsing round-trips from
// O(due) to O(clients). Each limiter's flushMu is held across snapshot->apply (so no other
// flush of it interleaves) and released before any re-enqueue (preserving lock-order
// invariant 1). Per-limiter fail-streak keeps fail-open/closed isolated across clients.
func (c *flushCoordinator) flushDue(sh *coordShard, due []*RedisLocalAsyncLimiter, now time.Time) {
	nowNanos := now.UnixNano()

	// A: lock each limiter and snapshot its pending work. Empty snapshots are released
	//    immediately (matches flushPending's early return: fail-streak untouched).
	flushes := make([]*limFlush, 0, len(due))
	for _, l := range due {
		l.nextFlushAt.Store(now.Add(l.cfg.SyncInterval).UnixNano())
		l.flushMu.Lock()
		batch, more := l.snapshotPendingLocked(l.cfg.MaxPipelineCommands)
		if len(batch) == 0 {
			// A fail-closed limiter that has latched redisDown but has nothing to flush
			// (its dirty delta was just dropped above on a window rollover during the
			// outage) must still probe Redis here, or redisDown could never clear after
			// recovery. This drop-then-probe MUST stay co-located in this critical section:
			// snapshotPendingLocked dropped the stale delta and we re-evaluate health in the
			// same flushMu hold, so a concurrent delta either was just snapshotted or will
			// re-enqueue us. Probe BEFORE releasing flushMu; re-enqueue AFTER (sh.mu must
			// never be held with flushMu — invariant 1).
			probeStillDown := false
			if !l.cfg.FailOpen && l.redisDown.Load() {
				l.probeRedisLocked()
				probeStillDown = l.redisDown.Load() // still down after the probe?
			}
			l.flushMu.Unlock()
			// Re-enqueue on a budget spill (more; defensive — unreachable today) or while a
			// fail-closed limiter is still down, so it keeps probing every tick until Redis
			// recovers (on a successful probe redisDown clears and it de-enqueues normally).
			if more || probeStillDown {
				l.nextFlushAt.Store(nowNanos)
				if l.enqueued.CompareAndSwap(false, true) {
					sh.mu.Lock()
					sh.active[l] = struct{}{}
					sh.mu.Unlock()
				}
			}
			continue
		}
		flushes = append(flushes, &limFlush{l: l, batch: batch, more: more})
	}
	if len(flushes) == 0 {
		return
	}

	// B: group by Redis client (insertion-ordered; client count is tiny).
	var groups []*clientGroup
	for _, f := range flushes {
		var g *clientGroup
		for _, cand := range groups {
			if cand.client == f.l.client {
				g = cand
				break
			}
		}
		if g == nil {
			g = &clientGroup{client: f.l.client}
			groups = append(groups, g)
		}
		f.off = len(g.flat)
		g.flat = append(g.flat, f.batch...)
		g.members = append(g.members, f)
	}

	// C: one INCRBY pipeline per client (chunked); demux results back to members.
	for _, g := range groups {
		cmds, errs := execIncrBatch(g.client, g.flat, DefaultMaxPipelineCommands)
		for _, f := range g.members {
			f.cmds = cmds[f.off : f.off+len(f.batch)]
			f.errs = errs[f.off : f.off+len(f.batch)]
		}
	}

	// D: apply per limiter + per-limiter fail streak; collect EXPIREs per group.
	for _, g := range groups {
		for _, f := range g.members {
			applyMore, creators, tickErr := f.l.applyResultsLocked(f.batch, f.cmds, f.errs)
			f.more = f.more || applyMore
			g.exp = append(g.exp, f.l.expireEntries(f.batch, creators)...)
			f.l.noteFlushOutcomeLocked(tickErr)
		}
	}

	// E: one EXPIRE pipeline per client for the freshly-created window keys.
	for _, g := range groups {
		execExpire(g.client, g.exp)
	}

	// F: release flushMu, THEN re-enqueue spilled limiters (release before sh.mu — keeps
	//    coordShard.mu out of the flushMu/stripe lock order).
	for _, f := range flushes {
		f.l.flushMu.Unlock()
		if f.more {
			f.l.nextFlushAt.Store(nowNanos)
			if f.l.enqueued.CompareAndSwap(false, true) {
				sh.mu.Lock()
				sh.active[f.l] = struct{}{}
				sh.mu.Unlock()
			}
		}
	}
}

// stop halts a coordinator's workers (manual/test coordinators only; the singleton runs
// for the process lifetime).
func (c *flushCoordinator) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		close(c.stopCh)
		c.started = false
	}
}
