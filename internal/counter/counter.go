package counter

import "sync/atomic"

// Counter is a thread-safe counter using atomic operations
type Counter struct {
	value uint64
}

// Increment atomically increments the counter by 1
func (c *Counter) Increment() {
	atomic.AddUint64(&c.value, 1)
}

// Get atomically returns the current counter value
func (c *Counter) Get() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Reset atomically resets the counter to 0
func (c *Counter) Reset() {
	atomic.StoreUint64(&c.value, 0)
}
