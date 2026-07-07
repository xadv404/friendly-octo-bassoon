package botapp

import "sync"

type pendingQty struct {
	mu   sync.Mutex
	data map[int64]string
}

func newPendingQty() *pendingQty {
	return &pendingQty{data: make(map[int64]string)}
}

func (p *pendingQty) Set(userID int64, provider string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data[userID] = provider
}

func (p *pendingQty) Get(userID int64) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prov, ok := p.data[userID]
	return prov, ok
}

func (p *pendingQty) Clear(userID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.data, userID)
}
