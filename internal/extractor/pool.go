package extractor

import (
	"context"
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// Pool exécute l'extraction sur des workers dédiés (séparés du scan).
type Pool struct {
	extractor *Extractor
	jobs      chan extractJob
	jobWg     sync.WaitGroup
	workerWg  sync.WaitGroup
	workers   int
}

type extractJob struct {
	target  models.ScanTarget
	finding models.Finding
}

func NewPool(ex *Extractor, workers int) *Pool {
	if workers < 1 {
		workers = 2
	}
	return &Pool{
		extractor: ex,
		jobs:      make(chan extractJob, 4096),
		workers:   workers,
	}
}

// Start lance les workers d'extraction.
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.workerWg.Add(1)
		go p.worker(ctx)
	}
}

func (p *Pool) worker(ctx context.Context) {
	defer p.workerWg.Done()
	for job := range p.jobs {
		p.extractor.ExtractFromFinding(ctx, job.target, job.finding)
		p.jobWg.Done()
	}
}

// Submit met une extraction en file (ne bloque pas les workers de scan).
func (p *Pool) Submit(target models.ScanTarget, finding models.Finding) {
	p.jobWg.Add(1)
	go func() {
		p.jobs <- extractJob{target: target, finding: finding}
	}()
}

// CloseAndWait attend la fin de toutes les extractions puis arrête les workers.
func (p *Pool) CloseAndWait() {
	p.jobWg.Wait()
	close(p.jobs)
	p.workerWg.Wait()
}
