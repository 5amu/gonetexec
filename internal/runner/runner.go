package runner

import (
	"context"
	"sync"
)

type Runner interface {
	Start(context.Context) error
	Stop()
}

type RunnerOptions struct {
	StopOnError   bool
	StopOnSuccess bool
	Threads       int
}

const DefaultThreads = 20

func ParallelRun(ctx context.Context, runners []Runner, opts *RunnerOptions) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if opts == nil {
		opts = &RunnerOptions{
			StopOnError:   false,
			StopOnSuccess: false,
			Threads:       10,
		}
	} else if opts.Threads <= 0 {
		opts.Threads = DefaultThreads
	}

	errC := make(chan error)
	guard := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for _, r := range runners {
		guard <- struct{}{}
		wg.Add(1)
		go func(r Runner) {
			if err := r.Start(childCtx); err != nil {
				if opts.StopOnError {
					errC <- err
				}
			} else {
				if opts.StopOnSuccess {
					errC <- nil
				}
			}
			<-guard
			wg.Done()
		}(r)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case err := <-errC:
		cancel()
		return err
	case <-done:
		return nil
	}
}
