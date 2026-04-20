package runner

import (
	"context"
	"sync"
)

type Runner interface {
	Start(context.Context) error
	Stop()
}

func ParallelRun(ctx context.Context, runners []Runner, stopOnError bool, threads int) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errC := make(chan error)
	guard := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, r := range runners {
		guard <- struct{}{}
		wg.Add(1)
		go func(r Runner) {
			if err := r.Start(childCtx); err != nil {
				if stopOnError {
					errC <- err
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
