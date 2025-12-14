// QUAC 100 Concurrent Operations Demo (Go)
//
// Demonstrates concurrent cryptographic operations using goroutines:
// - Parallel key generation
// - Concurrent KEM operations
// - Worker pool pattern
//
// Build: go build -o concurrent concurrent.go
// Run:   ./concurrent
//
// Copyright 2025 Dyber, Inc. All Rights Reserved.

package main

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Simulated QUAC operations
type SimulatedDevice struct {
	mu sync.Mutex
}

func (d *SimulatedDevice) KEMKeygen() (pk, sk []byte, err error) {
	// Simulate 65µs operation
	time.Sleep(65 * time.Microsecond)
	pk = make([]byte, 1184)
	sk = make([]byte, 2400)
	rand.Read(pk)
	rand.Read(sk)
	return pk, sk, nil
}

func (d *SimulatedDevice) KEMEncaps(pk []byte) (ct, ss []byte, err error) {
	// Simulate 35µs operation
	time.Sleep(35 * time.Microsecond)
	ct = make([]byte, 1088)
	ss = make([]byte, 32)
	rand.Read(ct)
	rand.Read(ss)
	return ct, ss, nil
}

func (d *SimulatedDevice) SignKeygen() (pk, sk []byte, err error) {
	// Simulate 130µs operation
	time.Sleep(130 * time.Microsecond)
	pk = make([]byte, 1952)
	sk = make([]byte, 4032)
	rand.Read(pk)
	rand.Read(sk)
	return pk, sk, nil
}

// Result holds operation result
type Result struct {
	Operation string
	Duration  time.Duration
	Error     error
}

// ============================================================================
// Parallel Key Generation
// ============================================================================

func parallelKeygen(device *SimulatedDevice, count int) []Result {
	results := make([]Result, count)
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			opStart := time.Now()
			_, sk, err := device.KEMKeygen()
			results[idx] = Result{
				Operation: fmt.Sprintf("keygen-%d", idx),
				Duration:  time.Since(opStart),
				Error:     err,
			}
			// Secure cleanup
			for j := range sk {
				sk[j] = 0
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(start)

	fmt.Printf("  Generated %d keypairs in %v\n", count, totalDuration)
	fmt.Printf("  Average: %v per operation\n", totalDuration/time.Duration(count))
	fmt.Printf("  Throughput: %.0f ops/sec\n", float64(count)/totalDuration.Seconds())

	return results
}

// ============================================================================
// Worker Pool Pattern
// ============================================================================

type Job struct {
	ID        int
	Operation string
}

type Worker struct {
	ID       int
	Device   *SimulatedDevice
	Jobs     <-chan Job
	Results  chan<- Result
	Done     chan<- bool
}

func (w *Worker) Start() {
	go func() {
		for job := range w.Jobs {
			start := time.Now()
			var err error

			switch job.Operation {
			case "keygen":
				_, sk, e := w.Device.KEMKeygen()
				err = e
				for i := range sk {
					sk[i] = 0
				}
			case "encaps":
				pk := make([]byte, 1184)
				rand.Read(pk)
				_, _, e := w.Device.KEMEncaps(pk)
				err = e
			case "sign-keygen":
				_, sk, e := w.Device.SignKeygen()
				err = e
				for i := range sk {
					sk[i] = 0
				}
			}

			w.Results <- Result{
				Operation: fmt.Sprintf("%s-%d", job.Operation, job.ID),
				Duration:  time.Since(start),
				Error:     err,
			}
		}
		w.Done <- true
	}()
}

func workerPoolDemo(device *SimulatedDevice, numWorkers, numJobs int) {
	jobs := make(chan Job, numJobs)
	results := make(chan Result, numJobs)
	done := make(chan bool, numWorkers)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		worker := Worker{
			ID:      i,
			Device:  device,
			Jobs:    jobs,
			Results: results,
			Done:    done,
		}
		worker.Start()
	}

	// Submit jobs
	start := time.Now()
	operations := []string{"keygen", "encaps", "sign-keygen"}
	for i := 0; i < numJobs; i++ {
		jobs <- Job{
			ID:        i,
			Operation: operations[i%len(operations)],
		}
	}
	close(jobs)

	// Wait for workers
	for i := 0; i < numWorkers; i++ {
		<-done
	}
	close(results)

	// Collect results
	var totalOps int64
	var errorCount int64
	for result := range results {
		totalOps++
		if result.Error != nil {
			errorCount++
		}
	}

	totalDuration := time.Since(start)
	fmt.Printf("  Workers: %d\n", numWorkers)
	fmt.Printf("  Jobs: %d\n", numJobs)
	fmt.Printf("  Total time: %v\n", totalDuration)
	fmt.Printf("  Throughput: %.0f ops/sec\n", float64(totalOps)/totalDuration.Seconds())
	fmt.Printf("  Errors: %d\n", errorCount)
}

// ============================================================================
// Pipeline Pattern
// ============================================================================

func pipelineDemo(device *SimulatedDevice, count int) {
	// Stage 1: Generate keypairs
	keypairs := make(chan struct {
		pk, sk []byte
	}, count)

	// Stage 2: Encapsulate
	encaps := make(chan struct {
		ct, ss []byte
	}, count)

	var ops int64
	start := time.Now()

	// Stage 1 goroutine - Key generation
	go func() {
		for i := 0; i < count; i++ {
			pk, sk, _ := device.KEMKeygen()
			keypairs <- struct {
				pk, sk []byte
			}{pk, sk}
			atomic.AddInt64(&ops, 1)
		}
		close(keypairs)
	}()

	// Stage 2 goroutine - Encapsulation
	go func() {
		for kp := range keypairs {
			ct, ss, _ := device.KEMEncaps(kp.pk)
			encaps <- struct {
				ct, ss []byte
			}{ct, ss}
			atomic.AddInt64(&ops, 1)

			// Secure cleanup
			for i := range kp.sk {
				kp.sk[i] = 0
			}
		}
		close(encaps)
	}()

	// Consume results
	var resultCount int
	for range encaps {
		resultCount++
	}

	totalDuration := time.Since(start)
	fmt.Printf("  Pipeline processed %d items\n", resultCount)
	fmt.Printf("  Total operations: %d\n", atomic.LoadInt64(&ops))
	fmt.Printf("  Total time: %v\n", totalDuration)
	fmt.Printf("  Throughput: %.0f items/sec\n", float64(resultCount)/totalDuration.Seconds())
}

// ============================================================================
// Main
// ============================================================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("  QUAC 100 Concurrent Operations Demo (Go)")
	fmt.Println("================================================================")
	fmt.Println()

	device := &SimulatedDevice{}

	// Demo 1: Parallel Key Generation
	fmt.Println("1. Parallel Key Generation")
	fmt.Println("-" + "--------------------------")
	fmt.Println("  Generating 100 ML-KEM-768 keypairs in parallel...")
	fmt.Println()
	parallelKeygen(device, 100)
	fmt.Println()

	// Demo 2: Worker Pool
	fmt.Println("2. Worker Pool Pattern")
	fmt.Println("-" + "----------------------")
	fmt.Println("  Processing mixed operations with worker pool...")
	fmt.Println()
	workerPoolDemo(device, 4, 50)
	fmt.Println()

	// Demo 3: Pipeline
	fmt.Println("3. Pipeline Pattern")
	fmt.Println("-" + "-------------------")
	fmt.Println("  Running keygen -> encaps pipeline...")
	fmt.Println()
	pipelineDemo(device, 50)
	fmt.Println()

	// Summary
	fmt.Println("================================================================")
	fmt.Println("  Concurrency Patterns Demonstrated")
	fmt.Println("================================================================")
	fmt.Println()
	fmt.Println("  1. Parallel Execution:")
	fmt.Println("     - Launch many goroutines for independent operations")
	fmt.Println("     - Ideal for batch key generation")
	fmt.Println()
	fmt.Println("  2. Worker Pool:")
	fmt.Println("     - Fixed number of workers processing job queue")
	fmt.Println("     - Bounds resource usage while maximizing throughput")
	fmt.Println()
	fmt.Println("  3. Pipeline:")
	fmt.Println("     - Chain operations through channels")
	fmt.Println("     - Each stage processes concurrently")
	fmt.Println()
	fmt.Println("Note: QUAC 100 hardware supports multiple concurrent operations")
	fmt.Println("with hardware-level parallelism for even higher throughput.")
	fmt.Println("================================================================")
}