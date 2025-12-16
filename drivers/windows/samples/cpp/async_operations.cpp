/*++

    QUAC 100 C++ Sample - Async Operations
    
    This sample demonstrates asynchronous cryptographic operations
    using the QUAC 100 driver's async API for high-throughput
    applications.
    
    Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

--*/

#include <iostream>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <functional>

#include <quac100lib.h>

#pragma comment(lib, "quac100.lib")

//
// Job completion callback type
//
using CompletionCallback = std::function<void(uint64_t jobId, QUAC_STATUS status, void* result)>;

//
// Async job manager class
//
class AsyncJobManager {
public:
    AsyncJobManager(QUAC_HANDLE device, size_t numThreads = 4)
        : m_device(device)
        , m_running(true)
    {
        // Start worker threads for polling job completion
        for (size_t i = 0; i < numThreads; i++) {
            m_workers.emplace_back(&AsyncJobManager::WorkerThread, this);
        }
    }
    
    ~AsyncJobManager() {
        // Signal shutdown
        m_running = false;
        m_cv.notify_all();
        
        // Wait for workers
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
    
    //
    // Submit an async KEM keygen job
    //
    uint64_t SubmitKemKeyGen(
        uint32_t algorithm,
        uint8_t* publicKey,
        uint8_t* secretKey,
        CompletionCallback callback
    ) {
        QUAC_ASYNC_SUBMIT submit = {};
        submit.OperationType = QUAC_OP_KEM_KEYGEN;
        submit.Priority = QUAC_PRIORITY_NORMAL;
        submit.Algorithm = algorithm;
        
        uint64_t jobId;
        QUAC_STATUS status = Quac100_AsyncSubmit(m_device, &submit, &jobId);
        
        if (status == QUAC_SUCCESS) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pendingJobs[jobId] = {
                callback,
                publicKey,
                secretKey,
                QUAC_OP_KEM_KEYGEN
            };
            m_cv.notify_one();
        }
        
        return (status == QUAC_SUCCESS) ? jobId : 0;
    }
    
    //
    // Submit an async signature job
    //
    uint64_t SubmitSign(
        uint32_t algorithm,
        const uint8_t* secretKey,
        const uint8_t* message,
        uint32_t messageLen,
        uint8_t* signature,
        uint32_t* signatureLen,
        CompletionCallback callback
    ) {
        QUAC_ASYNC_SUBMIT submit = {};
        submit.OperationType = QUAC_OP_SIGN;
        submit.Priority = QUAC_PRIORITY_NORMAL;
        submit.Algorithm = algorithm;
        // In real implementation, would include input data pointers
        
        uint64_t jobId;
        QUAC_STATUS status = Quac100_AsyncSubmit(m_device, &submit, &jobId);
        
        if (status == QUAC_SUCCESS) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pendingJobs[jobId] = {
                callback,
                signature,
                signatureLen,
                QUAC_OP_SIGN
            };
            m_cv.notify_one();
        }
        
        return (status == QUAC_SUCCESS) ? jobId : 0;
    }
    
    //
    // Cancel a pending job
    //
    bool Cancel(uint64_t jobId) {
        QUAC_STATUS status = Quac100_AsyncCancel(m_device, jobId);
        
        if (status == QUAC_SUCCESS) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pendingJobs.erase(jobId);
        }
        
        return (status == QUAC_SUCCESS);
    }
    
    //
    // Get number of pending jobs
    //
    size_t PendingCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pendingJobs.size();
    }
    
private:
    struct PendingJob {
        CompletionCallback callback;
        void* output1;
        void* output2;
        uint32_t opType;
    };
    
    void WorkerThread() {
        while (m_running) {
            uint64_t jobId = 0;
            PendingJob job;
            
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock, std::chrono::milliseconds(100), [this] {
                    return !m_running || !m_pendingJobs.empty();
                });
                
                if (!m_running && m_pendingJobs.empty()) {
                    break;
                }
                
                if (m_pendingJobs.empty()) {
                    continue;
                }
                
                // Get first pending job
                auto it = m_pendingJobs.begin();
                jobId = it->first;
                job = it->second;
            }
            
            // Poll for completion
            QUAC_ASYNC_POLL_OUTPUT pollResult;
            QUAC_STATUS status = Quac100_AsyncPoll(m_device, jobId, &pollResult);
            
            if (status == QUAC_SUCCESS) {
                if (pollResult.State == QUAC_JOB_STATE_COMPLETED ||
                    pollResult.State == QUAC_JOB_STATE_FAILED) {
                    
                    // Remove from pending
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_pendingJobs.erase(jobId);
                    }
                    
                    // Call completion callback
                    if (job.callback) {
                        job.callback(jobId, 
                            (pollResult.State == QUAC_JOB_STATE_COMPLETED) ? QUAC_SUCCESS : QUAC_ERROR_CRYPTO_FAILED,
                            job.output1);
                    }
                }
            }
        }
    }
    
    QUAC_HANDLE m_device;
    std::atomic<bool> m_running;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::thread> m_workers;
    std::map<uint64_t, PendingJob> m_pendingJobs;
};

//
// High-throughput batch processing example
//
class BatchProcessor {
public:
    BatchProcessor(QUAC_HANDLE device)
        : m_device(device)
        , m_jobManager(device, 4)
        , m_completed(0)
        , m_failed(0)
    {
    }
    
    //
    // Process a batch of KEM key generations
    //
    void ProcessKemKeyGenBatch(size_t count) {
        std::cout << "Submitting " << count << " async KEM keygen jobs..." << std::endl;
        
        // Allocate key buffers
        m_publicKeys.resize(count);
        m_secretKeys.resize(count);
        
        for (size_t i = 0; i < count; i++) {
            m_publicKeys[i].resize(KYBER768_PUBLIC_KEY_SIZE);
            m_secretKeys[i].resize(KYBER768_SECRET_KEY_SIZE);
        }
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Submit all jobs
        for (size_t i = 0; i < count; i++) {
            m_jobManager.SubmitKemKeyGen(
                QUAC_KEM_KYBER768,
                m_publicKeys[i].data(),
                m_secretKeys[i].data(),
                [this](uint64_t jobId, QUAC_STATUS status, void* result) {
                    if (status == QUAC_SUCCESS) {
                        m_completed++;
                    } else {
                        m_failed++;
                    }
                }
            );
        }
        
        // Wait for all to complete
        std::cout << "Waiting for completion..." << std::endl;
        while (m_completed + m_failed < count) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            // Progress update
            size_t done = m_completed + m_failed;
            if (done % 100 == 0) {
                std::cout << "\r  Progress: " << done << "/" << count << std::flush;
            }
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        std::cout << "\n\nResults:" << std::endl;
        std::cout << "  Completed: " << m_completed.load() << std::endl;
        std::cout << "  Failed: " << m_failed.load() << std::endl;
        std::cout << "  Total time: " << duration.count() << " ms" << std::endl;
        std::cout << "  Throughput: " << (count * 1000.0 / duration.count()) << " ops/sec" << std::endl;
    }
    
private:
    QUAC_HANDLE m_device;
    AsyncJobManager m_jobManager;
    std::vector<std::vector<uint8_t>> m_publicKeys;
    std::vector<std::vector<uint8_t>> m_secretKeys;
    std::atomic<size_t> m_completed;
    std::atomic<size_t> m_failed;
};

//
// Demo: Producer-Consumer pattern with async operations
//
void DemoProducerConsumer(QUAC_HANDLE device) {
    std::cout << "\n=== Producer-Consumer Async Demo ===" << std::endl;
    
    const size_t QUEUE_SIZE = 100;
    std::queue<std::vector<uint8_t>> randomQueue;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> producerDone(false);
    std::atomic<size_t> bytesProduced(0);
    std::atomic<size_t> bytesConsumed(0);
    
    // Producer thread - generates random data
    std::thread producer([&]() {
        for (size_t i = 0; i < 1000; i++) {
            std::vector<uint8_t> data(1024);
            
            QUAC_STATUS status = Quac100_Random(
                device,
                data.data(),
                static_cast<uint32_t>(data.size()),
                QUAC_RNG_QUALITY_NORMAL
            );
            
            if (status == QUAC_SUCCESS) {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCv.wait(lock, [&] { return randomQueue.size() < QUEUE_SIZE; });
                randomQueue.push(std::move(data));
                bytesProduced += 1024;
                lock.unlock();
                queueCv.notify_one();
            }
        }
        producerDone = true;
        queueCv.notify_all();
    });
    
    // Consumer thread - uses random data for something
    std::thread consumer([&]() {
        while (true) {
            std::vector<uint8_t> data;
            
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCv.wait(lock, [&] { 
                    return !randomQueue.empty() || producerDone; 
                });
                
                if (randomQueue.empty() && producerDone) {
                    break;
                }
                
                if (!randomQueue.empty()) {
                    data = std::move(randomQueue.front());
                    randomQueue.pop();
                }
            }
            queueCv.notify_one();
            
            if (!data.empty()) {
                // Simulate "consuming" the random data
                bytesConsumed += data.size();
            }
        }
    });
    
    // Progress monitor
    while (!producerDone || bytesConsumed < bytesProduced) {
        std::cout << "\r  Produced: " << bytesProduced << " bytes, "
                  << "Consumed: " << bytesConsumed << " bytes, "
                  << "Queue: " << randomQueue.size() << "   " << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    producer.join();
    consumer.join();
    
    std::cout << "\n\nProducer-Consumer demo complete!" << std::endl;
    std::cout << "  Total produced: " << bytesProduced << " bytes" << std::endl;
    std::cout << "  Total consumed: " << bytesConsumed << " bytes" << std::endl;
}

//
// Main entry point
//
int main() {
    std::cout << "QUAC 100 C++ Sample - Async Operations" << std::endl;
    std::cout << "=======================================" << std::endl;
    
    try {
        // Open device
        QUAC_HANDLE device;
        QUAC_STATUS status = Quac100_Open(&device);
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to open device");
        }
        
        std::cout << "\nDevice opened successfully!" << std::endl;
        
        // Demo 1: Batch processing
        std::cout << "\n--- Batch KEM KeyGen ---" << std::endl;
        BatchProcessor processor(device);
        processor.ProcessKemKeyGenBatch(1000);
        
        // Demo 2: Producer-Consumer
        DemoProducerConsumer(device);
        
        // Cleanup
        Quac100_Close(device);
        
        std::cout << "\n=== All async demos completed! ===" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
