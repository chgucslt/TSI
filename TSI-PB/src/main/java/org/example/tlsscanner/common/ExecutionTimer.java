package org.example.tlsscanner.common;

import java.util.function.Supplier;

public class ExecutionTimer<T> {

    private final Supplier<T> computation;
    private long timeCost;
    private T result;
    private boolean executed;

    // Private constructor to enforce factory method usage.
    private ExecutionTimer(Supplier<T> computation) {
        this.computation = computation;
        this.timeCost = 0;
        this.executed = false;
    }

    /**
     * Factory method to create an ExecutionTimer instance.
     * Example usage:
     * >>>>    ExecutionTimer<Integer> timer = ExecutionTimer.of(() -> {
     * >>>>        return someComputation();
     * >>>>    });
     * >>>>    int result = timer.execute();
     *
     * @param computation the computation to be timed, provided as a Supplier functional interface
     * @return a new ExecutionTimer instance
     * @param <T> the return type of the computation
     */
    public static <T> ExecutionTimer<T> of(Supplier<T> computation) {
        return new ExecutionTimer<>(computation);
    }

    /**
     * Executes the computation and measures its duration.
     *
     * @return the result of the computation
     */
    public T execute() {
        long startTime = System.currentTimeMillis();
        result = computation.get();
        long endTime = System.currentTimeMillis();
        timeCost = endTime - startTime;
        executed = true;
        return result;
    }

    public long getTimeCost() {
        if (!executed) {
            throw new IllegalStateException("Computation has not been executed yet");
        }
        return timeCost;
    }

    public T getResult() {
        if (!executed) {
            throw new IllegalStateException("Computation has not been executed yet");
        }
        return result;
    }

    public boolean isExecuted() {
        return executed;
    }
}
