package org.example.tlsscanner.api;

import org.example.tlsscanner.api.datastructures.Fingerprint;

public interface FingerprintComparator<T extends Fingerprint<K, V>, K, V> {

    double calculate(T f1, T f2);

}
