package com.pqc.mlkem;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.pqc.mlkem.Field.*;

class FieldTest {

    @Test
    void testAdd() {
        assertEquals(0, fieldAdd(0, 0));
        assertEquals(1, fieldAdd(0, 1));
        assertEquals(0, fieldAdd(Q - 1, 1));
        assertEquals(Q - 1, fieldAdd(Q - 2, 1));
        assertEquals(100, fieldAdd(3300, 129));
    }

    @Test
    void testSub() {
        assertEquals(0, fieldSub(0, 0));
        assertEquals(Q - 1, fieldSub(0, 1));
        assertEquals(1, fieldSub(1, 0));
        assertEquals(0, fieldSub(100, 100));
        assertEquals(3200, fieldSub(3300, 100));
    }

    @Test
    void testMul() {
        assertEquals(0, fieldMul(0, 100));
        assertEquals(0, fieldMul(100, 0));
        assertEquals(1, fieldMul(1, 1));
        // 17 * 17 = 289
        assertEquals(289, fieldMul(17, 17));
        // Wrap around: 3000 * 2 = 6000 mod 3329 = 2671
        assertEquals(mod(6000, Q), fieldMul(3000, 2));
    }

    @Test
    void testPow() {
        assertEquals(1, fieldPow(17, 0));
        assertEquals(17, fieldPow(17, 1));
        assertEquals(289, fieldPow(17, 2));
        // 17^(Q-1) mod Q should be 1 (Fermat's little theorem, Q is prime)
        assertEquals(1, fieldPow(17, Q - 1));
    }

    @Test
    void testModNegative() {
        assertEquals(Q - 1, mod(-1, Q));
        assertEquals(Q - 5, mod(-5, Q));
        assertEquals(0, mod(-Q, Q));
    }
}
