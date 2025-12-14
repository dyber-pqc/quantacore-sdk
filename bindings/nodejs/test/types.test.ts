/**
 * Unit tests for types module
 */

import {
    KemAlgorithm,
    SignAlgorithm,
    HashAlgorithm,
    KeyType,
    KeyUsage,
    InitFlags,
    KEM_SIZES,
    SIGN_SIZES,
    HASH_SIZES,
} from '../src/types';

describe('KemAlgorithm', () => {
    test('enum values', () => {
        expect(KemAlgorithm.MlKem512).toBe(0);
        expect(KemAlgorithm.MlKem768).toBe(1);
        expect(KemAlgorithm.MlKem1024).toBe(2);
    });

    test('KEM_SIZES for MlKem512', () => {
        const sizes = KEM_SIZES[KemAlgorithm.MlKem512];
        expect(sizes.publicKey).toBe(800);
        expect(sizes.secretKey).toBe(1632);
        expect(sizes.ciphertext).toBe(768);
        expect(sizes.sharedSecret).toBe(32);
    });

    test('KEM_SIZES for MlKem768', () => {
        const sizes = KEM_SIZES[KemAlgorithm.MlKem768];
        expect(sizes.publicKey).toBe(1184);
        expect(sizes.secretKey).toBe(2400);
        expect(sizes.ciphertext).toBe(1088);
        expect(sizes.sharedSecret).toBe(32);
    });

    test('KEM_SIZES for MlKem1024', () => {
        const sizes = KEM_SIZES[KemAlgorithm.MlKem1024];
        expect(sizes.publicKey).toBe(1568);
        expect(sizes.secretKey).toBe(3168);
        expect(sizes.ciphertext).toBe(1568);
        expect(sizes.sharedSecret).toBe(32);
    });
});

describe('SignAlgorithm', () => {
    test('enum values', () => {
        expect(SignAlgorithm.MlDsa44).toBe(0);
        expect(SignAlgorithm.MlDsa65).toBe(1);
        expect(SignAlgorithm.MlDsa87).toBe(2);
    });

    test('SIGN_SIZES for MlDsa44', () => {
        const sizes = SIGN_SIZES[SignAlgorithm.MlDsa44];
        expect(sizes.publicKey).toBe(1312);
        expect(sizes.secretKey).toBe(2560);
        expect(sizes.signature).toBe(2420);
    });

    test('SIGN_SIZES for MlDsa65', () => {
        const sizes = SIGN_SIZES[SignAlgorithm.MlDsa65];
        expect(sizes.publicKey).toBe(1952);
        expect(sizes.secretKey).toBe(4032);
        expect(sizes.signature).toBe(3309);
    });

    test('SIGN_SIZES for MlDsa87', () => {
        const sizes = SIGN_SIZES[SignAlgorithm.MlDsa87];
        expect(sizes.publicKey).toBe(2592);
        expect(sizes.secretKey).toBe(4896);
        expect(sizes.signature).toBe(4627);
    });
});

describe('HashAlgorithm', () => {
    test('enum values', () => {
        expect(HashAlgorithm.Sha256).toBe(0);
        expect(HashAlgorithm.Sha384).toBe(1);
        expect(HashAlgorithm.Sha512).toBe(2);
        expect(HashAlgorithm.Sha3_256).toBe(3);
        expect(HashAlgorithm.Sha3_384).toBe(4);
        expect(HashAlgorithm.Sha3_512).toBe(5);
        expect(HashAlgorithm.Shake128).toBe(6);
        expect(HashAlgorithm.Shake256).toBe(7);
    });

    test('HASH_SIZES', () => {
        expect(HASH_SIZES[HashAlgorithm.Sha256]).toBe(32);
        expect(HASH_SIZES[HashAlgorithm.Sha384]).toBe(48);
        expect(HASH_SIZES[HashAlgorithm.Sha512]).toBe(64);
        expect(HASH_SIZES[HashAlgorithm.Sha3_256]).toBe(32);
        expect(HASH_SIZES[HashAlgorithm.Sha3_384]).toBe(48);
        expect(HASH_SIZES[HashAlgorithm.Sha3_512]).toBe(64);
        expect(HASH_SIZES[HashAlgorithm.Shake128]).toBeNull();
        expect(HASH_SIZES[HashAlgorithm.Shake256]).toBeNull();
    });
});

describe('KeyType', () => {
    test('enum values', () => {
        expect(KeyType.Secret).toBe(0);
        expect(KeyType.Public).toBe(1);
        expect(KeyType.Private).toBe(2);
        expect(KeyType.KeyPair).toBe(3);
    });
});

describe('KeyUsage', () => {
    test('enum values', () => {
        expect(KeyUsage.Encrypt).toBe(0x01);
        expect(KeyUsage.Decrypt).toBe(0x02);
        expect(KeyUsage.Sign).toBe(0x04);
        expect(KeyUsage.Verify).toBe(0x08);
        expect(KeyUsage.Derive).toBe(0x10);
        expect(KeyUsage.Wrap).toBe(0x20);
        expect(KeyUsage.Unwrap).toBe(0x40);
        expect(KeyUsage.All).toBe(0x7f);
    });

    test('can combine flags', () => {
        const usage = KeyUsage.Encrypt | KeyUsage.Decrypt;
        expect(usage).toBe(0x03);
        expect(usage & KeyUsage.Encrypt).toBeTruthy();
        expect(usage & KeyUsage.Decrypt).toBeTruthy();
        expect(usage & KeyUsage.Sign).toBeFalsy();
    });
});

describe('InitFlags', () => {
    test('enum values', () => {
        expect(InitFlags.HardwareAccel).toBe(0x01);
        expect(InitFlags.SideChannelProtect).toBe(0x02);
        expect(InitFlags.ConstantTime).toBe(0x04);
        expect(InitFlags.AutoZeroize).toBe(0x08);
        expect(InitFlags.FipsMode).toBe(0x10);
        expect(InitFlags.Debug).toBe(0x20);
        expect(InitFlags.SoftwareFallback).toBe(0x40);
        expect(InitFlags.Default).toBe(0x0f);
    });

    test('default includes expected flags', () => {
        expect(InitFlags.Default & InitFlags.HardwareAccel).toBeTruthy();
        expect(InitFlags.Default & InitFlags.SideChannelProtect).toBeTruthy();
        expect(InitFlags.Default & InitFlags.ConstantTime).toBeTruthy();
        expect(InitFlags.Default & InitFlags.AutoZeroize).toBeTruthy();
        expect(InitFlags.Default & InitFlags.FipsMode).toBeFalsy();
        expect(InitFlags.Default & InitFlags.Debug).toBeFalsy();
    });
});