QUAC 100 Python SDK Documentation
==================================

Welcome to the QUAC 100 Python SDK documentation. This SDK provides Python
bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   api
   examples
   changelog

Quick Start
-----------

Installation::

    pip install quantacore-sdk

Basic usage::

    import quantacore

    # Initialize
    quantacore.initialize()

    try:
        # Open device
        device = quantacore.open_first_device()
        
        # Generate ML-KEM key pair
        kem = device.kem()
        with kem.generate_keypair_768() as kp:
            print(f"Public key: {len(kp.public_key)} bytes")
        
        device.close()
    finally:
        quantacore.cleanup()

Features
--------

* **ML-KEM (Kyber)** - Post-quantum key encapsulation
* **ML-DSA (Dilithium)** - Post-quantum digital signatures  
* **QRNG** - Quantum random number generation
* **Hardware-accelerated hashing** - SHA-2, SHA-3, SHAKE, HMAC
* **HSM Key Storage** - Secure key management

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`