using System;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace QuacTestSuite.Views
{
    public partial class ApiPlaygroundView : UserControl
    {
        private readonly Random _random = new Random();

        public ApiPlaygroundView()
        {
            InitializeComponent();
        }

        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Search functionality - filter tree view items
            string searchText = TxtSearch.Text.ToLower();
            if (string.IsNullOrEmpty(searchText))
            {
                // Show all items
                foreach (TreeViewItem item in FunctionTree.Items)
                {
                    item.Visibility = Visibility.Visible;
                    foreach (TreeViewItem child in item.Items)
                    {
                        child.Visibility = Visibility.Visible;
                    }
                }
            }
            else
            {
                // Filter items
                foreach (TreeViewItem item in FunctionTree.Items)
                {
                    bool parentMatch = item.Header.ToString()?.ToLower().Contains(searchText) ?? false;
                    bool hasVisibleChild = false;

                    foreach (TreeViewItem child in item.Items)
                    {
                        bool childMatch = child.Header.ToString()?.ToLower().Contains(searchText) ?? false;
                        child.Visibility = childMatch || parentMatch ? Visibility.Visible : Visibility.Collapsed;
                        if (child.Visibility == Visibility.Visible) hasVisibleChild = true;
                    }

                    item.Visibility = parentMatch || hasVisibleChild ? Visibility.Visible : Visibility.Collapsed;
                    if (hasVisibleChild) item.IsExpanded = true;
                }
            }
        }

        private void FunctionTree_Selected(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue is TreeViewItem item && item.Tag != null)
            {
                UpdateFunctionDisplay(item.Tag.ToString() ?? "");
            }
        }

        private void UpdateFunctionDisplay(string tag)
        {
            switch (tag)
            {
                case "init":
                    TxtFunctionName.Text = "quac_init()";
                    TxtFunctionDesc.Text = "Initialize the QuantaCore SDK. Must be called before any other SDK function. Returns QUAC_SUCCESS on success.";
                    break;
                case "shutdown":
                    TxtFunctionName.Text = "quac_shutdown()";
                    TxtFunctionDesc.Text = "Shutdown the QuantaCore SDK and release all resources. Should be called when done using the SDK.";
                    break;
                case "is_init":
                    TxtFunctionName.Text = "quac_is_initialized()";
                    TxtFunctionDesc.Text = "Check if the SDK has been initialized. Returns true if quac_init() was called successfully.";
                    break;
                case "version":
                    TxtFunctionName.Text = "quac_version_string()";
                    TxtFunctionDesc.Text = "Get the SDK version as a human-readable string (e.g., \"1.0.0\").";
                    break;
                case "version_info":
                    TxtFunctionName.Text = "quac_version_info()";
                    TxtFunctionDesc.Text = "Get detailed version information including major, minor, and patch numbers.";
                    break;
                case "dev_count":
                    TxtFunctionName.Text = "quac_device_count()";
                    TxtFunctionDesc.Text = "Get the number of available QUAC 100 devices in the system.";
                    break;
                case "dev_open":
                    TxtFunctionName.Text = "quac_open()";
                    TxtFunctionDesc.Text = "Open a device by index and obtain a device handle for subsequent operations.";
                    break;
                case "dev_close":
                    TxtFunctionName.Text = "quac_close()";
                    TxtFunctionDesc.Text = "Close a previously opened device and release its resources.";
                    break;
                case "dev_info":
                    TxtFunctionName.Text = "quac_get_info()";
                    TxtFunctionDesc.Text = "Get detailed information about an open device including serial number, firmware version, and capabilities.";
                    break;
                case "dev_caps":
                    TxtFunctionName.Text = "quac_get_capabilities()";
                    TxtFunctionDesc.Text = "Get device capabilities bitmask indicating supported algorithms and features.";
                    break;
                case "dev_reset":
                    TxtFunctionName.Text = "quac_reset()";
                    TxtFunctionDesc.Text = "Reset the device to its initial state. This clears all temporary keys and pending operations.";
                    break;
                case "kem_keygen":
                    TxtFunctionName.Text = "quac_kem_keygen()";
                    TxtFunctionDesc.Text = "Generate a key encapsulation key pair using ML-KEM (Kyber) algorithm with hardware acceleration.";
                    break;
                case "kem_encaps":
                    TxtFunctionName.Text = "quac_kem_encaps()";
                    TxtFunctionDesc.Text = "Encapsulate a shared secret using a public key, producing a ciphertext that only the private key holder can decrypt.";
                    break;
                case "kem_decaps":
                    TxtFunctionName.Text = "quac_kem_decaps()";
                    TxtFunctionDesc.Text = "Decapsulate a ciphertext using a secret key to recover the shared secret.";
                    break;
                case "kem_params":
                    TxtFunctionName.Text = "quac_kem_get_params()";
                    TxtFunctionDesc.Text = "Get the key sizes and ciphertext size for a given ML-KEM algorithm variant.";
                    break;
                case "sign_keygen":
                    TxtFunctionName.Text = "quac_sign_keygen()";
                    TxtFunctionDesc.Text = "Generate a digital signature key pair using ML-DSA (Dilithium) algorithm.";
                    break;
                case "sign":
                    TxtFunctionName.Text = "quac_sign()";
                    TxtFunctionDesc.Text = "Create a digital signature for a message using a secret key.";
                    break;
                case "verify":
                    TxtFunctionName.Text = "quac_verify()";
                    TxtFunctionDesc.Text = "Verify a digital signature against a message and public key. Returns QUAC_SUCCESS if valid.";
                    break;
                case "sign_params":
                    TxtFunctionName.Text = "quac_sign_get_params()";
                    TxtFunctionDesc.Text = "Get the key sizes and signature size for a given ML-DSA algorithm variant.";
                    break;
                case "slh_keygen":
                    TxtFunctionName.Text = "quac_slh_keygen()";
                    TxtFunctionDesc.Text = "Generate a hash-based signature key pair using SLH-DSA (SPHINCS+) algorithm.";
                    break;
                case "slh_sign":
                    TxtFunctionName.Text = "quac_slh_sign()";
                    TxtFunctionDesc.Text = "Create a hash-based digital signature using SLH-DSA with optional randomization.";
                    break;
                case "slh_verify":
                    TxtFunctionName.Text = "quac_slh_verify()";
                    TxtFunctionDesc.Text = "Verify a SLH-DSA signature against a message and public key.";
                    break;
                case "random":
                    TxtFunctionName.Text = "quac_random_bytes()";
                    TxtFunctionDesc.Text = "Generate cryptographically secure random bytes using the hardware Quantum Random Number Generator (QRNG).";
                    break;
                case "seed":
                    TxtFunctionName.Text = "quac_random_seed()";
                    TxtFunctionDesc.Text = "Add additional entropy to the QRNG by mixing in user-provided seed data.";
                    break;
                case "reseed":
                    TxtFunctionName.Text = "quac_random_reseed()";
                    TxtFunctionDesc.Text = "Force the QRNG to reseed from the hardware entropy source.";
                    break;
                case "entropy":
                    TxtFunctionName.Text = "quac_entropy_available()";
                    TxtFunctionDesc.Text = "Get the amount of entropy currently available in the QRNG pool (in bits).";
                    break;
                case "key_import":
                    TxtFunctionName.Text = "quac_key_import()";
                    TxtFunctionDesc.Text = "Import an external key into the device's secure key storage.";
                    break;
                case "key_export":
                    TxtFunctionName.Text = "quac_key_export()";
                    TxtFunctionDesc.Text = "Export a key from the device's secure key storage (if exportable).";
                    break;
                case "key_delete":
                    TxtFunctionName.Text = "quac_key_delete()";
                    TxtFunctionDesc.Text = "Securely delete a key from the device's key storage.";
                    break;
                case "key_list":
                    TxtFunctionName.Text = "quac_key_list()";
                    TxtFunctionDesc.Text = "List all keys currently stored in the device's secure key storage.";
                    break;
                case "kem_batch":
                    TxtFunctionName.Text = "quac_kem_encaps_batch()";
                    TxtFunctionDesc.Text = "Perform batch key encapsulation for multiple public keys in a single operation.";
                    break;
                case "sign_batch":
                    TxtFunctionName.Text = "quac_sign_batch()";
                    TxtFunctionDesc.Text = "Sign multiple messages in a single batch operation for improved throughput.";
                    break;
                case "verify_batch":
                    TxtFunctionName.Text = "quac_verify_batch()";
                    TxtFunctionDesc.Text = "Verify multiple signatures in a single batch operation.";
                    break;
                case "self_test":
                    TxtFunctionName.Text = "quac_self_test()";
                    TxtFunctionDesc.Text = "Execute FIPS 140-3 mandated cryptographic self-tests including Known Answer Tests (KAT).";
                    break;
                case "health":
                    TxtFunctionName.Text = "quac_get_health()";
                    TxtFunctionDesc.Text = "Get the overall health status of the device including all subsystem checks.";
                    break;
                case "temp":
                    TxtFunctionName.Text = "quac_get_temperature()";
                    TxtFunctionDesc.Text = "Read the current device temperature in degrees Celsius from the on-chip thermal sensor.";
                    break;
                case "stats":
                    TxtFunctionName.Text = "quac_get_statistics()";
                    TxtFunctionDesc.Text = "Get performance statistics including operation counts, throughput, and error rates.";
                    break;
                case "clear_stats":
                    TxtFunctionName.Text = "quac_clear_statistics()";
                    TxtFunctionDesc.Text = "Reset all performance statistics counters to zero.";
                    break;
                default:
                    TxtFunctionName.Text = "Select a function";
                    TxtFunctionDesc.Text = "Choose a function from the list on the left to see its details and execute it.";
                    break;
            }
        }

        private void Execute_Click(object sender, RoutedEventArgs e)
        {
            var sw = Stopwatch.StartNew();
            
            // Simulate execution
            System.Threading.Thread.Sleep(_random.Next(5, 25));
            
            sw.Stop();

            var funcName = TxtFunctionName.Text;
            var sb = new StringBuilder();

            if (funcName.Contains("keygen"))
            {
                // Generate fake key data
                int pkSize = funcName.Contains("slh") ? 32 : 1184;
                int skSize = funcName.Contains("slh") ? 64 : 2400;
                
                var pk = new byte[pkSize];
                var sk = new byte[skSize];
                _random.NextBytes(pk);
                _random.NextBytes(sk);

                sb.AppendLine("// Key pair generated successfully");
                sb.AppendLine();
                sb.AppendLine("public_key (first 64 bytes):");
                sb.AppendLine(BitConverter.ToString(pk, 0, Math.Min(64, pk.Length)).Replace("-", " "));
                sb.AppendLine("...");
                sb.AppendLine();
                sb.AppendLine("secret_key (first 64 bytes):");
                sb.AppendLine(BitConverter.ToString(sk, 0, Math.Min(64, sk.Length)).Replace("-", " "));
                sb.AppendLine("...");
                sb.AppendLine();
                sb.AppendLine($"Total public_key size: {pk.Length} bytes");
                sb.AppendLine($"Total secret_key size: {sk.Length} bytes");

                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("version"))
            {
                sb.AppendLine("// Version information");
                sb.AppendLine();
                sb.AppendLine("Version String: \"1.0.2\"");
                sb.AppendLine("Major: 1");
                sb.AppendLine("Minor: 0");
                sb.AppendLine("Patch: 2");
                sb.AppendLine("Build Date: Dec 15 2025");
                sb.AppendLine("Build Type: Release");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("device_count"))
            {
                sb.AppendLine("// Device enumeration result");
                sb.AppendLine();
                sb.AppendLine("count = 1");
                sb.AppendLine();
                sb.AppendLine("Device 0: QUAC 100 (Simulator)");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("get_info"))
            {
                sb.AppendLine("// Device information");
                sb.AppendLine();
                sb.AppendLine("quac_device_info_t {");
                sb.AppendLine("    .serial = \"QC-2025-001234\",");
                sb.AppendLine("    .model = \"QUAC 100\",");
                sb.AppendLine("    .firmware_version = \"1.0.2\",");
                sb.AppendLine("    .driver_version = \"1.0.0\",");
                sb.AppendLine("    .pcie_speed = PCIE_GEN4_X16,");
                sb.AppendLine("    .dma_channels = 4,");
                sb.AppendLine("    .crypto_engines = 8,");
                sb.AppendLine("    .sram_size = 4194304,");
                sb.AppendLine("    .is_simulator = true");
                sb.AppendLine("}");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("temperature"))
            {
                sb.AppendLine("// Temperature reading");
                sb.AppendLine();
                sb.AppendLine($"celsius = {_random.Next(38, 48)}");
                sb.AppendLine();
                sb.AppendLine("Status: Normal operating range");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("random"))
            {
                var data = new byte[32];
                _random.NextBytes(data);

                sb.AppendLine("// Random bytes generated (32 bytes)");
                sb.AppendLine();
                sb.AppendLine(BitConverter.ToString(data).Replace("-", " "));
                sb.AppendLine();
                sb.AppendLine("Source: Hardware QRNG");
                sb.AppendLine("Entropy: 8.0 bits/byte");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("self_test"))
            {
                sb.AppendLine("// Self-test results (FIPS 140-3)");
                sb.AppendLine();
                sb.AppendLine("[PASS] ML-KEM-768 Known Answer Test");
                sb.AppendLine("[PASS] ML-DSA-65 Known Answer Test");
                sb.AppendLine("[PASS] SLH-DSA-SHA2-128s Known Answer Test");
                sb.AppendLine("[PASS] QRNG Entropy Test (NIST SP 800-90B)");
                sb.AppendLine("[PASS] Memory Integrity Check");
                sb.AppendLine("[PASS] DMA Controller Test");
                sb.AppendLine("[PASS] Secure Key Storage Test");
                sb.AppendLine();
                sb.AppendLine("All FIPS 140-3 self-tests PASSED.");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("health"))
            {
                sb.AppendLine("// Device health status");
                sb.AppendLine();
                sb.AppendLine("quac_health_t {");
                sb.AppendLine("    .overall = QUAC_HEALTH_OK,");
                sb.AppendLine("    .crypto_engines = QUAC_HEALTH_OK,");
                sb.AppendLine("    .qrng = QUAC_HEALTH_OK,");
                sb.AppendLine("    .dma = QUAC_HEALTH_OK,");
                sb.AppendLine("    .key_storage = QUAC_HEALTH_OK,");
                sb.AppendLine("    .temperature = QUAC_HEALTH_OK,");
                sb.AppendLine("    .pcie_link = QUAC_HEALTH_OK");
                sb.AppendLine("}");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("statistics") || funcName.Contains("stats"))
            {
                sb.AppendLine("// Performance statistics");
                sb.AppendLine();
                sb.AppendLine("quac_stats_t {");
                sb.AppendLine($"    .total_operations = {_random.Next(10000, 50000)},");
                sb.AppendLine($"    .kem_operations = {_random.Next(3000, 15000)},");
                sb.AppendLine($"    .sign_operations = {_random.Next(2000, 10000)},");
                sb.AppendLine($"    .verify_operations = {_random.Next(2000, 10000)},");
                sb.AppendLine($"    .random_bytes_generated = {_random.Next(100000, 500000)},");
                sb.AppendLine("    .avg_kem_latency_us = 125,");
                sb.AppendLine("    .avg_sign_latency_us = 342,");
                sb.AppendLine("    .errors = 0");
                sb.AppendLine("}");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("encaps"))
            {
                var ct = new byte[1088];
                var ss = new byte[32];
                _random.NextBytes(ct);
                _random.NextBytes(ss);

                sb.AppendLine("// Encapsulation result");
                sb.AppendLine();
                sb.AppendLine("ciphertext (first 64 bytes):");
                sb.AppendLine(BitConverter.ToString(ct, 0, 64).Replace("-", " "));
                sb.AppendLine("...");
                sb.AppendLine();
                sb.AppendLine("shared_secret (32 bytes):");
                sb.AppendLine(BitConverter.ToString(ss).Replace("-", " "));
                sb.AppendLine();
                sb.AppendLine($"Ciphertext size: {ct.Length} bytes");

                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("sign") && !funcName.Contains("keygen"))
            {
                var sig = new byte[3309];
                _random.NextBytes(sig);

                sb.AppendLine("// Signature generated");
                sb.AppendLine();
                sb.AppendLine("signature (first 64 bytes):");
                sb.AppendLine(BitConverter.ToString(sig, 0, 64).Replace("-", " "));
                sb.AppendLine("...");
                sb.AppendLine();
                sb.AppendLine($"Signature size: {sig.Length} bytes");
                sb.AppendLine("Algorithm: ML-DSA-65");

                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("verify"))
            {
                sb.AppendLine("// Signature verification result");
                sb.AppendLine();
                sb.AppendLine("Verification: PASSED");
                sb.AppendLine();
                sb.AppendLine("The signature is valid for the given message and public key.");

                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("entropy"))
            {
                sb.AppendLine("// Entropy pool status");
                sb.AppendLine();
                sb.AppendLine($"available_entropy = {_random.Next(2000, 4096)} bits");
                sb.AppendLine("pool_capacity = 4096 bits");
                sb.AppendLine("health_status = OK");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("key_list"))
            {
                sb.AppendLine("// Stored keys");
                sb.AppendLine();
                sb.AppendLine("Key slots in use: 3 / 256");
                sb.AppendLine();
                sb.AppendLine("Slot 0: ML-KEM-768 (exportable)");
                sb.AppendLine("Slot 1: ML-DSA-65 (non-exportable)");
                sb.AppendLine("Slot 2: SLH-DSA-SHA2-128s (non-exportable)");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else if (funcName.Contains("init"))
            {
                sb.AppendLine("// SDK initialized");
                sb.AppendLine();
                sb.AppendLine("Library: libquac100.so");
                sb.AppendLine("Version: 1.0.2");
                sb.AppendLine("Devices found: 1");
                sb.AppendLine("FIPS mode: Enabled");
                
                SetSuccess("QUAC_SUCCESS");
            }
            else
            {
                sb.AppendLine("// Function executed successfully");
                sb.AppendLine();
                sb.AppendLine("return value: QUAC_SUCCESS (0x00000000)");
                
                SetSuccess("QUAC_SUCCESS");
            }

            TxtResult.Text = sb.ToString();
            TxtExecTime.Text = $"Execution: {sw.ElapsedMilliseconds} ms";
        }

        private void CopyResult_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtResult.Text);
        }

        private void SaveResult_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = $"api_result_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (dlg.ShowDialog() == true)
            {
                System.IO.File.WriteAllText(dlg.FileName, TxtResult.Text);
            }
        }

        private void ClearResult_Click(object sender, RoutedEventArgs e)
        {
            TxtResult.Text = "// Results will appear here after execution...";
            TxtExecTime.Text = "Execution: -- ms";
        }

        private void SetSuccess(string status)
        {
            TxtResultStatus.Text = status;
            ResultStatus.Background = new SolidColorBrush(Color.FromRgb(0x2E, 0xD5, 0x73));
        }

        private void SetError(string status)
        {
            TxtResultStatus.Text = status;
            ResultStatus.Background = new SolidColorBrush(Color.FromRgb(0xFF, 0x47, 0x57));
        }
    }
}
