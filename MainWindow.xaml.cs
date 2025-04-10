using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

namespace ModernSign
{
    // Class to hold token display information
    public class TokenSlotInfo
    {
        public ulong SlotId { get; set; }
        public string Label { get; set; }
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string SerialNumber { get; set; }
    }

    public partial class MainWindow : Window
    {
        // Path to the PKCS#11 library (eTPKCS11.dll)
        private readonly string libraryPath = @"C:\Windows\System32\eTPKCS11.dll";
        private List<TokenSlotInfo> tokenSlots = new List<TokenSlotInfo>();

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
        }

        // Load token information on window load.
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            Task.Run(() =>
            {
                try
                {
                    var pkcs11Factory = new Pkcs11InteropFactories();
                    using (IPkcs11Library pkcs11Library =
                           pkcs11Factory.Pkcs11LibraryFactory.LoadPkcs11Library(pkcs11Factory, libraryPath,
                               AppType.MultiThreaded))
                    {
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        if (slots == null || slots.Count == 0)
                        {
                            Dispatcher.Invoke(() => StatusTextBlock.Text = "No token found in any slot.");
                            return;
                        }

                        foreach (var slot in slots)
                        {
                            try
                            {
                                var tokenInfo = slot.GetTokenInfo();
                                tokenSlots.Add(new TokenSlotInfo
                                {
                                    SlotId = slot.SlotId,
                                    Label = tokenInfo.Label?.Trim(),
                                    Manufacturer = tokenInfo.ManufacturerId?.Trim(),
                                    Model = tokenInfo.Model?.Trim(),
                                    SerialNumber = tokenInfo.SerialNumber?.Trim()
                                });
                            }
                            catch (Pkcs11Exception ex)
                            {
                                Console.WriteLine($"Slot {slot.SlotId}: Error retrieving token info: {ex.Message}");
                            }
                        }

                        Dispatcher.Invoke(() =>
                        {
                            TokenDataGrid.ItemsSource = tokenSlots;
                            StatusTextBlock.Text = "Token information loaded.";
                        });
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => StatusTextBlock.Text = $"Error: {ex.Message}");
                }
            });
        }

        // Browse button: let the user select a file.
        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog
            {
                Title = "Select File to Sign"
            };
            if (dlg.ShowDialog() == true)
            {
                FilePathTextBox.Text = dlg.FileName;
            }
        }

        // When a token is selected, load its available signature mechanisms.
        // When a token is selected, load its available signature mechanisms.

        private void TokenDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TokenDataGrid.SelectedItem == null)
            {
                SignatureAlgorithmComboBox.ItemsSource = null;
                return;
            }

            var selectedToken = (TokenSlotInfo)TokenDataGrid.SelectedItem;

            try
            {
                var pkcs11Factory = new Pkcs11InteropFactories();

                using (IPkcs11Library pkcs11Library =
                       pkcs11Factory.Pkcs11LibraryFactory.LoadPkcs11Library(pkcs11Factory, libraryPath,
                           AppType.MultiThreaded))
                {
                    // Locate the matching slot by SlotId.
                    ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent)
                        .FirstOrDefault(s => s.SlotId == selectedToken.SlotId);
                    if (slot != null)
                    {
                        // Get the list of mechanisms provided by the token.
                        List<CKM> mechList = slot.GetMechanismList();

                        // Determine the key type by opening a session and searching for a private signing key.
                        CKK keyType = CKK.CKK_RSA; // Default value – will be updated if possible.
                        try
                        {
                            using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                            {
                                // Search for private signing key objects.
                                var searchAttributes = new List<IObjectAttribute>
                                {
                                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true)
                                };

                                List<IObjectHandle> foundKeys = session.FindAllObjects(searchAttributes);
                                if (foundKeys != null && foundKeys.Count > 0)
                                {
                                    // Instead of a list of IObjectAttribute, pass a list of CKA to GetAttributeValue.
                                    List<IObjectAttribute> attrValues =
                                        session.GetAttributeValue(foundKeys[0], new List<CKA> { CKA.CKA_KEY_TYPE });
                                    if (attrValues != null && attrValues.Count > 0)
                                    {
                                        ulong keyTypeValue = attrValues[0].GetValueAsUlong();
                                        keyType = (CKK)keyTypeValue;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            // If there's an issue retrieving the key type, log it and continue with the default value.
                            Console.WriteLine($"Error retrieving key type: {ex.Message}");
                        }

                        // Filter mechanisms: include only those with the CKF_SIGN flag and valid for the key type.
                        var signingMechanisms = new List<MechanismDisplay>();
                        foreach (CKM mechanism in mechList)
                        {
                            var mechInfo = slot.GetMechanismInfo(mechanism);
                            if ((mechInfo.MechanismFlags.Flags & (ulong)CKF.CKF_SIGN) != 0)
                            {
                                if (IsMechanismSupportedForKeyType(mechanism, keyType))
                                {
                                    // Build a display name for the mechanism.
                                    string displayName;
                                    if (Enum.IsDefined(typeof(CKM), mechanism))
                                    {
                                        displayName = mechanism.ToString();
                                    }
                                    else
                                    {
                                        displayName = $"Vendor Mechanism (0x{((uint)mechanism):X})";
                                    }

                                    signingMechanisms.Add(new MechanismDisplay
                                    {
                                        MechanismValue = (ulong)mechanism,
                                        DisplayName = displayName
                                    });
                                }
                            }
                        }

                        Dispatcher.Invoke(() =>
                        {
                            SignatureAlgorithmComboBox.ItemsSource = signingMechanisms;
                            SignatureAlgorithmComboBox.DisplayMemberPath = "DisplayName";
                            if (signingMechanisms.Count > 0)
                                SignatureAlgorithmComboBox.SelectedIndex = 0;
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    StatusTextBlock.Text = $"Error loading signature mechanisms: {ex.Message}";
                });
            }
        }

        private bool IsMechanismSupportedForKeyType(CKM mechanism, CKK keyType)
        {
            // For RSA keys (CKK_RSA)
            if (keyType == CKK.CKK_RSA)
            {
                return mechanism == CKM.CKM_RSA_PKCS ||
                       mechanism == CKM.CKM_SHA256_RSA_PKCS ||
                       mechanism == CKM.CKM_SHA1_RSA_PKCS ||
                       mechanism == CKM.CKM_SHA384_RSA_PKCS ||
                       mechanism == CKM.CKM_SHA512_RSA_PKCS;
            }
            // For ECC keys (CKK_EC)
            else if (keyType == CKK.CKK_EC)
            {
                return mechanism == CKM.CKM_ECDSA ||
                       mechanism == CKM.CKM_ECDSA_SHA1 ||
                       mechanism == CKM.CKM_ECDSA_SHA256 ||
                       mechanism == CKM.CKM_ECDSA_SHA384 ||
                       mechanism == CKM.CKM_ECDSA_SHA512;
            }

            // If you need to support other key types, add conditions here.
            return false;
        }


        // Sign button: Prompt for PIN and sign the file using the chosen mechanism.
        private async void SignButton_Click(object sender, RoutedEventArgs e)
        {
            // Validate file selection.
            if (string.IsNullOrEmpty(FilePathTextBox.Text) || !File.Exists(FilePathTextBox.Text))
            {
                MessageBox.Show("Please select a valid file to sign.", "File Not Found", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Validate token selection.
            if (TokenDataGrid.SelectedItem == null)
            {
                MessageBox.Show("Please select a token/device from the list.", "No Token Selected", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Validate that a signature algorithm is selected.
            if (SignatureAlgorithmComboBox.SelectedItem == null)
            {
                MessageBox.Show("Please select a signature algorithm.", "No Algorithm Selected", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Prompt for the PIN using the modal dialog.
            PinPromptWindow pinWindow = new PinPromptWindow
            {
                Owner = this
            };
            if (pinWindow.ShowDialog() != true)
            {
                StatusTextBlock.Text = "Signing cancelled: no PIN entered.";
                return;
            }

            string pin = pinWindow.Pin;

            // Capture UI values.
            string filePath = FilePathTextBox.Text;
            TokenSlotInfo selectedToken = (TokenSlotInfo)TokenDataGrid.SelectedItem;
            // Capture the chosen signature mechanism. The ComboBox items contain CKM enum values.
            // Correct: first cast to MechanismDisplay, then use its property
            MechanismDisplay selectedMechDisplay = (MechanismDisplay)SignatureAlgorithmComboBox.SelectedItem;
            CKM selectedMechanism = (CKM)selectedMechDisplay.MechanismValue;


            StatusTextBlock.Text = "Signing in progress...";
            await Task.Run(() =>
            {
                try
                {
                    // Read file data.
                    byte[] dataToSign = File.ReadAllBytes(filePath);

                    var pkcs11Factory = new Pkcs11InteropFactories();
                    using (IPkcs11Library pkcs11Library =
                           pkcs11Factory.Pkcs11LibraryFactory.LoadPkcs11Library(pkcs11Factory, libraryPath,
                               AppType.MultiThreaded))
                    {
                        // Locate the token's slot.
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        ISlot chosenSlot = slots.FirstOrDefault(s => s.SlotId == selectedToken.SlotId);
                        if (chosenSlot == null)
                        {
                            Dispatcher.Invoke(() => StatusTextBlock.Text = "Selected token not found.");
                            return;
                        }

                        using (ISession session = chosenSlot.OpenSession(SessionType.ReadWrite))
                        {
                            session.Login(CKU.CKU_USER, pin);

                            // Define attributes for finding a private signing key.
                            List<IObjectAttribute> searchAttributes = new List<IObjectAttribute>
                            {
                                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true)
                            };

                            List<IObjectHandle> foundKeys = session.FindAllObjects(searchAttributes);
                            if (foundKeys == null || foundKeys.Count == 0)
                            {
                                Dispatcher.Invoke(() =>
                                    StatusTextBlock.Text = "No private signing key found on token.");
                                session.Logout();
                                return;
                            }

                            IObjectHandle privateKeyHandle = foundKeys[0];

                            // If the selected mechanism is CKM_RSA_PKCS, we must hash and build a DigestInfo structure manually.
                            // We'll assume SHA256 is desired.
                            if (selectedMechanism == CKM.CKM_RSA_PKCS)
                            {
                                using (SHA256 sha256 = SHA256.Create())
                                {
                                    // Compute the SHA-256 digest
                                    byte[] digest = sha256.ComputeHash(dataToSign);

                                    // Build the DigestInfo structure for SHA-256.
                                    // The DER prefix for SHA-256 is (in hex): 3031300d060960864801650304020105000420
                                    byte[] derPrefix = Convert.FromHexString("3031300D060960864801650304020105000420");
                                    // Concatenate the DER prefix with the digest
                                    dataToSign = derPrefix.Concat(digest).ToArray();
                                }
                            }

                            // Use the user-selected signing mechanism.
                            IMechanism mechanism = session.Factories.MechanismFactory.Create(selectedMechanism);
                            byte[] signature = session.Sign(mechanism, privateKeyHandle, dataToSign);

                            // Save the signature to a file (saved alongside the file to sign).
                            string sigPath = filePath + ".sig";
                            File.WriteAllBytes(sigPath, signature);
                            session.Logout();

                            Dispatcher.Invoke(() =>
                            {
                                StatusTextBlock.Text = $"File signed successfully. Signature saved to: {sigPath}";
                            });
                        }
                    }
                }
                catch (Pkcs11Exception pkex)
                {
                    Dispatcher.Invoke(() => StatusTextBlock.Text = $"PKCS#11 error: {pkex.Message}");
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => StatusTextBlock.Text = $"General error: {ex.Message}");
                }
            });
        }

        // Verify button: verify the signature.
        private async void VerifyButton_Click(object sender, RoutedEventArgs e)
        {
            // Validate file selection.
            if (string.IsNullOrEmpty(FilePathTextBox.Text) || !File.Exists(FilePathTextBox.Text))
            {
                MessageBox.Show("Please select a valid signature file for verification.", "File Not Found",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Make sure the selected file has a .sig extension.
            string sigPath = FilePathTextBox.Text;
            if (!sigPath.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("The selected file must be a signature file with a '.sig' extension.", "Invalid File",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Derive the original file path by removing the ".sig" extension.
            string originalFilePath = sigPath.Substring(0, sigPath.Length - 4);
            if (!File.Exists(originalFilePath))
            {
                MessageBox.Show($"The original file was not found: {originalFilePath}", "Error", MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }

            // Read original file data and signature.
            byte[] originalData = File.ReadAllBytes(originalFilePath);
            byte[] signature = File.ReadAllBytes(sigPath);

            // Validate token selection.
            if (TokenDataGrid.SelectedItem == null)
            {
                MessageBox.Show("Please select a token/device from the list.", "No Token Selected", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Validate mechanism selection.
            if (SignatureAlgorithmComboBox.SelectedItem == null)
            {
                MessageBox.Show("Please select a signature algorithm.", "No Algorithm Selected", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var selectedToken = (TokenSlotInfo)TokenDataGrid.SelectedItem;
            var selectedMechDisplay = (MechanismDisplay)SignatureAlgorithmComboBox.SelectedItem;
            CKM selectedMechanism = (CKM)selectedMechDisplay.MechanismValue;

            StatusTextBlock.Text = "Verification in progress...";
            await Task.Run(() =>
            {
                try
                {
                    var pkcs11Factory = new Pkcs11InteropFactories();
                    using (IPkcs11Library pkcs11Library =
                           pkcs11Factory.Pkcs11LibraryFactory.LoadPkcs11Library(pkcs11Factory, libraryPath,
                               AppType.MultiThreaded))
                    {
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        ISlot chosenSlot = slots.FirstOrDefault(s => s.SlotId == selectedToken.SlotId);
                        if (chosenSlot == null)
                        {
                            Dispatcher.Invoke(() => StatusTextBlock.Text = "Selected token not found.");
                            return;
                        }

                        // For verification, we need the public key.
                        using (ISession session = chosenSlot.OpenSession(SessionType.ReadOnly))
                        {
                            // Search for public keys on the token.
                            var searchAttributes = new List<IObjectAttribute>
                            {
                                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)
                            };
                            List<IObjectHandle> pubKeys = session.FindAllObjects(searchAttributes);
                            if (pubKeys == null || pubKeys.Count == 0)
                            {
                                Dispatcher.Invoke(() => StatusTextBlock.Text = "No public key found on token.");
                                return;
                            }

                            // For simplicity, use the first public key.
                            IObjectHandle publicKeyHandle = pubKeys[0];

                            // If using CKM_RSA_PKCS, prepare the data by hashing and building the DigestInfo.
                            byte[] dataForVerification = originalData;
                            if (selectedMechanism == CKM.CKM_RSA_PKCS)
                            {
                                using (SHA256 sha256 = SHA256.Create())
                                {
                                    byte[] digest = sha256.ComputeHash(originalData);
                                    byte[] derPrefix = Convert.FromHexString("3031300D060960864801650304020105000420");
                                    dataForVerification = derPrefix.Concat(digest).ToArray();
                                }
                            }

                            IMechanism mechanism = session.Factories.MechanismFactory.Create(selectedMechanism);

                            // Use the overload with an out parameter.
                            bool isValid = false;
                            session.Verify(mechanism, publicKeyHandle, dataForVerification, signature, out isValid);

                            Dispatcher.Invoke(() =>
                            {
                                if (isValid)
                                    StatusTextBlock.Text = "Signature verified successfully.";
                                else
                                    StatusTextBlock.Text = "Signature verification failed.";
                            });
                        }
                    }
                }
                catch (Pkcs11Exception pkex)
                {
                    Dispatcher.Invoke(() =>
                        StatusTextBlock.Text = $"PKCS#11 error during verification: {pkex.Message}");
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => StatusTextBlock.Text = $"Verification failed: {ex.Message}");
                }
            });
        }
    }
}