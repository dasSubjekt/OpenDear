namespace OpenDear.ViewModel
{
    using System;
    using System.IO;
    using System.Linq;
    using OpenDear.Model;
    using OpenDear.Crypto;
    using System.ComponentModel;
    using System.Windows.Threading;
    using System.Collections.Generic;
    using System.Security.Cryptography;


    public partial class MainViewModel : ViewModelBase
    {
        #region constructors

        /// <summary>Initialises a new instance of the MainViewModel class.</summary>
        public MainViewModel() : base()
        {
            _isDatabaseWithPassword = _isDragOverData = _isDragOverKeys = _isProgressBarIndeterminate = false;
            _iErrorId = _iPasswordLength = _iProgressBarValue = _iUserPinLength = 0;
            _iProgressBarMaximum = ciProgrssBarDefaultMaximum;
            _sBackgroundStatus = _sDatabaseDirectory = _sErrorMessage = _sInputKeyFilePath = _sInputMessageFilePath = _sNewDatabaseName = string.Empty;
            _abEncryptedPassword = null;
            _eMenuTab = nMenuTab.Keys;
            _Database = null;

            rcClose = new RelayCommand(ExecuteClose);
            rcCreateDatabase = new RelayCommand(ExecuteCreateDatabase, CanExecuteCreateDatabase);
            rcDecryptMessage = new RelayCommand(ExecuteDecryptMessage, CanExecuteDecryptMessage);
            rcEmptyPasswordOrPin = new RelayCommand(ExecuteEmptyPasswordOrPin, CanExecuteEmptyPasswordOrPin);
            rcF5 = new RelayCommand(ExecuteF5, CanExecuteF5);
            rcIsClosing = new RelayCommand(ExecuteIsClosing, CanExecuteIsClosing);
            rcLogin = new RelayCommand(ExecuteLogin, CanExecuteLogin);
            rcReadMessage = new RelayCommand(ExecuteReadMessage, CanExecuteReadMessage);
            rcReadKeyFile = new RelayCommand(ExecuteReadKeyFile, CanExecuteReadKeyFile);
            rcReadTokens = new RelayCommand(ExecuteReadTokens);
            rcSelectInputMessage = new RelayCommand(ExecuteSelectInputMessage);
            rcSelectKey = new RelayCommand(ExecuteSelectKey);
            rcUnlockKey = new RelayCommand(ExecuteUnlockKey, CanExecuteUnlockKey);

            InitialiseTranslations();

            _blDatabases = new BindingList<Property>();
            ReadAndDisplayDatabases();

            _blMessages = new BindingList<Property>
            {
                new Property(DateTime.Now, Translate("ProgramVersion"))
            };

            _blSubkeys = new BindingList<PgpSignature>();
            _SelectedSubkey = null;

            _blSubkeyProperties = new BindingList<Property>();
            _SelectedSubkeyProperty = null;

            _ltTokens = new List<PgpToken>();
            _blTokens = new BindingList<PgpToken>();
            _SelectedToken = null;

            _UserInterfaceTimer = new DispatcherTimer();
            _UserInterfaceTimer.Tick += new EventHandler(UserInterfaceTimerTick);
            _UserInterfaceTimer.Interval = new TimeSpan(0, 0, 0, 0, 250);

            InitialiseCryptography();
        }
        #endregion

        #region commands and methods

        private void AddSubkeyProperty(nSubkeyProperty eSubkeyProperty, string sName, string sValue)
        {
            _blSubkeyProperties.Add(new Property((int)eSubkeyProperty, (int)eSubkeyProperty, sName, sValue));
        }

        /// <summary></summary>
        private bool CanExecuteCreateDatabase()
        {
            return isExecuteCreateDatabase;
        }

        /// <summary></summary>
        private bool CanExecuteDecryptMessage()
        {
            return isExecuteDecryptMessage;
        }

        /// <summary></summary>
        private bool CanExecuteEmptyPasswordOrPin()
        {
            return isExecuteEmptyPasswordOrPin;
        }

        /// <summary></summary>
        private bool CanExecuteF5()
        {
            return isExecuteF5;
        }

        /// <summary></summary>
        private bool CanExecuteLogin()
        {
            return isExecuteLogin;
        }

        /// <summary></summary>
        private bool CanExecuteReadMessage()
        {
            return isExecuteReadMessage;
        }

        /// <summary></summary>
        private bool CanExecuteReadKeyFile()
        {
            return isExecuteReadKeyFile;
        }

        /// <summary></summary>
        private bool CanExecuteUnlockKey()
        {
            return isExecuteUnlockKey;
        }

        /// <summary>Delegate method invoked by rcCreateDatabase.</summary>
        private void ExecuteCreateDatabase()
        {
            /*
            byte[] abDecryptedPassword1, abDecryptedPassword2, abReEncryptedPassword, abNewSalt;
            BytesAndTextUtility PasswordBytes;

            if (isExecuteCreateDatabase)
            {
                // Todo test if database name exists

                if (_Database != null)
                    _Database.Dispose();

                _Database = new EncryptedDatabase(GetDatabasePath(_sNewDatabaseName), _Cryptography);
                _Database.CreateTables();

                if (_Database.eState == SQLiteDatabase.nState.OK)
                {
                    if (_isDatabaseWithPassword)
                    {
                        // abDecryptedPassword1 = _RsaUiDecryptor.Decrypt(_abEncryptedPassword1, RSAEncryptionPadding.Pkcs1);
                        // abDecryptedPassword2 = _RsaUiDecryptor.Decrypt(_abEncryptedPassword2, RSAEncryptionPadding.Pkcs1);
                        // PasswordBytes = new BytesAndTextUtility(abDecryptedPassword1, abDecryptedPassword2);
                        // 
                        // if (PasswordBytes.isAllBytesEqual)   // This necessary test somewhat endangers password safety because this is plain text.
                        // {
                        //     abReEncryptedPassword = _Cryptography.EncryptAes(abDecryptedPassword1, _BackgroundThread.abAesKey);
                        //     abNewSalt = new byte[EncryptionServices.ciIvOrSaltBytesLength];
                        //     _Cryptography.GetRandomBytes(abNewSalt);
                        //     _Database.abSalt = abNewSalt;
                        // 
                        //     _BackgroundThread.Enqueue(new BackgroundMessage(BackgroundMessage.nType.PasswordToKey, abReEncryptedPassword, abNewSalt));
                        //     StartBackgroundThread();
                        // }
                        // else
                        // {
                        //     ValidateRaiseErrorsChanged(nValidationType.Single, "abEncryptedPassword2", false, Translate("PasswordsDifferent"));
                        //     RaisePropertyChanged("sStatus");
                        // }
                        // Unencrypted passwords should not remain in working memory, so overwrite.
                        // _Cryptography.GetRandomBytes(abDecryptedPassword1);
                        // _Cryptography.GetRandomBytes(abDecryptedPassword2);
                    }
                    else
                    {

                    }
                }
                else
                {
                    _Database.Dispose();
                    _Database = null;
                }
            } */
        }

        /// <summary>Delegate method invoked by rcDecryptMessage.</summary>
        protected void ExecuteDecryptMessage()
        {

        }

        /// <summary>Delegate method invoked by rcEmptyPasswordOrPin.</summary>
        private void ExecuteEmptyPasswordOrPin()
        {
            iPasswordLength = 0;   // There is no direct access to the contents of the PasswordBox control, so this is the workaround.

            if (_ltTokens != null)
            {
                foreach (PgpToken Token in _ltTokens)
                {
                    if (Token.eType == PgpToken.nType.Private)   // lock all private keys
                        Token.Lock();
                }
            }
        }

        /// <summary>Delegate method invoked by rcF5.</summary>
        private void ExecuteF5()
        {
            if (isExecuteF5)
            {

            }
        }

        /// <summary>Delegate method invoked by rcIsClosing.</summary>
        protected override void ExecuteIsClosing()
        {
            if (_BackgroundThread != null)
            {
                _BackgroundThread.Dispose();
                _BackgroundThread = null;
            }
            if (_Cryptography != null)
            {
                _Cryptography.Dispose();
                _Cryptography = null;
            }
            if (_Database != null)
            {
                _Database.Dispose();
                _Database = null;
            }
            if (_RsaUiDecryptor != null)
            {
                _RsaUiDecryptor.Clear();
                _RsaUiDecryptor = null;
            }
            if (_RsaUiEncryptor != null)
            {
                _RsaUiEncryptor.Clear();
                _RsaUiEncryptor = null;
            }
        }

        /// <summary>Delegate method invoked by rcLogin.</summary>
        protected void ExecuteLogin()
        {
        }

        /// <summary>Delegate method invoked by rcReadMessage.</summary>
        protected void ExecuteReadMessage()
        {
            byte[] abMessageBytes;
            string sErrorMessage, sMatchedKeyMessage;
            PgpFile MessageFile;
            PgpMessage NewMessage = null;
            BytesAndTextUtility BytesAndText;

            if (isExecuteReadMessage)
            {
                MessageFile = new PgpFile();
                abMessageBytes = MessageFile.GetBytes(_sInputMessageFilePath, false);

                switch (MessageFile.eStatus)
                {
                    case PgpArmor.nStatus.CrcError: sErrorMessage = string.Format(sFileCrcError, _sInputKeyFilePath); break;
                    case PgpArmor.nStatus.ParseError: sErrorMessage = string.Format(sFileParseError, _sInputKeyFilePath); break;
                    case PgpArmor.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sInputKeyFilePath); break;
                    default: sErrorMessage = string.Empty; break;
                }

                if (string.IsNullOrEmpty(sErrorMessage))
                {
                    NewMessage = new PgpMessage(abMessageBytes, _Cryptography);

                    switch (NewMessage.eStatus)
                    {
                        case PgpMessage.nStatus.ParseErrorRaw: sErrorMessage = string.Format(sFileParseError, _sInputMessageFilePath); break;
                        case PgpMessage.nStatus.ParseErrorSub: sErrorMessage = string.Format(sFileParseErrorSub, _sInputMessageFilePath); break;
                        case PgpMessage.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sInputMessageFilePath); break;
                        default: sErrorMessage = string.Empty; break;
                    }
                }

                if (string.IsNullOrEmpty(sErrorMessage))
                {
                    if (NewMessage != null)   // just to be sure, but this should always be true 
                    {
                        NewMessage.MatchPublicKeys(_ltTokens);
                        BytesAndText = new BytesAndTextUtility();

                        foreach (PgpPublicKeyEncryptedKey WrappedKey in NewMessage.ltPublicKeyEncryptedKeys)
                        {
                            if (WrappedKey.MatchedPublicKey == null)
                            {
                                BytesAndText.abBytes = WrappedKey.abPublicKeyId;
                                sMatchedKeyMessage = string.Format(sPublicKeyNotMatched, BytesAndText.sHexadecimalBytes);
                            }
                            else
                                sMatchedKeyMessage = string.Format(sPublicKeyMatched, WrappedKey.sUserId);

                            _blMessages.Add(new Property(DateTime.Now, sMatchedKeyMessage));
                        }
                    }
                }
                else
                {
                    _blMessages.Add(new Property(DateTime.Now, sErrorMessage));
                    eMenuTab = nMenuTab.Progress;
                }
            }
        }

        /// <summary>Delegate method invoked by rcReadKeyFile.</summary>
        private void ExecuteReadKeyFile()
        {
            byte[] abKeyBytes = null;
            long kFileSize;
            string sErrorMessage;
            PgpFile KeyFile;
            PgpToken NewToken = null;

            if (isExecuteReadKeyFile)
            {
                KeyFile = new PgpFile();
                kFileSize = KeyFile.GetFileSize(_sInputKeyFilePath);

                if (kFileSize > PgpFile.ckMaxKeyFileSize)
                {
                    sErrorMessage = string.Format(sKeyFileTooLarge, _sInputKeyFilePath);
                }
                else
                {
                    abKeyBytes = KeyFile.GetBytes(_sInputKeyFilePath, true);

                    switch (KeyFile.eStatus)
                    {
                        case PgpArmor.nStatus.CrcError: sErrorMessage = string.Format(sFileCrcError, _sInputKeyFilePath); break;
                        case PgpArmor.nStatus.ParseError: sErrorMessage = string.Format(sFileParseError, _sInputKeyFilePath); break;
                        case PgpArmor.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sInputKeyFilePath); break;
                        default: sErrorMessage = string.Empty; break;
                    }
                }

                if (string.IsNullOrEmpty(sErrorMessage))
                {
                    NewToken = new PgpToken(abKeyBytes, _ltTokens, _Cryptography);

                    switch (NewToken.eStatus)
                    {
                        case PgpToken.nStatus.ParseErrorRaw: sErrorMessage = string.Format(sFileParseError, _sInputKeyFilePath); break;
                        case PgpToken.nStatus.ParseErrorSub: sErrorMessage = string.Format(sFileParseErrorSub, _sInputKeyFilePath); break;
                        case PgpToken.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sInputKeyFilePath); break;
                        default: sErrorMessage = string.Empty; break;
                    }
                }

                if (string.IsNullOrEmpty(sErrorMessage))
                {
                    if (NewToken != null)   // just to be sure, but this should always be true 
                    {
                        if (_ltTokens.Contains(NewToken))
                        {
                            _blMessages.Add(new Property(DateTime.Now, sDuplicateTokenError));
                            eMenuTab = nMenuTab.Progress;
                        }
                        else
                        {
                            _ltTokens.Add(NewToken);
                            RequeryDisplayedTokens();
                            sInputKeyFilePath = string.Empty;
                        }
                    }
                }
                else
                {
                    _blMessages.Add(new Property(DateTime.Now, sErrorMessage));
                    eMenuTab = nMenuTab.Progress;
                }
            }
        }

        /// <summary>Delegate method invoked by rcReadTokens.</summary>
        protected void ExecuteReadTokens()
        {
            // Console.WriteLine("ExecuteReadTokens start " + DateTime.Now.ToString("mm:ss fff"));
            _Cryptography.ReadTokens(_ltTokens);
            // Console.WriteLine("ExecuteReadTokens end   " + DateTime.Now.ToString("mm:ss fff"));

            RequeryDisplayedTokens();
        }

        /// <summary>Delegate method invoked by rcSelectInputMessage.</summary>
        private void ExecuteSelectInputMessage()
        {
            sInputMessageFilePath = OpenFileDialog(ref _sInputMessageFilePath, sSelectInputMessage);
        }

        /// <summary>Delegate method invoked by rcSelectKey.</summary>
        private void ExecuteSelectKey()
        {
            sInputKeyFilePath = OpenFileDialog(ref _sInputKeyFilePath, sSelectKeyFile);
        }

        /// <summary>Delegate method invoked by rcUnlockKey.</summary>
        private void ExecuteUnlockKey()
        {
        }

        /// <summary></summary>
        private string OpenFileDialog(ref string sFilePath, string sDialogTitle)
        {
            string sInitialDirectory, sReturn = sFilePath;

            if (string.IsNullOrEmpty(sFilePath))
                sInitialDirectory = string.Empty;
            else
                sInitialDirectory = Path.GetFullPath(sFilePath);

            if (string.IsNullOrEmpty(sInitialDirectory))
                sInitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            using (System.Windows.Forms.OpenFileDialog FileDialog = new System.Windows.Forms.OpenFileDialog
            {
                Title = sDialogTitle,
                InitialDirectory = sInitialDirectory,
                // DefaultExt = sDefaultExtension,
                FilterIndex = 1,
                Filter = sAllFiles + " (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            })
            {
                if (FileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    sReturn = FileDialog.FileName;
            }
            return sReturn;
        }

        private void RaisePropertyChangedDbWithPassword()
        {
            // iPassword1Length = iPassword2Length = 0;
            RaisePropertyChanged("isDatabaseWithPassword");
            RaisePropertyChanged("isDatabaseWithToken");
            RaisePropertyChanged("sPinOrPassword");
            RaisePropertyChanged("sTokenOrPassword");
            RaisePropertyChanged("iPasswordMaxLength");
            RaisePropertyChanged("VisibleWhenWithToken");
            RaisePropertyChanged("VisibleWhenWithPassword");
        }

        /// <summary></summary>
        private string GetDatabasePath(string sName)
        {
            return _sDatabaseDirectory + ccDirectorySeparator + sName + SQLiteDatabase.csDatabaseExtension;
        }

        /// <summary></summary>
        private void InitialiseCryptography()
        {
            _Cryptography = new EncryptionServices();
            _BackgroundThread = new BackgroundThread(_Cryptography);

            if (_blMessages != null)
                _blMessages.Add(new Property(DateTime.Now, string.Format(Translate(_Cryptography.isWithOpenSc ? "OpenScFound" : "OpenScNotFound"), _Cryptography.sPkcs11Library)));

            if (_Cryptography.isWithOpenSc)
            {
                if (_blMessages != null)
                    _blMessages.Add(new Property(DateTime.Now, string.Format(sOpenScInformation, _Cryptography.Pkcs11LibraryDescription, _Cryptography.Pkcs11LibraryVersion, _Cryptography.Pkcs11LibraryManufacturer, _Cryptography.Pkcs11LibraryCryptokiVersion)));

                ExecuteReadTokens();
            }

            _RsaUiDecryptor = new RSACng(ciUserInterfacePasswordEncryptionStrength);  // create a private RSA key
            _RsaUiEncryptor = new RSACng(512);   // initialise with the smallest key size possible, it will be overwritten anyway
            _RsaUiEncryptor.ImportParameters(_RsaUiDecryptor.ExportParameters(false));   // copy the RSA public key for the password boxes
        }

        /// <summary></summary>
        private void InitialiseTranslations()
        {
            _dyTranslations = new Dictionary<string, string>
            {
#if ENGLISH
                { "AllFiles", "All files" },
                { "Authenticate", "authenticate" },
                { "BitsText", "Bits" },
                { "Cancel", "Cancel" },
                { "CasualCertificationText", "Casual Certification (less secure)" },
                { "Certify", "certify" },
                { "Close", "Close" },
                { "CommentText", "Comment" },
                { "Create", "Create" },
                { "CreatedKeyText", "key created" },
                { "CreatedSignatureText", "signature created" },
                { "Data", "Data" },
                { "DatabaseNameExists", "A database with this name already exists." },
                { "DatabaseNameText", "Database name" },
                { "DateTimeFormat", "yyyy-MM-dd HH:mm:ss" },
                { "Decrypt", "decrypt" },
                { "DuplicateTokenError", "Key or token already exists." },
                { "Encrypt", "encrypt" },
                { "EmailText", "eMail" },
                { "Empty", "Empty" },
                { "EncryptedDatabase", "EncryptedDatabase" },
                { "EnterPassword1", "Enter password" },
                { "EnterPassword2", "Repeat password" },
                { "Error", "Error" },
                { "ExpiresText", "expires" },
                { "ExponentText", "exponent e" },
                { "FileCrcError", "Integrity error: wrong CRC check sum in file »{0:s}«." },
                { "FileError", "Error reading file »{0:s}«." },
                { "FileParseError", "Error interpreting file »{0:s}«." },
                { "FileParseErrorSub", "Error interpreting a packet in file »{0:s}«." },
                { "FingerprintText", "SHA-1" },
                { "FunctionsText", "Function(s)" },
                { "GenericCertificationText", "Generic Certification (insecure)" },
                { "HashAlgorithmText", "hash algorithm" },
                { "InputFileDoesNotExist", "This input file does not exist." },
                { "InputFileText", "Input file" },
                { "KeyFileText", "Key file" },
                { "KeyFileDoesNotExist", "This key file does not exist." },
                { "KeyFileTooLarge", "The file »{0:s}« is too large for a key file." },
                { "KeyNotFoundText", "Key not found" },
                { "KeysOrTokensText", "Keys or tokens" },
                { "Keys", "Keys" },
                { "Login", "Login" },
                { "MasterKeyFingerprintText", "SHA-1 master key" },
                { "MessageText", "message" },
                { "ModulusText", "modulus p * q" },
                { "NameText", "Name" },
                { "NeverText", "never" },
                { "NewDatabase", "New database" },
                { "None", "none" },
                { "OpenScFound", "The OpenSC library »{0:s}« was found." },
                { "OpenScInformation", "OpenSC library information: »{0:s}« version {1:s} of »{2:s}« with Cryptoki version {3:s}." },
                { "OpenScNotFound", "The OpenSC library was not found." },
                { "PassphraseOrPinText", "Passphrase or PIN" },
                { "PasswordsDifferent", "The passwords are not identical." },
                { "PendingText", "pending" },
                { "PersonaCertificationText", "Persona Certification (insecure)" },
                { "Pin", "Pin" },
                { "PositiveCertificationText", "Positive Certification (secure)" },
                { "Private", "private" },
                { "ProgramVersion", "Program version " + sProgramVersion + " of 06/09/2020 is ready." },
                { "Progress", "Progress" },
                { "PropertyText", "Property" },
                { "Public", "public" },
                { "PublicKeyAlgorithmText", "for algorithm" },
                { "PublicKeyMatched", "Encrypted for {0:s}." },
                { "PublicKeyNotMatched", "Encrypted for unknown ID {0:s}." },
                { "Read", "Read" },
                { "ReadTokens", "Read tokens" },
                { "RsaEncryptOrSignText", "RSA, encrypt or sign" },
                { "RsaEncryptOnlyText", "RSA, encrypt only" },    
                { "RsaSignOnlyText", "RSA, sign only" },
                { "Select", "Select" },
                { "SelectInputMessage", "Select input message" },
                { "SelectKeyFile", "Select key file" },
                { "Setup", "Setup" },
                { "Sign", "sign" },
                { "SignatureTypeText", "signature type" },
                { "SubkeyBindingText", "Subkey Binding" },
                { "SubkeysText", "Subkeys" },
                { "Symmetric", "Symmetric" },
                { "TimeText", "time" },
                { "TypeText", "Type" },
                { "User", "User" },
                { "ValueText", "Value" },
                { "VerifiedFalseText", "ERROR" },
                { "VerifiedText", "verified" },
                { "VerifiedTrueText", "yes" },
                { "VerifyAuthenticity", "verify authenticity" },
                { "VerifyCertificates", "verify certificates" },
                { "VerifySignatures", "verify signatures" },
                { "WindowTitle", "OpenDear - Open-source Double Encryption And Re-encryption" },
                { "WithPassword", "with password" },
                { "WithToken", "with token" },
                { "Yes", "yes" }
#elif DEUTSCH
                { "AllFiles", "Alle Dateien" },
                { "Authenticate", "sich authentisieren" },
                { "BitsText", "Bit" },
                { "Cancel", "Abbrechen" },
                { "CasualCertificationText", "Beiläufige Zertifizierung (weniger sicher)" },
                { "Certify", "zertifizieren" },
                { "Close", "Schließen" },
                { "CommentText", "Kommentar" },
                { "Create", "Anlegen" },
                { "CreatedKeyText", "Schlüssel erstellt" },
                { "CreatedSignatureText", "Signatur erstellt" },
                { "Data", "Daten" },
                { "DatabaseNameExists", "Eine Datenbank mit diesem Namen existiert bereits." },
                { "DatabaseNameText", "Datenbankname" },
                { "DateTimeFormat", "dd.MM.yyyy HH:mm:ss" },
                { "Decrypt", "Entschlüsseln" },
                { "DuplicateTokenError", "Schlüssel oder Token existiert bereits." },
                { "EmailText", "E-Mail" },
                { "Empty", "Leeren" },
                { "Encrypt", "verschlüsseln" },
                { "EncryptedDatabase", "Datenbank" },
                { "EnterPassword1", "Passwort eingeben" },
                { "EnterPassword2", "Passwort wiederholen" },
                { "Error", "Fehler" },
                { "ExpiresText", "Schlüssel läuft ab" },
                { "ExponentText", "Exponent e" },
                { "FileCrcError", "Integritätsfehler: falsche CRC-Prüfsumme in Datei »{0:s}«." },
                { "FileError", "Fehler beim Lesen der Datei »{0:s}«." },
                { "FileParseError", "Fehler beim Interpretieren der Datei »{0:s}«." },
                { "FileParseErrorSub", "Fehler beim Interpretieren eines Pakets in Datei »{0:s}«." },
                { "FingerprintText", "SHA-1" },
                { "FunctionsText", "Funktion(en)" },
                { "GenericCertificationText", "Generische Zertifizierung (unsicher)" },
                { "HashAlgorithmText", "Hashalgorithmus" },
                { "InputFileDoesNotExist", "Diese Eingabedatei existiert nicht." },
                { "InputFileText", "Eingabedatei" },
                { "KeyFileText", "Schlüsseldatei" },
                { "KeyFileTooLarge", "Die Datei »{0:s}« ist zu groß für eine Schlüsseldatei." },
                { "KeyFileDoesNotExist", "Diese Schlüsseldatei existiert nicht." },
                { "KeyNotFoundText", "Schlüssel nicht gefunden" },
                { "KeysOrTokensText", "Schlüssel oder Token" },
                { "Keys", "Schlüssel" },
                { "Login", "Anmelden" },
                { "MasterKeyFingerprintText", "SHA-1 Oberschlüssel" },
                { "MessageText", "Nachricht" },
                { "ModulusText", "Modul p * q" },
                { "NameText", "Name" },
                { "NeverText", "nie" },
                { "NewDatabase", "Neue Datenbank" },
                { "None", "keine" },
                { "OpenScFound", "Die OpenSC-Bibliothek »{0:s}« wurde gefunden." },
                { "OpenScInformation", "OpenSC-Bibliotheksinformation: »{0:s}« Version {1:s} von »{2:s}« mit Cryptoki-Version {3:s}." },
                { "OpenScNotFound", "Die OpenSC-Bibliothek wurde nicht gefunden." },
                { "PassphraseOrPinText", "Passphrase oder PIN" },
                { "PasswordsDifferent", "Die Passwörter sind nicht identisch." },
                { "PendingText", "ausstehend" },
                { "PersonaCertificationText", "Persona-Zertifizierung (unsicher)" },
                { "Pin", "Pin" },
                { "PositiveCertificationText", "Positive Zertifizierung (sicher)" },
                { "Private", "privat" },
                { "ProgramVersion", "Die Programmversion " + sProgramVersion + " vom 06.09.2020 ist bereit." },
                { "Progress", "Verlauf" },
                { "PropertyText", "Eigenschaft" },
                { "Public", "öffentlich" },
                { "PublicKeyAlgorithmText", "für Algorithmus" },
                { "PublicKeyMatched", "Verschlüsselt für {0:s}." },
                { "PublicKeyNotMatched", "Verschlüsselt für unbekannte ID {0:s}." },
                { "Read", "Einlesen" },
                { "ReadTokens", "Token lesen" },
                { "RsaEncryptOrSignText", "RSA, verschlüsseln oder signieren" },
                { "RsaEncryptOnlyText", "RSA, nur verschlüsseln" },
                { "RsaSignOnlyText", "RSA, nur signieren" },
                { "Select", "Auswählen" },
                { "SelectInputMessage", "Eingabenachricht auswählen" },
                { "SelectKeyFile", "Schlüsseldatei auswählen" },
                { "Setup", "Einrichtung" },
                { "Sign", "signieren" },
                { "SignatureTypeText", "Signaturtyp" },
                { "SubkeyBindingText", "Unterschlüssel binden" },
                { "SubkeysText", "Unterschlüssel" },
                { "Symmetric", "Symmetrisch" },
                { "TimeText", "Zeit" },
                { "TypeText", "Typ" },
                { "User", "Benutzer" },
                { "ValueText", "Wert" },
                { "VerifiedFalseText", "FEHLER" },
                { "VerifiedText", "verifiziert" },
                { "VerifiedTrueText", "ja" },
                { "VerifyAuthenticity", "Authentizität prüfen" },
                { "VerifyCertificates", "Zertifikate prüfen" },
                { "VerifySignatures", "Signaturen prüfen" },
                { "WindowTitle", "OpenDear - Quelloffenes Doppeltes Verschlüsseln und Umschlüsseln" },
                { "WithPassword", "mit Passwort" },
                { "WithToken", "mit Token" },
                { "Yes", "ja" }
#endif
            };
        }

        private void ReadAndDisplayDatabases()
        {
            DirectoryInfo DatabaseDirectoryInfo;
            Property NewProperty;
            int iDatabaseId;

            _sDatabaseDirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + ccDirectorySeparator + csApplicationName;
            _blDatabases.Clear();

            if (!Directory.Exists(_sDatabaseDirectory))
            {
                // TODO try + error message
                Directory.CreateDirectory(_sDatabaseDirectory);
            }

            if (Directory.Exists(_sDatabaseDirectory))
            {
                iDatabaseId = 1;
                DatabaseDirectoryInfo = new DirectoryInfo(_sDatabaseDirectory);

                foreach (FileInfo DatabaseFileInfo in DatabaseDirectoryInfo.GetFiles("*" + SQLiteDatabase.csDatabaseExtension, SearchOption.TopDirectoryOnly))
                {
                    NewProperty = new Property(iDatabaseId, 0, DatabaseFileInfo.Name.Substring(0, DatabaseFileInfo.Name.Length - SQLiteDatabase.csDatabaseExtension.Length));
                    _blDatabases.Add(NewProperty);
                }
            }
        }

        /// <summary></summary>
        private void RequeryDisplayedSubkeyProperties()
        {
            string sCreatedKey, sCreatedSignature, sExpires, sExponent, sFingerprint, sHashAlgorithm, sMasterKeyFingerprint, sModulus, sPublicKeyAlgorithm, sSignatureType, sVerified;
            DateTime? CreatedKey, CreatedSignature, Expires;
            BytesAndTextUtility BytesAndText;

            SelectedSubkeyProperty = null;
            _blSubkeyProperties.Clear();

            if (_SelectedSubkey != null)
            {
                switch (_SelectedSubkey.eVerified)
                {
                    case PgpSignature.nVerified.False: sVerified = sVerifiedFalseText; break;
                    case PgpSignature.nVerified.KeyNotFound: sVerified = sKeyNotFoundText; break;
                    case PgpSignature.nVerified.Pending: sVerified = sPendingText; break;
                    case PgpSignature.nVerified.True: sVerified = sVerifiedTrueText; break;
                    default: sVerified = string.Empty; break;
                }

                switch (_SelectedSubkey.eSignatureType)
                {
                    case PgpPacketBase.nSignatureType.GenericCertification: sSignatureType = sGenericCertificationText; break;
                    case PgpPacketBase.nSignatureType.PersonaCertification: sSignatureType = sPersonaCertificationText; break;
                    case PgpPacketBase.nSignatureType.CasualCertification: sSignatureType = sCasualCertificationText; break;
                    case PgpPacketBase.nSignatureType.PositiveCertification: sSignatureType = sPositiveCertificationText; break;
                    case PgpPacketBase.nSignatureType.SubkeyBinding: sSignatureType = sSubkeyBindingText; break;
                    default: sSignatureType = string.Empty; break;
                }

                switch (_SelectedSubkey.ePublicKeyAlgorithm)
                {
                    case PgpPacketBase.nPublicKeyAlgorithm.RsaEncryptOrSign: sPublicKeyAlgorithm = sRsaEncryptOrSignText; break;
                    case PgpPacketBase.nPublicKeyAlgorithm.RsaEncryptOnly: sPublicKeyAlgorithm = sRsaEncryptOnlyText; break;
                    case PgpPacketBase.nPublicKeyAlgorithm.RsaSignOnly: sPublicKeyAlgorithm = sRsaSignOnlyText; break;
                    default: sPublicKeyAlgorithm = string.Empty; break;
                }

                switch (_SelectedSubkey.eHashAlgorithm)
                {
                    case PgpPacketBase.nHashAlgorithm.Sha1: sHashAlgorithm = csSha1; break;
                    case PgpPacketBase.nHashAlgorithm.Sha224: sHashAlgorithm = csSha224; break;
                    case PgpPacketBase.nHashAlgorithm.Sha256: sHashAlgorithm = csSha256; break;
                    case PgpPacketBase.nHashAlgorithm.Sha384: sHashAlgorithm = csSha384; break;
                    case PgpPacketBase.nHashAlgorithm.Sha512: sHashAlgorithm = csSha512; break;
                    default: sHashAlgorithm = string.Empty; break;
                }

                CreatedKey = _SelectedSubkey.CreatedKey;
                sCreatedKey = (CreatedKey == null) ? string.Empty : CreatedKey.Value.ToLocalTime().ToString(sDateTimeFormat);

                CreatedSignature = _SelectedSubkey.CreatedSignature;
                sCreatedSignature = (CreatedSignature == null) ? string.Empty : CreatedSignature.Value.ToLocalTime().ToString(sDateTimeFormat);

                Expires = _SelectedSubkey.Expires;
                sExpires = (Expires == null) ? sNeverText : Expires.Value.ToLocalTime().ToString(sDateTimeFormat);

                BytesAndText = new BytesAndTextUtility(_SelectedSubkey.abMasterKeyFingerprint);
                sMasterKeyFingerprint = BytesAndText.sHexadecimalBytes;

                BytesAndText.abBytes = _SelectedSubkey.abFingerprint;
                sFingerprint = BytesAndText.sHexadecimalBytes;

                BytesAndText.abBytes = _SelectedSubkey.abModulus;
                sModulus = BytesAndText.sHexadecimalBytes;

                BytesAndText.abBytes = _SelectedSubkey.abExponent;
                sExponent = BytesAndText.sHexadecimalBytes;

                AddSubkeyProperty(nSubkeyProperty.Verified, sVerifiedText, sVerified);
                AddSubkeyProperty(nSubkeyProperty.SignatureType, sSignatureTypeText, sSignatureType);
                AddSubkeyProperty(nSubkeyProperty.PublicKeyAlgorithm, sPublicKeyAlgorithmText, sPublicKeyAlgorithm);
                AddSubkeyProperty(nSubkeyProperty.HashAlgorithm, sHashAlgorithmText, sHashAlgorithm);
                AddSubkeyProperty(nSubkeyProperty.CreatedKey, sCreatedKeyText, sCreatedKey);
                AddSubkeyProperty(nSubkeyProperty.CreatedSignature, sCreatedSignatureText, sCreatedSignature);
                AddSubkeyProperty(nSubkeyProperty.Expires, sExpiresText, sExpires);
                AddSubkeyProperty(nSubkeyProperty.MasterKeyFingerprint, sMasterKeyFingerprintText, sMasterKeyFingerprint);
                AddSubkeyProperty(nSubkeyProperty.Fingerprint, sFingerprintText, sFingerprint);
                AddSubkeyProperty(nSubkeyProperty.Modulus, sModulusText, sModulus);
                AddSubkeyProperty(nSubkeyProperty.Exponent, sExponentText, sExponent);

                if (_SelectedSubkey.PrivateKeyPacket != null)
                {

                }
            }
        }

        /// <summary></summary>
        private void RequeryDisplayedSubkeys()
        {
            SelectedSubkey = null;
            _blSubkeys.Clear();

            if ((_SelectedToken != null) && (_SelectedToken.ltSubkeys != null))
            {
                foreach (PgpSignature FoundSubkey in _SelectedToken.ltSubkeys)   // even though the name 'foreach' does not tell, it returns the objects in order
                    _blSubkeys.Add(FoundSubkey);
            }
        }

        /// <summary></summary>
        private void RequeryDisplayedTokens()
        {
            IEnumerable<PgpToken> qyFoundTokens;

            SelectedToken = null;
            _blTokens.Clear();

            if (_ltTokens != null)
            {
                qyFoundTokens = from t in _ltTokens orderby t.sName select t;

                foreach (PgpToken FoundToken in qyFoundTokens)   // even though the name 'foreach' does not tell, it returns the objects in order
                    _blTokens.Add(FoundToken);

                if (_blTokens.Count == 1)
                    SelectedToken = _blTokens.First();
            }
        }

        private void StartBackgroundThread(int iMaxProgressBar = -1)
        {
            if (_BackgroundThread.Start())
            {
                if (iMaxProgressBar < 0)
                {
                    isProgressBarIndeterminate = true;
                }
                else
                {
                    iProgressBarValue = 0;
                    iProgressBarMaximum = iMaxProgressBar;
                    isProgressBarIndeterminate = false;
                }
                _UserInterfaceTimer.Start();
            }
        }

        /// <summary>Timer event handler that updates the user interface in regular intervals.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        private void UserInterfaceTimerTick(object sender, EventArgs e)
        {
            bool isProgressChanged = false;

            Console.WriteLine("Tick");

            while (!_BackgroundThread.quReturn.IsEmpty)
            {
                _BackgroundThread.quReturn.TryDequeue(out BackgroundMessage UserInterfaceMessage);

                if (UserInterfaceMessage != null)
                {
                    switch (UserInterfaceMessage.eType)
                    {
                        case BackgroundMessage.nType.PasswordToKey:
                            byte[] abAesKey = _Cryptography.DecryptAes(UserInterfaceMessage.abKeyOrPassword, _BackgroundThread.abAesKey);

                            Console.Write("abAesKey = ");

                            for (int i = 0; i < abAesKey.Length; i++)
                                Console.Write(abAesKey[i].ToString("x2") + " ");

                            Console.WriteLine();
                            _Database.TryLogin(abAesKey);
                            break;

                        case BackgroundMessage.nType.Stop:
                            if (_UserInterfaceTimer.IsEnabled)
                                _UserInterfaceTimer.Stop();

                            isProgressBarIndeterminate = false;
                            _iProgressBarValue = 0;
                            iProgressBarMaximum = ciProgrssBarDefaultMaximum;
                            isProgressChanged = true;
                            _sBackgroundStatus = string.Empty;

                            break;
                    }
                }
            }

            if (isProgressChanged)
            {
                RaisePropertyChanged("iProgressBarValue");
                RaisePropertyChanged("sStatus");
                // CommandManager.InvalidateRequerySuggested();
            }
        }

        #endregion
    }
}