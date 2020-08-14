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
            _isDatabaseWithPassword = _isProgressBarIndeterminate = false;
            _iErrorId = _iPassword1Length = _iPassword2Length = _iProgressBarValue = _iUserPinLength = 0;
            _iProgressBarMaximum = ciProgrssBarDefaultMaximum;
            _sBackgroundStatus = _sDatabaseDirectory = _sErrorMessage = _sImportKeyFilePath = _sNewDatabaseName = string.Empty;
            _abEncryptedPassword1 = _abEncryptedPassword2 = _abEncryptedUserPin = null;
            _eMenuTab = nMenuTab.Keys;
            _Database = null;

            rcClose = new RelayCommand(ExecuteClose);
            rcCreateDatabase = new RelayCommand(ExecuteCreateDatabase, CanExecuteCreateDatabase);
            rcF5 = new RelayCommand(ExecuteF5, CanExecuteF5);
            rcIsClosing = new RelayCommand(ExecuteIsClosing, CanExecuteIsClosing);
            rcLogin = new RelayCommand(ExecuteLogin, CanExecuteLogin);
            rcRefreshTokens = new RelayCommand(ExecuteRefreshTokens);
            rcImportKey = new RelayCommand(ExecuteImportKey, CanExecuteImportKey);
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

        /// <summary></summary>
        private bool CanExecuteCreateDatabase()
        {
            return isExecuteCreateDatabase;
        }

        /// <summary></summary>
        protected bool CanExecuteF5()
        {
            return isExecuteF5;
        }

        /// <summary></summary>
        private bool CanExecuteLogin()
        {
            return isExecuteLogin;
        }

        /// <summary></summary>
        private bool CanExecuteImportKey()
        {
            return isExecuteImportKey;
        }

        /// <summary></summary>
        private bool CanExecuteUnlockKey()
        {
            return isExecuteUnlockKey;
        }

        /// <summary>Delegate method invoked by rcCreateDatabase.</summary>
        private void ExecuteCreateDatabase()
        {
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
                        abDecryptedPassword1 = _RsaUiDecryptor.Decrypt(_abEncryptedPassword1, RSAEncryptionPadding.Pkcs1);
                        abDecryptedPassword2 = _RsaUiDecryptor.Decrypt(_abEncryptedPassword2, RSAEncryptionPadding.Pkcs1);
                        PasswordBytes = new BytesAndTextUtility(abDecryptedPassword1, abDecryptedPassword2);

                        if (PasswordBytes.isAllBytesEqual)   // This necessary test somewhat endangers password safety because this is plain text.
                        {
                            abReEncryptedPassword = _Cryptography.EncryptAes(abDecryptedPassword1, _BackgroundThread.abAesKey);
                            abNewSalt = new byte[EncryptionServices.ciIvOrSaltBytesLength];
                            _Cryptography.GetRandomBytes(abNewSalt);
                            _Database.abSalt = abNewSalt;

                            _BackgroundThread.Enqueue(new BackgroundMessage(BackgroundMessage.nType.PasswordToKey, abReEncryptedPassword, abNewSalt));
                            StartBackgroundThread();
                        }
                        else
                        {
                            ValidateRaiseErrorsChanged(nValidationType.Single, "abEncryptedPassword2", false, Translate("PasswordsDifferent"));
                            RaisePropertyChanged("sStatus");
                        }
                        // Unencrypted passwords should not remain in working memory, so overwrite.
                        _Cryptography.GetRandomBytes(abDecryptedPassword1);
                        _Cryptography.GetRandomBytes(abDecryptedPassword2);
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

        /// <summary>Delegate method invoked by rcRefreshTokens.</summary>
        protected void ExecuteRefreshTokens()
        {

        }

        /// <summary>Delegate method invoked by rcImportKey.</summary>
        private void ExecuteImportKey()
        {
            byte[] abKeyBytes;
            string sErrorMessage;
            PgpFile KeyFile;
            PgpToken NewToken = null;

            if (isExecuteImportKey)
            {
                KeyFile = new PgpFile();
                abKeyBytes = KeyFile.GetBytes(_sImportKeyFilePath);

                switch (KeyFile.eStatus)
                {
                    case PgpArmor.nStatus.CrcError: sErrorMessage = string.Format(sFileCrcError, _sImportKeyFilePath); break;
                    case PgpArmor.nStatus.ParseError: sErrorMessage = string.Format(sFileParseError, _sImportKeyFilePath); break;
                    case PgpArmor.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sImportKeyFilePath); break;
                    default: sErrorMessage = string.Empty; break;
                }

                if (string.IsNullOrEmpty(sErrorMessage))
                {
                    NewToken = new PgpToken(abKeyBytes, _Cryptography);

                    switch (NewToken.eStatus)
                    {
                        case PgpToken.nStatus.ParseErrorRaw: sErrorMessage = string.Format(sFileParseError, _sImportKeyFilePath); break;
                        case PgpToken.nStatus.ParseErrorSub: sErrorMessage = string.Format(sFileParseErrorSub, _sImportKeyFilePath); break;
                        case PgpToken.nStatus.Undefined: sErrorMessage = string.Format(sFileError, _sImportKeyFilePath); break;
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
                        }
                        else
                        {
                            _ltTokens.Add(NewToken);
                            RequeryDisplayedTokens();
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

        /// <summary>Delegate method invoked by rcSelectKey.</summary>
        private void ExecuteSelectKey()
        {
            OpenFileDialog();
        }

        /// <summary>Delegate method invoked by rcUnlockKey.</summary>
        private void ExecuteUnlockKey()
        {
        }

        /// <summary></summary>
        private void OpenFileDialog()
        {
            string sInitialDirectory = string.Empty;

            if (!string.IsNullOrEmpty(_sImportKeyFilePath))
                sInitialDirectory = Path.GetFullPath(_sImportKeyFilePath);

            if (string.IsNullOrEmpty(sInitialDirectory))
                sInitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            using (System.Windows.Forms.OpenFileDialog FileDialog = new System.Windows.Forms.OpenFileDialog
            {
                Title = sSelectKeyFile,
                InitialDirectory = sInitialDirectory,
                // DefaultExt = sDefaultExtension,
                FilterIndex = 1,
                Filter = sAllFiles + " (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            })
            {
                if (FileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    sImportKeyFilePath = FileDialog.FileName;
                }
            }
        }

        private void RaisePropertyChangedDbWithPassword()
        {
            iPassword1Length = iPassword2Length = 0;
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

                ExecuteRefreshTokens();
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
                { "BitsText", "Bits" },
                { "Cancel", "Cancel" },
                { "Close", "Close" },
                { "CommentText", "Comment" },
                { "Create", "Create" },
                { "Data", "Data" },
                { "DatabaseNameExists", "A database with this name already exists." },
                { "DatabaseNameText", "Database name" },
                { "DuplicateTokenError", "Key or token already exists." },
                { "EmailText", "eMail" },
                { "EncryptedDatabase", "EncryptedDatabase" },
                { "EnterPassword1", "Enter password" },
                { "EnterPassword2", "Repeat password" },
                { "Error", "Error" },
                { "FileCrcError", "Integrity error: wrong CRC check sum in file »{0:s}«." },
                { "FileError", "Error reading file »{0:s}«." },
                { "FileParseError", "Error interpreting file »{0:s}«." },
                { "FileParseErrorSub", "Error interpreting a packet in file »{0:s}«." },
                { "FunctionsText", "Functions" },
                { "Import", "Import" },
                { "KeyFileText", "Key file" },
                { "KeyFileDoesNotExist", "This key file does not exist." },
                { "KeysOrTokensText", "Key or Token" },
                { "Keys", "Keys" },
                { "Login", "Login" },
                { "MessageText", "message" },
                { "NameText", "Name" },
                { "NewDatabase", "New database" },
                { "OpenScFound", "The OpenSC library »{0:s}« was found." },
                { "OpenScInformation", "OpenSC library information: »{0:s}« version {1:s} of »{2:s}« with Cryptoki version {3:s}." },
                { "OpenScNotFound", "The OpenSC library was not found." },
                { "PasswordsDifferent", "The passwords are not identical." },
                { "Pin", "Pin" },
                { "Private", "Private" },
                { "ProgramVersion", "Program version " + sProgramVersion + " of 14/08/2020 is ready." },
                { "Progress", "Progress" },
                { "Public", "Public" },
                { "RefreshTokens", "Refresh tokens" },
                { "Select", "Select" },
                { "SelectKeyFile", "Select key file" },
                { "Setup", "Setup" },
                { "SubkeysText", "Subkeys" },
                { "Symmetric", "Symmetric" },
                { "TimeText", "time" },
                { "TypeText", "Type" },
                { "User", "User" },
                { "WindowTitle", "OpenDear - Double Encryption And Re-encryption" },
                { "WithPassword", "with password" },
                { "WithToken", "with token" },
                { "Yes", "yes" }
#elif DEUTSCH
                { "AllFiles", "Alle Dateien" },
                { "BitsText", "Bit" },
                { "Cancel", "Abbrechen" },
                { "Close", "Schließen" },
                { "CommentText", "Kommentar" },
                { "Create", "Anlegen" },
                { "Data", "Daten" },
                { "DatabaseNameExists", "Eine Datenbank mit diesem Namen existiert bereits." },
                { "DatabaseNameText", "Datenbankname" },
                { "DuplicateTokenError", "Schlüssel oder Token existiert bereits." },
                { "EmailText", "E-Mail" },
                { "EncryptedDatabase", "Datenbank" },
                { "EnterPassword1", "Passwort eingeben" },
                { "EnterPassword2", "Passwort wiederholen" },
                { "Error", "Fehler" },
                { "FileCrcError", "Integritätsfehler: falsche CRC-Prüfsumme in Datei »{0:s}«." },
                { "FileError", "Fehler beim Lesen der Datei »{0:s}«." },
                { "FileParseError", "Fehler beim Interpretieren der Datei »{0:s}«." },
                { "FileParseErrorSub", "Fehler beim Interpretieren eines Pakets in Datei »{0:s}«." },
                { "FunctionsText", "Funktionen" },
                { "Import", "Einlesen" },
                { "KeyFileText", "Schlüsseldatei" },
                { "KeyFileDoesNotExist", "Diese Schlüsseldatei existiert nicht." },
                { "KeysOrTokensText", "Schlüssel oder Token" },
                { "Keys", "Schlüssel" },
                { "Login", "Anmelden" },
                { "MessageText", "Nachricht" },
                { "NameText", "Name" },
                { "NewDatabase", "Neue Datenbank" },
                { "OpenScFound", "Die OpenSC-Bibliothek »{0:s}« wurde gefunden." },
                { "OpenScInformation", "OpenSC-Bibliotheksinformation: »{0:s}« Version {1:s} von »{2:s}« mit Cryptoki-Version {3:s}." },
                { "OpenScNotFound", "Die OpenSC-Bibliothek wurde nicht gefunden." },
                { "PasswordsDifferent", "Die Passwörter sind nicht identisch." },
                { "Pin", "Pin" },
                { "Private", "Privat" },
                { "ProgramVersion", "Die Programmversion " + sProgramVersion + " vom 14.08.2020 ist bereit." },
                { "Progress", "Verlauf" },
                { "Public", "Öffentlich" },
                { "RefreshTokens", "Token neu lesen" },
                { "Select", "Auswählen" },
                { "SelectKeyFile", "Schlüsseldatei auswählen" },
                { "Setup", "Einrichtung" },
                { "SubkeysText", "Unterschlüssel" },
                { "Symmetric", "Symmetrisch" },
                { "TimeText", "Zeit" },
                { "TypeText", "Typ" },
                { "User", "Benutzer" },
                { "WindowTitle", "OpenDear - Doppeltes Verschlüsseln und Umschlüsseln" },
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
        private void RequeryDisplayedSubkeys()
        {
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

            _blTokens.Clear();

            if (_ltTokens != null)
            {
                qyFoundTokens = from t in _ltTokens orderby t.sName select t;

                foreach (PgpToken FoundToken in qyFoundTokens)   // even though the name 'foreach' does not tell, it returns the objects in order
                    _blTokens.Add(FoundToken);
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