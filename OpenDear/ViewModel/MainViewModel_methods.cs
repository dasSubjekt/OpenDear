namespace OpenDear.ViewModel
{
    using System;
    using System.IO;
    using OpenDear.Model;
    using OpenDear.Crypto;
    using System.ComponentModel;
    using System.Windows.Threading;
    using System.Collections.Generic;
    using System.Security.Cryptography;


    public partial class MainViewModel : ViewModelBase
    {
        #region constructors

        /// <summary>Initializes a new instance of the MainViewModel class.</summary>
        public MainViewModel() : base()
        {
            _dyTranslations = new Dictionary<string, string>
            {
#if ENGLISH
                { "Cancel", "Cancel" },
                { "Close", "Close" },
                { "Create", "Create" },
                { "Data", "Data" },
                { "DatabaseNameExists", "A database with this name already exists." },
                { "DatabaseNameText", "Database name" },
                { "EncryptedDatabase", "EncryptedDatabase" },
                { "EnterPassword1", "Enter password" },
                { "EnterPassword2", "Repeat password" },
                { "Keys", "Keys" },
                { "Login", "Login" },
                { "MessageText", "message" },
                { "NewDatabase", "New database" },
                { "OpenScFound", "The OpenSC library »{0:s}« was found." },
                { "OpenScInformation", "OpenSC library information: »{0:s}« version {1:s} of »{2:s}« with Cryptoki version {3:s}." },
                { "OpenScNotFound", "The OpenSC library was not found." },
                { "PasswordsDifferent", "The passwords are not identical." },
                { "Pin", "Pin" },
                { "ProgramVersion", "Program version " + sProgramVersion + " of 05/07/2020 is ready." },
                { "Progress", "Progress" },
                { "RefreshTokens", "Refresh tokens" },
                { "Setup", "Setup" },
                { "TimeText", "time" },
                { "User", "User" },
                { "WindowTitle", "OpenDear - Double Encryption And Re-encryption" },
                { "WithPassword", "with password" },
                { "WithToken", "with token" },
                { "Yes", "yes" }
#elif DEUTSCH
                { "Cancel", "Abbrechen" },
                { "Close", "Schließen" },
                { "Create", "Anlegen" },
                { "Data", "Daten" },
                { "DatabaseNameExists", "Eine Datenbank mit diesem Namen existiert bereits." },
                { "DatabaseNameText", "Datenbankname" },
                { "EncryptedDatabase", "Datenbank" },
                { "EnterPassword1", "Passwort eingeben" },
                { "EnterPassword2", "Passwort wiederholen" },
                { "Keys", "Schlüssel" },
                { "Login", "Anmelden" },
                { "MessageText", "Nachricht" },
                { "NewDatabase", "Neue Datenbank" },
                { "OpenScFound", "Die OpenSC-Bibliothek »{0:s}« wurde gefunden." },
                { "OpenScInformation", "OpenSC-Bibliotheksinformation: »{0:s}« Version {1:s} von »{2:s}« mit Cryptoki-Version {3:s}." },
                { "OpenScNotFound", "Die OpenSC-Bibliothek wurde nicht gefunden." },
                { "PasswordsDifferent", "Die Passwörter sind nicht identisch." },
                { "Pin", "Pin" },
                { "ProgramVersion", "Die Programmversion " + sProgramVersion + " vom 05.07.2020 ist bereit." },
                { "Progress", "Verlauf" },
                { "RefreshTokens", "Token neu lesen" },
                { "Setup", "Einrichtung" },
                { "TimeText", "Zeit" },
                { "User", "Benutzer" },
                { "WindowTitle", "OpenDear - Doppeltes Verschlüsseln und Umschlüsseln" },
                { "WithPassword", "mit Passwort" },
                { "WithToken", "mit Token" },
                { "Yes", "ja" }
#endif
            };

            _eMenuTab = nMenuTab.Setup;
            _iErrorId = _iPassword1Length = _iPassword2Length = _iProgressBarValue = _iUserPinLength = 0;
            _iProgressBarMaximum = ciProgrssBarDefaultMaximum;
            _isDatabaseWithPassword = _isProgressBarIndeterminate = false;
            _abEncryptedPassword1 = _abEncryptedPassword2 = _abEncryptedUserPin = null;
            _sBackgroundStatus = _sErrorMessage = _sNewDatabaseName = string.Empty;
            _ltValidationErrors = new List<Property>();
            _BackgroundThread = new BackgroundThread(_Cryptography);

            _Cryptography = new EncryptionServices();
            _RsaUiDecryptor = new RSACng(ciUserInterfacePasswordEncryptionStrength);  // create a private RSA key
            _RsaUiEncryptor = new RSACng(512);   // initialise with the smallest key size possible, it will be overwritten anyway
            _RsaUiEncryptor.ImportParameters(_RsaUiDecryptor.ExportParameters(false));   // copy the RSA public key for the password boxes

            _blDatabases = new BindingList<Property>();
            ReadAndDisplayDatabases();
            _Database = null;

            _blMessages = new BindingList<Property>
            {
                new Property(DateTime.Now, Translate("ProgramVersion")),
                new Property(DateTime.Now, string.Format(Translate(_Cryptography.isWithOpenSc ? "OpenScFound" : "OpenScNotFound"), _Cryptography.sPkcs11Library))
            };

            if (_Cryptography.isWithOpenSc)
            {
                _blMessages.Add(new Property(DateTime.Now, string.Format(Translate("OpenScInformation"), _Cryptography.Pkcs11LibraryDescription, _Cryptography.Pkcs11LibraryVersion, _Cryptography.Pkcs11LibraryManufacturer, _Cryptography.Pkcs11LibraryCryptokiVersion)));
                ExecuteRefreshTokens();
            }

            _UserInterfaceTimer = new DispatcherTimer();
            _UserInterfaceTimer.Tick += new EventHandler(UserInterfaceTimerTick);
            _UserInterfaceTimer.Interval = new TimeSpan(0, 0, 0, 0, 250);

            rcClose = new RelayCommand(ExecuteClose);
            rcCreateDatabase = new RelayCommand(ExecuteCreateDatabase, CanExecuteCreateDatabase);
            rcF5 = new RelayCommand(ExecuteF5, CanExecuteF5);
            rcIsClosing = new RelayCommand(ExecuteIsClosing, CanExecuteIsClosing);
            rcLogin = new RelayCommand(ExecuteLogin, CanExecuteLogin);
            rcRefreshTokens = new RelayCommand(ExecuteRefreshTokens);
            rcUnlock = new RelayCommand(ExecuteUnlock, CanExecuteUnlock);
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
        private bool CanExecuteUnlock()
        {
            return isExecuteUnlock;
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

        /// <summary>Delegate method invoked by rcUnlock.</summary>
        private void ExecuteUnlock()
        {
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