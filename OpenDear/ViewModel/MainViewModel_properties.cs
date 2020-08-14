﻿namespace OpenDear.ViewModel
{
    using System;
    using System.IO;
    using OpenDear.Model;
    using System.Windows;
    using OpenDear.Crypto;
    using System.Reflection;
    using System.Windows.Input;
    using System.ComponentModel;
    using System.Windows.Threading;
    using System.Collections.Generic;
    using System.Security.Cryptography;


    public partial class MainViewModel : ViewModelBase, INotifyDataErrorInfo
    {
        private const int ciMaxPasswordLength = 10;
        private const int ciMinPasswordLength = 8;
        private const int ciProgrssBarDefaultMaximum = 1;
        private const int ciUserInterfacePasswordEncryptionStrength = 2048;

        public const long ckTicksPerSecond = 10000000L;
        public const long ckSeconds_0_1970 = 62135600400L;

        private const char ccDirectorySeparator = '\\';
        private const string csApplicationName = "OpenDear";

        public enum nMenuTab { Setup = 0, User = 1, Keys = 2, Data = 3, Progress = 4 };

        private bool _isDatabaseWithPassword, _isProgressBarIndeterminate;
        private int _iErrorId, _iPassword1Length, _iPassword2Length, _iProgressBarValue, _iProgressBarMaximum, _iUserPinLength;
        private string _sBackgroundStatus, _sDatabaseDirectory, _sErrorMessage, _sImportKeyFilePath, _sNewDatabaseName;
        private byte[] _abEncryptedPassword1, _abEncryptedPassword2, _abEncryptedUserPin;
        private nMenuTab _eMenuTab;
        private BackgroundThread _BackgroundThread;
        private EncryptionServices _Cryptography;
        private RSACng _RsaUiDecryptor, _RsaUiEncryptor;
        private EncryptedDatabase _Database;
        private BindingList<Property> _blDatabases;
        private BindingList<Property> _blMessages;
        private List<PgpToken> _ltTokens;
        private BindingList<PgpSignature> _blSubkeys;
        private BindingList<PgpToken> _blTokens;
        private DispatcherTimer _UserInterfaceTimer;
        private PgpSignature _SelectedSubkey;
        private PgpToken _SelectedToken;

        #region properties

        public ICommand rcClose { get; }
        public ICommand rcCreateDatabase { get; }
        public ICommand rcF5 { get; }
        public ICommand rcIsClosing { get; }
        public ICommand rcLogin { get; }
        public ICommand rcRefreshTokens { get; }
        public ICommand rcImportKey { get; }
        public ICommand rcSelectKey { get; }
        public ICommand rcUnlockKey { get; }

        public string sAllFiles { get => Translate("AllFiles"); }
        public string sBitsText { get => Translate("BitsText"); }
        public string sCancel { get => Translate("Cancel"); }
        public string sClose { get => Translate("Close"); }
        public string sCommentText { get => Translate("CommentText"); }
        public string sCreate { get => Translate("Create"); }
        public string sData { get => Translate("Data"); }
        public string sDatabase { get => Translate("EncryptedDatabase"); }
        public string sDatabaseNameText { get => Translate("DatabaseNameText"); }
        public string sDuplicateTokenError { get => Translate("DuplicateTokenError"); }
        public string sEmailText { get => Translate("EmailText"); }
        public string sEnterPassword1 { get => Translate("EnterPassword1"); }
        public string sEnterPassword2 { get => Translate("EnterPassword2"); }
        public string sFileCrcError { get => Translate("FileCrcError"); }
        public string sFileError { get => Translate("FileError"); }
        public string sFileParseError { get => Translate("FileParseError"); }
        public string sFileParseErrorSub { get => Translate("FileParseErrorSub"); }
        public string sFunctionsText { get => Translate("FunctionsText"); }
        public string sImport { get => Translate("Import"); }
        public string sKeyFileText { get => Translate("KeyFileText"); }
        public string sKeysOrTokensText { get => Translate("KeysOrTokensText"); }
        public string sKeys { get => Translate("Keys"); }
        public string sLogin { get => Translate("Login"); }
        public string sMessageText { get => Translate("MessageText"); }
        public string sNameText { get => Translate("NameText"); }
        public string sNewDatabase { get => Translate("NewDatabase"); }
        public string sOpenScInformation { get => Translate("OpenScInformation"); }
        public string sPin { get => Translate("Pin"); }
        public string sProgress { get => Translate("Progress"); }
        public string sRefreshTokens { get => Translate("RefreshTokens"); }
        public string sSelect { get => Translate("Select"); }
        public string sSelectKeyFile { get => Translate("SelectKeyFile"); }
        public string sSetup { get => Translate("Setup"); }
        public string sSubkeysText { get => Translate("SubkeysText"); }
        public string sTimeText { get => Translate("TimeText"); }
        public string sTypeText { get => Translate("TypeText"); }
        public string sUser { get => Translate("User"); }
        public string sWindowTitle { get => Translate("WindowTitle"); }
        public string sWithPassword { get => Translate("WithPassword"); }
        public string sWithToken { get => Translate("WithToken"); }


        /// <summary></summary>
        public string sBackgroundStatus
        {
            get { return _sBackgroundStatus; }
            set
            {
                if (value != _sBackgroundStatus)
                {
                    _sBackgroundStatus = value;
                    RaisePropertyChanged("sStatus");
                }
            }
        }

        /// <summary></summary>
        public BindingList<Property> blDatabases
        {
            get { return _blDatabases; }
        }

        /// <summary></summary>
        public bool isDatabaseWithPassword
        {
            get { return _isDatabaseWithPassword; }
            set
            {
                if (value)
                {
                    _isDatabaseWithPassword = true;
                    RaisePropertyChangedDbWithPassword();
                }
            }
        }

        /// <summary></summary>
        public bool isDatabaseWithToken
        {
            get { return !_isDatabaseWithPassword; }
            set
            {
                if (value)
                {
                    _isDatabaseWithPassword = false;
                    RaisePropertyChangedDbWithPassword();
                }
            }
        }

        /// <summary></summary>
        public byte[] abEncryptedPassword1
        {
            get { return _abEncryptedPassword1; }
            set
            {
                if (value != _abEncryptedPassword1)
                {
                    _abEncryptedPassword1 = value;
                    ClearErrors("abEncryptedPassword2");
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("abEncryptedPassword1");
                }
            }
        }

        /// <summary></summary>
        public byte[] abEncryptedPassword2
        {
            get { return _abEncryptedPassword2; }
            set
            {
                if (value != _abEncryptedPassword2)
                {
                    _abEncryptedPassword2 = value;
                    ClearErrors("abEncryptedPassword2");
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("abEncryptedPassword2");
                }
            }
        }

        /// <summary></summary>
        public byte[] abEncryptedUserPin
        {
            get { return _abEncryptedUserPin; }
            set
            {
                if (value != _abEncryptedUserPin)
                {
                    _abEncryptedUserPin = value;
                    if (value == null)
                        Console.WriteLine(_iUserPinLength.ToString() + " sUserPin=(null)");
                    else
                    {
                        Console.WriteLine(value[0].ToString("x2") + " " + value[1].ToString("x2") + " " + value[2].ToString("x2") + " " + value[3].ToString("x2") + " " + value[4].ToString("x2") + " " + value[5].ToString("x2"));
                        // Console.WriteLine(_iUserPinLength.ToString() + " sUserPin=(" + value.Length + ")" + TextEncoder.GetString(_PrivateRsaDecryptor.Decrypt(value, RSAEncryptionPadding.Pkcs1)));
                    }
                    RaisePropertyChanged("abEncryptedUserPin");
                }
            }
        }

        /// <summary></summary>
        public bool isExecuteCreateDatabase
        {
            get { return false; }
        }

        /// <summary></summary>
        public bool isExecuteF5
        {
            get
            {
                return true;
            }
        }

        /// <summary></summary>
        public bool isExecuteLogin
        {
            get
            {
                return true;
            }
        }

        /// <summary></summary>
        public bool isExecuteImportKey
        {
            get
            {
                return !(string.IsNullOrEmpty(_sImportKeyFilePath) || PropertyHasErrors("sImportKeyFilePath"));
            }
        }

        /// <summary></summary>
        public bool isExecuteUnlockKey
        {
            get
            {
                return true;   // _Cryptography.isTokenPresent && (_sTokenPin.Length >= ciTokenPinMinLength);
            }
        }

        public string sImportKeyFilePath
        {
            get { return _sImportKeyFilePath; }
            set
            {
                if (value != _sImportKeyFilePath)
                {
                    ValidateRaiseErrorsChanged(nValidationType.Single, "sImportKeyFilePath", string.IsNullOrEmpty(value) || File.Exists(value), Translate("KeyFileDoesNotExist"));

                    _sImportKeyFilePath = value;
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("sImportKeyFilePath");
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        /// <summary></summary>
        public nMenuTab eMenuTab
        {
            get { return _eMenuTab; }
            set
            {
                if (value != _eMenuTab)
                {
                    _eMenuTab = value;
                    RaisePropertyChanged("iMenuTab");
                }
            }
        }

        /// <summary></summary>
        public int iMenuTab
        {
            get { return (int)_eMenuTab; }
            set { eMenuTab = (nMenuTab)value; }
        }

        /// <summary></summary>
        public BindingList<Property> blMessages
        {
            get { return _blMessages; }
        }

        public string sNewDatabaseName
        {
            get { return _sNewDatabaseName; }
            set
            {
                if (value != _sNewDatabaseName)
                {
                    ValidateRaiseErrorsChanged(nValidationType.Single, "sNewDatabaseName", !File.Exists(GetDatabasePath(value)), Translate("DatabaseNameExists"));

                    _sNewDatabaseName = value;
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("sNewDatabaseName");
                }
            }
        }

        public int iPassword1Length
        {
            get { return _iPassword1Length; }
            set
            {
                if (value != _iPassword1Length)
                {
                    _iPassword1Length = value;
                    RaisePropertyChanged("iPassword1Length");
                }
            }
        }

        public int iPasswordMaxLength
        {
            get { return ciMaxPasswordLength; }
        }

        public int iPassword2Length
        {
            get { return _iPassword2Length; }
            set
            {
                if (value != _iPassword2Length)
                {
                    _iPassword2Length = value;
                    RaisePropertyChanged("iPassword2Length");
                }
            }
        }

        public string sPinOrPassword
        {
            get { return _isDatabaseWithPassword ? sEnterPassword2 : sPin; }
        }

        public string sProgramVersion
        {
            get
            {
                Version ProgramVersion = Assembly.GetExecutingAssembly().GetName().Version;

                return ProgramVersion.Major.ToString() + "." + ProgramVersion.Minor.ToString() + "." + ProgramVersion.Build.ToString();
            }
        }
           
        /// <summary></summary>
        public bool isProgressBarIndeterminate
        {
            get { return _isProgressBarIndeterminate; }
            set
            {
                if (value != _isProgressBarIndeterminate)
                {
                    _isProgressBarIndeterminate = value;
                    RaisePropertyChanged("isProgressBarIndeterminate");
                }
            }
        }

        /// <summary></summary>
        public int iProgressBarValue
        {
            get { return _iProgressBarValue; }
            set
            {
                if (value != _iProgressBarValue)
                {
                    _iProgressBarValue = value;
                    RaisePropertyChanged("iProgressBarValue");
                }
            }
        }

        /// <summary></summary>
        public int iProgressBarMaximum
        {
            get { return _iProgressBarMaximum; }
            set
            {
                if (value != _iProgressBarMaximum)
                {
                    _iProgressBarMaximum = value;
                    RaisePropertyChanged("iProgressBarMaximum");
                }
            }
        }

        public RSACng RsaUiEncryptor
        {
            get { return _RsaUiEncryptor; }
        }

        /// <summary></summary>
        public PgpSignature SelectedSubkey
        {
            get { return _SelectedSubkey; }
            set
            {
                if (value != _SelectedSubkey)
                {
                    _SelectedSubkey = value;
                    RaisePropertyChanged("SelectedSubkey");
                }
            }
        }

        /// <summary></summary>
        public PgpToken SelectedToken
        {
            get { return _SelectedToken; }
            set
            {
                if (value != _SelectedToken)
                {
                    _SelectedToken = value;
                    RequeryDisplayedSubkeys();
                    RaisePropertyChanged("SelectedToken");
                }
            }
        }

        /// <summary></summary>
        public string sStatus
        {
            get { return string.IsNullOrEmpty(sErrorMessage) ? _sBackgroundStatus : sErrorMessage; }
        }

        /// <summary></summary>
        public BindingList<PgpSignature> blSubkeys
        {
            get { return _blSubkeys; }
        }

        /// <summary></summary>
        public BindingList<PgpToken> blTokens
        {
            get { return _blTokens; }
        }

        public int iUserPinLength
        {
            get { return _iUserPinLength; }
            set
            {
                if (value != _iUserPinLength)
                {
                    _iUserPinLength = value;
                    RaisePropertyChanged("iUserPinLength");
                }
            }
        }

        /// <summary></summary>
        public Visibility VisibleWhenWithPassword
        {
            get { return _isDatabaseWithPassword ? Visibility.Visible : Visibility.Collapsed; }
        }

        /// <summary></summary>
        public Visibility VisibleWhenWithToken
        {
            get { return _isDatabaseWithPassword ? Visibility.Collapsed : Visibility.Visible; }
        }

        /// <summary></summary>
        public bool isWithOpenSc
        {
            get { return _Cryptography.isWithOpenSc; }
        }
        #endregion
    }
}
