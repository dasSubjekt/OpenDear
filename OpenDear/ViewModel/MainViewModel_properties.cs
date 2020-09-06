namespace OpenDear.ViewModel
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
        private const int ciMaxPasswordLength = 20;
        private const int ciMinPasswordLength = 8;
        private const int ciProgrssBarDefaultMaximum = 1;
        private const int ciUserInterfacePasswordEncryptionStrength = 2048;

        public const long ckTicksPerSecond = 10000000L;
        public const long ckSeconds_0_1970 = 62135600400L;

        private const char ccDirectorySeparator = '\\';
        private const string csApplicationName = "OpenDear";
        private const string csSha1 = "SHA-1";
        private const string csSha224 = "SHA224";
        private const string csSha256 = "SHA256";
        private const string csSha384 = "SHA384";
        private const string csSha512 = "SHA512";

        public enum nMenuTab { Setup = 0, User = 1, Keys = 2, Data = 3, Progress = 4 };
        public enum nSubkeyProperty
        {
            Verified, SignatureType, PublicKeyAlgorithm, HashAlgorithm, CreatedKey, CreatedSignature, Expires, MasterKeyFingerprint, Fingerprint, Modulus, Exponent,
            StringToKeyUsage, SymmetricKeyAlgorithm, StringToKeySpecifier, Iterations, P, Q, DP, DQ, InverseQ, D
        };

        private bool _isDatabaseWithPassword, _isDragOverData, _isDragOverKeys, _isProgressBarIndeterminate;
        private int _iErrorId, _iPasswordLength, _iProgressBarValue, _iProgressBarMaximum, _iUserPinLength;
        private string _sBackgroundStatus, _sDatabaseDirectory, _sErrorMessage, _sInputKeyFilePath, _sInputMessageFilePath, _sNewDatabaseName;
        private byte[] _abEncryptedPassword;
        private nMenuTab _eMenuTab;
        private BackgroundThread _BackgroundThread;
        private EncryptionServices _Cryptography;
        private RSACng _RsaUiDecryptor, _RsaUiEncryptor;
        private EncryptedDatabase _Database;
        private BindingList<Property> _blDatabases;
        private BindingList<Property> _blMessages;
        private List<PgpToken> _ltTokens;
        private BindingList<PgpSignature> _blSubkeys;
        private BindingList<Property> _blSubkeyProperties;
        private BindingList<PgpToken> _blTokens;
        private DispatcherTimer _UserInterfaceTimer;
        private PgpSignature _SelectedSubkey;
        private Property _SelectedSubkeyProperty;
        private PgpToken _SelectedToken;

        #region properties

        public ICommand rcClose { get; }
        public ICommand rcCreateDatabase { get; }
        public ICommand rcDecryptMessage { get; }
        public ICommand rcEmptyPasswordOrPin { get; }
        public ICommand rcF5 { get; }
        public ICommand rcIsClosing { get; }
        public ICommand rcLogin { get; }
        public ICommand rcReadMessage { get; }
        public ICommand rcReadKeyFile { get; }
        public ICommand rcReadTokens { get; }
        public ICommand rcSelectInputMessage { get; }
        public ICommand rcSelectKey { get; }
        public ICommand rcUnlockKey { get; }

        public string sAllFiles { get => Translate("AllFiles"); }
        public string sBitsText { get => Translate("BitsText"); }
        public string sCancel { get => Translate("Cancel"); }
        public string sCasualCertificationText { get => Translate("CasualCertificationText"); }
        public string sClose { get => Translate("Close"); }
        public string sCommentText { get => Translate("CommentText"); }
        public string sCreate { get => Translate("Create"); }
        public string sCreatedKeyText { get => Translate("CreatedKeyText"); }
        public string sCreatedSignatureText { get => Translate("CreatedSignatureText"); }
        public string sData { get => Translate("Data"); }
        public string sDatabase { get => Translate("EncryptedDatabase"); }
        public string sDatabaseNameText { get => Translate("DatabaseNameText"); }
        public string sDateTimeFormat { get => Translate("DateTimeFormat"); }
        public string sDecrypt { get => Translate("Decrypt"); }
        public string sDuplicateTokenError { get => Translate("DuplicateTokenError"); }
        public string sEmailText { get => Translate("EmailText"); }
        public string sEmpty { get => Translate("Empty"); }
        public string sEnterPassword1 { get => Translate("EnterPassword1"); }
        public string sEnterPassword2 { get => Translate("EnterPassword2"); }
        public string sExpiresText { get => Translate("ExpiresText"); }
        public string sExponentText { get => Translate("ExponentText"); }
        public string sFileCrcError { get => Translate("FileCrcError"); }
        public string sFileError { get => Translate("FileError"); }
        public string sFileParseError { get => Translate("FileParseError"); }
        public string sFileParseErrorSub { get => Translate("FileParseErrorSub"); }
        public string sFingerprintText { get => Translate("FingerprintText"); }
        public string sFunctionsText { get => Translate("FunctionsText"); }
        public string sGenericCertificationText { get => Translate("GenericCertificationText"); }
        public string sHashAlgorithmText { get => Translate("HashAlgorithmText"); }
        public string sInputFileText { get => Translate("InputFileText"); }
        public string sKeyFileText { get => Translate("KeyFileText"); }
        public string sKeyFileTooLarge { get => Translate("KeyFileTooLarge"); }
        public string sKeyNotFoundText { get => Translate("KeyNotFoundText"); }
        public string sKeysOrTokensText { get => Translate("KeysOrTokensText"); }
        public string sKeys { get => Translate("Keys"); }
        public string sLogin { get => Translate("Login"); }
        public string sMasterKeyFingerprintText { get => Translate("MasterKeyFingerprintText"); }
        public string sMessageText { get => Translate("MessageText"); }
        public string sModulusText { get => Translate("ModulusText"); }
        public string sNameText { get => Translate("NameText"); }
        public string sNeverText { get => Translate("NeverText"); }
        public string sNewDatabase { get => Translate("NewDatabase"); }
        public string sOpenScInformation { get => Translate("OpenScInformation"); }
        public string sPassphraseOrPinText { get => Translate("PassphraseOrPinText"); }
        public string sPendingText { get => Translate("PendingText"); }
        public string sPersonaCertificationText { get => Translate("PersonaCertificationText"); }
        public string sPin { get => Translate("Pin"); }
        public string sPositiveCertificationText { get => Translate("PositiveCertificationText"); }
        public string sProgress { get => Translate("Progress"); }
        public string sPropertyText { get => Translate("PropertyText"); }
        public string sPublicKeyAlgorithmText { get => Translate("PublicKeyAlgorithmText"); }
        public string sPublicKeyMatched { get => Translate("PublicKeyMatched"); }
        public string sPublicKeyNotMatched { get => Translate("PublicKeyNotMatched"); }
        public string sRead { get => Translate("Read"); }
        public string sReadTokens { get => Translate("ReadTokens"); }
        public string sRsaEncryptOrSignText { get => Translate("RsaEncryptOrSignText"); }
        public string sRsaEncryptOnlyText { get => Translate("RsaEncryptOnlyText"); }
        public string sRsaSignOnlyText { get => Translate("RsaSignOnlyText"); }
        public string sSelect { get => Translate("Select"); }
        public string sSelectInputMessage { get => Translate("sSelectInputMessage"); }
        public string sSelectKeyFile { get => Translate("SelectKeyFile"); }
        public string sSetup { get => Translate("Setup"); }
        public string sSignatureTypeText { get => Translate("SignatureTypeText"); }
        public string sSubkeyBindingText { get => Translate("SubkeyBindingText"); }
        public string sSubkeysText { get => Translate("SubkeysText"); }
        public string sTimeText { get => Translate("TimeText"); }
        public string sTypeText { get => Translate("TypeText"); }
        public string sUser { get => Translate("User"); }
        public string sValueText { get => Translate("ValueText"); }
        public string sVerifiedFalseText { get => Translate("VerifiedFalseText"); }
        public string sVerifiedText { get => Translate("VerifiedText"); }
        public string sVerifiedTrueText { get => Translate("VerifiedTrueText"); }
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
        public bool isDragOverData
        {
            get { return _isDragOverData; }
            set
            {
                if (value != _isDragOverData)
                {
                    _isDragOverData = value;

                    if (_isDragOverData && (eMenuTab != nMenuTab.Data))
                        eMenuTab = nMenuTab.Data;

                    RaisePropertyChanged("isDragOverData");
                }
            }
        }

        /// <summary></summary>
        public bool isDragOverKeys
        {
            get { return _isDragOverKeys; }
            set
            {
                if (value != _isDragOverKeys)
                {
                    _isDragOverKeys = value;

                    if (_isDragOverKeys && (eMenuTab != nMenuTab.Keys))
                        eMenuTab = nMenuTab.Keys;

                    RaisePropertyChanged("isDragOverKeys");
                }
            }
        }

        /// <summary></summary>
        public byte[] abEncryptedPassword
        {
            get { return _abEncryptedPassword; }
            set
            {
                if (value != _abEncryptedPassword)
                {
                    _abEncryptedPassword = value;
                    RaisePropertyChanged("abEncryptedPassword");
                }
            }
        }

        /*
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
        */

        /// <summary></summary>
        public bool isExecuteCreateDatabase
        {
            get { return false; }
        }

        /// <summary></summary>
        public bool isExecuteDecryptMessage
        {
            get
            {
                return !(string.IsNullOrEmpty(_sInputMessageFilePath) || PropertyHasErrors("sInputMessageFilePath"));
            }
        }

        /// <summary></summary>
        public bool isExecuteEmptyPasswordOrPin
        {
            get { return _iPasswordLength > 0; }
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
        public bool isExecuteReadMessage
        {
            get
            {
                return !(string.IsNullOrEmpty(_sInputMessageFilePath) || PropertyHasErrors("sInputMessageFilePath"));
            }
        }

        /// <summary></summary>
        public bool isExecuteReadKeyFile
        {
            get
            {
                return !(string.IsNullOrEmpty(_sInputKeyFilePath) || PropertyHasErrors("sInputKeyFilePath"));
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

        public string sInputKeyFilePath
        {
            get { return _sInputKeyFilePath; }
            set
            {
                if (value != _sInputKeyFilePath)
                {
                    ValidateRaiseErrorsChanged(nValidationType.Single, "sInputKeyFilePath", string.IsNullOrEmpty(value) || File.Exists(value), Translate("KeyFileDoesNotExist"));

                    _sInputKeyFilePath = value;
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("sInputKeyFilePath");
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        public string sInputMessageFilePath
        {
            get { return _sInputMessageFilePath; }
            set
            {
                if (value != _sInputMessageFilePath)
                {
                    ValidateRaiseErrorsChanged(nValidationType.Single, "sInputMessageFilePath", string.IsNullOrEmpty(value) || File.Exists(value), Translate("InputFileDoesNotExist"));

                    _sInputMessageFilePath = value;
                    RaisePropertyChanged("sStatus");
                    RaisePropertyChanged("sInputMessageFilePath");
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

                    if (_eMenuTab != nMenuTab.Keys)
                        isDragOverKeys = false;
                    else if (_eMenuTab != nMenuTab.Data)
                        isDragOverData = false;

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

        public int iPasswordLength
        {
            get { return _iPasswordLength; }
            set
            {
                if (value != _iPasswordLength)
                {
                    _iPasswordLength = value;
                    RaisePropertyChanged("iPasswordLength");
                }
            }
        }

        public int iPasswordMaxLength
        {
            get { return ciMaxPasswordLength; }
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
                    RequeryDisplayedSubkeyProperties();
                    RaisePropertyChanged("SelectedSubkey");
                }
            }
        }

        /// <summary></summary>
        public Property SelectedSubkeyProperty
        {
            get { return _SelectedSubkeyProperty; }
            set
            {
                if (value != _SelectedSubkeyProperty)
                {
                    _SelectedSubkeyProperty = value;
                    RaisePropertyChanged("SelectedSubkeyProperty");
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
        public BindingList<Property> blSubkeyProperties
        {
            get { return _blSubkeyProperties; }
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
        public Visibility VisibleWhenWithOpenSc
        {
            get { return isWithOpenSc ? Visibility.Visible : Visibility.Collapsed; }
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
