namespace OpenDear.Model
{
    using System;


    /// <summary>A data structure for exchanging information with <c>BackgroundThread</c>.</summary>
    public class BackgroundMessage
    {
        public enum nReturn { Empty };
        public enum nType { PasswordToKey, Status, Stop, UserMessage };

        private readonly nReturn _eReturn;
        private nType _eType;
        private byte[] _abKeyOrPassword, _abSignatureOrSalt;
        private int _iProgressMaximum, _iValue;
        private string _sText;
        private readonly DateTime _TimeStamp;


        #region constructors

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        public BackgroundMessage(nType eType)
        {
            _eType = eType;
            _abKeyOrPassword = _abSignatureOrSalt = null;
            _eReturn = nReturn.Empty;
            _iValue = _iProgressMaximum = 0;
            _sText = string.Empty;
            _TimeStamp = DateTime.MinValue;
        }

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        public BackgroundMessage(nType eType, int iValue, int iProgressMaximum = 0) : this(eType)
        {
            _iValue = iValue;
            _iProgressMaximum = iProgressMaximum;
        }

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public BackgroundMessage(nType eType, string sText) : this(eType)
        {
            _sText = sText;
        }

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        public BackgroundMessage(nType eType, int iValue, string sText) : this(eType)
        {
            _iValue = iValue;
            _sText = sText;
        }

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public BackgroundMessage(nType eType, nReturn eReturn) : this(eType)
        {
            _eReturn = eReturn;
            _TimeStamp = DateTime.Now;
        }

        /// <summary>A constructor to initialize a <c>new BackgroundMessage</c>.</summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public BackgroundMessage(nType eType, byte[] abKeyOrPassword, byte[] abSignatureOrSalt) : this(eType)
        {
            _eReturn = eReturn;
            _abKeyOrPassword = abKeyOrPassword;
            _abSignatureOrSalt = abSignatureOrSalt;
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abKeyOrPassword
        {
            get { return _abKeyOrPassword; }
            set { _abKeyOrPassword = value; }
        }

        /// <summary></summary>
        public int iProgressMaximum
        {
            get { return _iProgressMaximum; }
            set { _iProgressMaximum = value; }
        }

        /// <summary></summary>
        public nReturn eReturn
        {
            get { return _eReturn; }
        }

        /// <summary></summary>
        public byte[] abSignatureOrSalt
        {
            get { return _abSignatureOrSalt; }
            set { _abSignatureOrSalt = value; }
        }

        /// <summary></summary>
        public string sText
        {
            get { return _sText; }
            set { _sText = value; }
        }

        /// <summary></summary>
        public DateTime TimeStamp
        {
            get { return _TimeStamp; }
        }

        /// <summary></summary>
        public nType eType
        {
            get { return _eType; }
            set { _eType = value; }
        }

        /// <summary></summary>
        public int iValue
        {
            get { return _iValue; }
            set { _iValue = value; }
        }

        #endregion

        #region methods

        #endregion
    }
}
