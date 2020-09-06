namespace OpenDear.Crypto
{
    using System;
    using System.Text;


    /// <summary>Implements RFC 4880 section 5.11. User ID Packet.</summary>
    public class PgpUserId : PgpPacket
    {
        private const char ccCommentStart = '(';
        private const char ccCommentEnd = ')';
        private const char ccEmailStart = '<';
        private const char ccEmailEnd = '>';

        private string _sComment, _sEmail, _sName, _sUserId;

        #region constructors

        public PgpUserId(PgpPacket FromPacket) : base(FromPacket)
        {
            if ((_abRawBytes == null) || (_abRawBytes.Length < _iHeaderLength) || (_ePacketTag != nPacketTag.UserId))
            {
                _eStatus = nStatus.ParseError;
            }
            else if (_eStatus == nStatus.OK)
            {
                _sUserId = Encoding.UTF8.GetString(_abRawBytes, _iHeaderLength, _abRawBytes.Length - _iHeaderLength);
                SplitUserId();
            }
        }

        public PgpUserId(string sUserId) : base(nPacketTag.UserId)
        {
            _sUserId = sUserId;
            SplitUserId();
        }

        #endregion

        #region properties

        /// <summary></summary>
        public string sComment
        {
            get { return _sComment; }
            set
            {
                if (value != _sComment)
                {
                    _sComment = value;
                    BuildUserId();
                }
            }
        }

        /// <summary></summary>
        public string sEmail
        {
            get { return _sEmail; }
            set
            {
                if (value != _sEmail)
                {
                    _sEmail = value;
                    BuildUserId();
                }
            }
        }

        /// <summary></summary>
        public string sName
        {
            get { return _sName; }
            set
            {
                if (value != _sName)
                {
                    _sName = value;
                    BuildUserId();
                }
            }
        }

        /// <summary></summary>
        public string sUserId
        {
            get { return _sUserId; }
            set
            {
                if (value != _sUserId)
                {
                    _sUserId = value;
                    SplitUserId();
                }
            }
        }

        #endregion

        #region methods

        private void BuildUserId()
        {
            _iDataLength = _iHeaderLength = 0;
            _abRawBytes = null;
            _sUserId = _sName;

            if (!string.IsNullOrEmpty(_sComment))
                _sUserId += " " + ccCommentStart + _sComment + ccCommentEnd;

            if (!string.IsNullOrEmpty(_sEmail))
            {
                if (string.IsNullOrEmpty(_sName))
                    _sUserId = _sEmail;
                else
                    _sUserId += " " + ccEmailStart + _sEmail + ccEmailEnd;
            }

            EncodeRawBytes();
        }

        private string PartOfUserId(char cStart, char cEnd)
        {
            int iStart, iEnd;
            string sReturn = string.Empty;

            if (!string.IsNullOrEmpty(_sUserId))
            {
                iStart = _sUserId.IndexOf(cStart);
                iEnd = _sUserId.LastIndexOf(cEnd);

                if ((iStart > 0) && (iEnd > 0) && (iStart < iEnd))
                    sReturn = _sUserId.Substring(iStart + 1, iEnd - iStart - 1).Trim();
            }
            return sReturn;
        }

        private void SplitUserId()
        {
            int iFirstStart, iSecondStart;

            _sComment = _sEmail = _sName = string.Empty;

            if (!string.IsNullOrEmpty(_sUserId))
            {
                _sComment = PartOfUserId(ccCommentStart, ccCommentEnd);
                _sEmail = PartOfUserId(ccEmailStart, ccEmailEnd);

                iFirstStart = _sUserId.IndexOf(ccCommentStart);
                iSecondStart = _sUserId.LastIndexOf(ccEmailStart);

                if ((iSecondStart > 0) && ((iFirstStart < 0) || (iFirstStart > iSecondStart)))
                    iFirstStart = iSecondStart;

                if (iFirstStart < 0)
                {
                    if (_sUserId.IndexOf('@') > 0)
                        _sEmail = _sUserId.Trim();
                    else
                        _sName = _sUserId.Trim();
                }
                else if (iFirstStart > 0)
                    _sName = _sUserId.Substring(0, iFirstStart - 1).Trim();
            }

            // Console.WriteLine("sUserId=" + _sUserId);
            // Console.WriteLine("sComment=" + _sComment);
            // Console.WriteLine("sEmail=" + _sEmail);
            // Console.WriteLine("sName=" + _sName);
        }

        #endregion

        public override void EncodeRawBytes()
        {
            byte[] abData, abHeader;

            abData = Encoding.UTF8.GetBytes(_sUserId);
            abHeader = EncodeHeaderBytes(abData.Length);

            if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + _iDataLength))
                _abRawBytes = new byte[_iHeaderLength + _iDataLength];

            CopyToRawBytes(abHeader, 0, 0, _iHeaderLength);
            CopyToRawBytes(abData, 0, _iHeaderLength, _iDataLength);
        }

        // public PgpUserId(string sUserId)
        // {
        //     _abRawBytes = Encoding.UTF8.GetBytes(_sUserId);
        // }
    }
}
