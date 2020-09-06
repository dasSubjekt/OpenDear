namespace OpenDear.Crypto
{
    using System;
    using OpenDear.Model;


    public class PgpArmor
    {
        private const string csArmorMessageHeader = "-----BEGIN PGP MESSAGE-----";
        private const string csArmorPrivateKeyHeader = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
        private const string csArmorPublicKeyHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

        private static readonly string[] asDelimiters = { "\r\n", "\r", "\n" };

        public enum nStatus { OK, CrcError, ParseError, Undefined };
        private enum nArmorParserState { Start, Header, KeyValue, BlankLine, ArmoredData, Checksum, Success, Error };

        private nStatus _eStatus;


        #region constructors

        public PgpArmor()
        {
            _eStatus = nStatus.Undefined;
        }

        #endregion

        #region properties

        public nStatus eStatus
        {
            get { return _eStatus; }
        }

        #endregion

        #region methods

        private bool IsPartOfArmor(string sData)
        {
            bool isReturn = true;
            char c;
            int i, iLastIndex;

            if (string.IsNullOrEmpty(sData))
                return false;
            else if ((sData == "=") || (sData == "=="))
                return true;
            else
            {
                iLastIndex = sData.Length - 1;

                if (sData[iLastIndex] == '=')
                    iLastIndex--;

                if (sData[iLastIndex] == '=')
                    iLastIndex--;

                for (i = 0; i <= iLastIndex; i++)
                {
                    c = sData[i];
                    isReturn = isReturn && (((c >= '0') && (c <= '9')) || ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || (c == '+') || (c == '/'));
                }
                return isReturn;
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public byte[] Parse(string sArmor, bool isKey)
        {
            byte[] abCrc24, abReturn = null;
            int i, iCrc24Value;
            Crc24 Crc24Computed;
            BytesAndTextUtility StringConverter;
            nArmorParserState eArmorParserState = nArmorParserState.Start;
            string sArmoredData, sChecksum, sHeader;
            string[] asLines;

            if (string.IsNullOrEmpty(sArmor))
            {
                _eStatus = nStatus.ParseError;
            }
            else
            {
                asLines = sArmor.Split(asDelimiters, StringSplitOptions.None);
                sArmoredData = sChecksum = sHeader = string.Empty;

                for (i = 0; i < asLines.Length; i++)
                {
                    switch (eArmorParserState)
                    {
                        case nArmorParserState.Start:
                            eArmorParserState = isKey ? ParseCheckForKeyHeader(asLines[i]) : ParseCheckForMessageHeader(asLines[i]);
                            if (eArmorParserState == nArmorParserState.Header) sHeader = asLines[i]; break;
                        case nArmorParserState.Header:
                        case nArmorParserState.KeyValue: eArmorParserState = ParseCheckForBlankLine(asLines[i]); break;
                        case nArmorParserState.BlankLine:
                        case nArmorParserState.ArmoredData:
                            eArmorParserState = ParseCheckForData(asLines[i], sHeader);
                            if (eArmorParserState == nArmorParserState.ArmoredData) sArmoredData += asLines[i];
                            else if (eArmorParserState == nArmorParserState.Checksum) sChecksum = asLines[i]; break;
                        case nArmorParserState.Checksum: eArmorParserState = ParseCheckForFooter(asLines[i], sHeader); break;
                    }
                }

                if (eArmorParserState == nArmorParserState.Success)
                {
                    StringConverter = new BytesAndTextUtility(sArmoredData);
                    abReturn = StringConverter.abBase64StringBytes;

                    if (abReturn == null)
                    {
                        _eStatus = nStatus.ParseError;
                    }
                    else
                    {
                        _eStatus = nStatus.OK;

                        if (!string.IsNullOrEmpty(sChecksum))
                        {
                            StringConverter = new BytesAndTextUtility(sChecksum.Substring(1));
                            abCrc24 = StringConverter.abBase64StringBytes;

                            if ((abCrc24 == null) || (abCrc24.Length != Crc24.ciCrc24Length))
                            {
                                _eStatus = nStatus.ParseError;
                                abReturn = null;
                            }
                            else
                            {
                                iCrc24Value = (abCrc24[0] << 16) | (abCrc24[1] << 8) | abCrc24[2];
                                Crc24Computed = new Crc24(abReturn);
                                if (iCrc24Value != Crc24Computed.iCrc24)
                                {
                                    _eStatus = nStatus.CrcError;
                                    abReturn = null;
                                }
                            }
                        }
                    }
                }
                else
                    _eStatus = nStatus.ParseError;
            }
            return abReturn;
        }

        private nArmorParserState ParseCheckForBlankLine(string sLine)
        {
            if (string.IsNullOrEmpty(sLine))
                return nArmorParserState.BlankLine;
            else if (sLine.IndexOf(": ") > 0)
                return nArmorParserState.KeyValue;
            else
                return nArmorParserState.Error;
        }

        private nArmorParserState ParseCheckForData(string sLine, string sHeader)
        {
            if (string.IsNullOrEmpty(sLine))
                return nArmorParserState.Error;
            else if ((sLine.Length == 5) && (sLine[0] == '=') && IsPartOfArmor(sLine.Substring(1)))
                return nArmorParserState.Checksum;
            else if (IsPartOfArmor(sLine))
                return nArmorParserState.ArmoredData;
            else
                return ParseCheckForFooter(sLine, sHeader);
        }

        private nArmorParserState ParseCheckForFooter(string sLine, string sHeader)
        {
            if (sLine == sHeader.Replace("BEGIN", "END"))
                return nArmorParserState.Success;
            else
                return nArmorParserState.Error;
        }

        private nArmorParserState ParseCheckForKeyHeader(string sLine)
        {
            if (!string.IsNullOrEmpty(sLine) && ((sLine == csArmorPrivateKeyHeader) || (sLine == csArmorPublicKeyHeader)))
                return nArmorParserState.Header;
            else
                return nArmorParserState.Start;
        }

        private nArmorParserState ParseCheckForMessageHeader(string sLine)
        {
            if (!string.IsNullOrEmpty(sLine) && (sLine == csArmorMessageHeader))
                return nArmorParserState.Header;
            else
                return nArmorParserState.Start;
        }
        #endregion
    }
}
