namespace OpenDear.Model
{
    using System;
    using System.Text;


    public class BytesAndTextUtility
    {
        protected byte[] _abFirst, _abSecond;

        #region constructors

        public BytesAndTextUtility(byte[] abFirst, byte[] abSecond = null)
        {
            _abFirst = abFirst;
            _abSecond = abSecond;
        }

        public BytesAndTextUtility(string sText)
        {
            if (string.IsNullOrEmpty(sText))
                _abFirst = null;
            else
                _abFirst = Encoding.UTF8.GetBytes(sText);

            _abSecond = null;
        }
        #endregion

        #region properties

        public bool isAllBytesEqual
        {
            get
            {
                bool isReturn = true;
                int i;

                if ((_abFirst == null) || (_abSecond == null) || (_abFirst.Length != _abSecond.Length))
                {
                    isReturn = false;
                }
                else
                {
                    for (i = 0; i < _abFirst.Length; i++)
                        isReturn = isReturn && (_abFirst[i] == _abSecond[i]);
                }
                return isReturn;
            }
        }

        public byte[] abBase64StringBytes
        {
            get
            {
                bool isValid = (_abFirst != null) && (_abFirst.Length > 3) && ((_abFirst.Length & 3) == 0);
                byte b;
                int i, iPaddingLength = 0;

                if (isValid)
                {
                    if (_abFirst[_abFirst.Length - 1] == '=')
                    {
                        if (_abFirst[_abFirst.Length - 2] == '=')
                        {
                            iPaddingLength = 2;
                            b = _abFirst[_abFirst.Length - 3];
                            isValid = ((b == 'g') || (b == 'w') || (b == 'A') || (b == 'Q'));
                        }
                        else
                        {
                            iPaddingLength = 1;
                            b = _abFirst[_abFirst.Length - 2];
                            isValid = ((b == '0') || (b == '4') || (b == '8') || (b == 'c') || (b == 'g') || (b == 'k') || (b == 'o') || (b == 's') || (b == 'w') || (b == 'A') || (b == 'E') || (b == 'I') || (b == 'M') || (b == 'Q') || (b == 'U') || (b == 'Y'));
                        }
                    }
                }

                if (isValid)
                {
                    for (i = 0; i < (_abFirst.Length - iPaddingLength - 1); i++)
                    {
                        b = _abFirst[i];
                        isValid = isValid && (((b >= '0') && (b <= '9')) || ((b >= 'A') && (b <= 'Z')) || ((b >= 'a') && (b <= 'z')) || (b == '+') || (b == '/'));
                    }
                }

                if (isValid)
                    return Convert.FromBase64String(Encoding.UTF8.GetString(_abFirst));
                else
                    return null;
            }
        }

        public string sHexadecimalBytes
        {
            get
            {
                int i;
                StringBuilder BytesStringBuilder = new StringBuilder();

                if ((_abFirst != null) && (_abFirst.Length > 0))
                {
                    for (i = 0; i < (_abFirst.Length - 1); i++)
                        BytesStringBuilder.AppendFormat("{0:x2} ", _abFirst[i]);

                    BytesStringBuilder.AppendFormat("{0:x2}", _abFirst[_abFirst.Length - 1]);
                }
                return BytesStringBuilder.ToString();
            }
        }

        #endregion

        #region methods

        #endregion
    }
}
