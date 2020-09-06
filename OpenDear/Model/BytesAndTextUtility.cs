namespace OpenDear.Model
{
    using System;
    using System.Text;


    public class BytesAndTextUtility
    {
        protected byte[] _abBytes;

        #region constructors

        public BytesAndTextUtility(byte[] abBytes = null)
        {
            _abBytes = abBytes;
        }

        public BytesAndTextUtility(string sText)
        {
            if (string.IsNullOrEmpty(sText))
                _abBytes = null;
            else
                _abBytes = Encoding.UTF8.GetBytes(sText);
        }
        #endregion

        #region properties

        public byte[] abBase64StringBytes
        {
            get
            {
                bool isValid = (_abBytes != null) && (_abBytes.Length > 3) && ((_abBytes.Length & 3) == 0);
                byte b;
                int i, iPaddingLength = 0;

                if (isValid)
                {
                    if (_abBytes[_abBytes.Length - 1] == '=')
                    {
                        if (_abBytes[_abBytes.Length - 2] == '=')
                        {
                            iPaddingLength = 2;
                            b = _abBytes[_abBytes.Length - 3];
                            isValid = ((b == 'g') || (b == 'w') || (b == 'A') || (b == 'Q'));
                        }
                        else
                        {
                            iPaddingLength = 1;
                            b = _abBytes[_abBytes.Length - 2];
                            isValid = ((b == '0') || (b == '4') || (b == '8') || (b == 'c') || (b == 'g') || (b == 'k') || (b == 'o') || (b == 's') || (b == 'w') || (b == 'A') || (b == 'E') || (b == 'I') || (b == 'M') || (b == 'Q') || (b == 'U') || (b == 'Y'));
                        }
                    }
                }

                if (isValid)
                {
                    for (i = 0; i < (_abBytes.Length - iPaddingLength - 1); i++)
                    {
                        b = _abBytes[i];
                        isValid = isValid && (((b >= '0') && (b <= '9')) || ((b >= 'A') && (b <= 'Z')) || ((b >= 'a') && (b <= 'z')) || (b == '+') || (b == '/'));
                    }
                }

                if (isValid)
                    return Convert.FromBase64String(Encoding.UTF8.GetString(_abBytes));
                else
                    return null;
            }
        }

        /// <summary></summary>
        public byte[] abBytes
        {
            get { return _abBytes; }
            set { _abBytes = value; }
        }

        public string sHexadecimalBytes
        {
            get
            {
                int i;
                StringBuilder BytesStringBuilder = new StringBuilder();

                if ((_abBytes != null) && (_abBytes.Length > 0))
                {
                    for (i = 0; i < (_abBytes.Length - 1); i++)
                        BytesStringBuilder.AppendFormat("{0:x2} ", _abBytes[i]);

                    BytesStringBuilder.AppendFormat("{0:x2}", _abBytes[_abBytes.Length - 1]);
                }
                return BytesStringBuilder.ToString();
            }
        }

        #endregion

        #region methods

        #endregion
    }
}
