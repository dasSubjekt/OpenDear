namespace OpenDear.Model
{
    using System;
    using System.Text;


    public class DatabaseVariable
    {
        public enum nDataType { None = -1, Int32 = 0, UInt64 = 1, ByteArray = 2, StringUtf8 = 3 };

        protected byte _bId;
        protected byte[] _abValue;
        protected nDataType _eDataType;
        protected int _iLength, _iValueBufferLength;


        public DatabaseVariable()
        {
            _bId = 0;
            _abValue = null;
            _eDataType = nDataType.None;
            _iLength = _iValueBufferLength = 0;
        }

        #region properties

        public byte bId
        {
            get { return _bId; }
            set
            {
                if (value <= 0x3f)
                    _bId = value;
                else
                    throw new ArgumentException("Property bId in class DatabaseVariable must not be larger than 63.");
            }
        }

        public int iLength
        {
            get { return _iLength; }
        }

        public byte bTag
        {
            get
            {
                if ((_iLength < 1) || (_abValue == null))
                    return 0;
                else
                    return (byte)((int)_eDataType << 6 | _bId);
            }
        }

        public byte[] abValue
        {
            get
            {
                byte[] abReturn = null;

                if ((_eDataType == nDataType.ByteArray) && (_abValue != null) && (_iLength > 1))
                {
                    abReturn = new byte[_iLength - 2];
                    for (int i = 2; i < _iLength; i++)
                        abReturn[i - 2] = _abValue[i];

                    return abReturn;
                }
                else
                    throw new FormatException("Failed to read data of type byte[] in class DatabaseVariable.");
            }
            set
            {
                byte[] abLengthBytes;

                if (value.Length <= ushort.MaxValue)
                {
                    _eDataType = nDataType.ByteArray;
                    abLengthBytes = BitConverter.GetBytes((ushort)value.Length);

                    _iLength = value.Length + 2;
                    if (_iLength > _iValueBufferLength)
                        ExtendValueBuffer(_iLength);

                    _abValue[0] = abLengthBytes[0];
                    _abValue[1] = abLengthBytes[1];
                    for (int i = 2; i < _iLength; i++)
                        _abValue[i] = value[i - 2];
                }
                else
                    throw new FormatException("Byte array too long to be stored.");
            }
        }

        public int iValue
        {
            get
            {
                if ((_eDataType == nDataType.Int32) && (_abValue != null) && (_iLength == 4))
                    return BitConverter.ToInt32(_abValue, 0);
                else
                    throw new FormatException("Failed to read data of type int in class DatabaseVariable.");
            }
            set
            {
                _eDataType = nDataType.Int32;
                _iLength = _iValueBufferLength = 4;
                _abValue = BitConverter.GetBytes(value);
            }
        }

        public string sValue
        {
            get
            {
                if ((_eDataType == nDataType.StringUtf8) && (_abValue != null) && (_iLength > 1))
                    return Encoding.UTF8.GetString(_abValue, 2, _iLength - 2);
                else
                    throw new FormatException("Failed to read data of type string in class DatabaseVariable.");
            }
            set
            {
                byte[] abLengthBytes, abTextBytes = Encoding.UTF8.GetBytes(value);

                if (abTextBytes.Length <= ushort.MaxValue)
                {
                    _eDataType = nDataType.StringUtf8;
                    abLengthBytes = BitConverter.GetBytes((ushort)abTextBytes.Length);

                    _iLength = abTextBytes.Length + 2;
                    if (_iLength > _iValueBufferLength)
                        ExtendValueBuffer(_iLength);

                    _abValue[0] = abLengthBytes[0];
                    _abValue[1] = abLengthBytes[1];
                    for (int i = 2; i < _iLength; i++)
                        _abValue[i] = abTextBytes[i - 2];
                }
                else
                    throw new FormatException("String too long to be stored.");
            }
        }

        public ulong vValue
        {
            get
            {
                if ((_eDataType == nDataType.UInt64) && (_abValue != null) && (_iLength == 8))
                    return BitConverter.ToUInt64(_abValue, 0);
                else
                    throw new FormatException("Failed to read data of type ulong in class DatabaseVariable.");
            }
            set
            {
                _eDataType = nDataType.UInt64;
                _iLength = _iValueBufferLength = 8;
                _abValue = BitConverter.GetBytes(value);
            }
        }
        #endregion

        #region commands and methods

        protected void ExtendValueBuffer(int iLength)
        {
            _abValue = new byte[iLength];
            _iValueBufferLength = iLength;
        }

        public byte[] GetValue()
        {
            return _abValue;
        }

        protected bool ReadByteArray(byte[] abBuffer, int iOffset, nDataType eDataType)
        {
            bool isReturn = (abBuffer != null) && (iOffset >= 0) && (abBuffer.Length > (iOffset + 1));

            if (isReturn)
            {
                _eDataType = eDataType;
                _iLength = BitConverter.ToUInt16(abBuffer, iOffset) + 2;
                isReturn = abBuffer.Length >= (iOffset + _iLength);

                if (isReturn)
                {
                    if (_iLength > _iValueBufferLength)
                        ExtendValueBuffer(_iLength);
                    for (int i = 0; i < _iLength; i++)
                        _abValue[i] = abBuffer[i + iOffset];
                }
            }
            return isReturn;
        }

        protected bool ReadInt32(byte[] abBuffer, int iOffset)
        {
            bool isReturn = (abBuffer != null) && (iOffset >= 0) && (abBuffer.Length > (iOffset + 3));

            if (isReturn)
            {
                _eDataType = nDataType.Int32;
                _iLength = 4;
                if (_iLength > _iValueBufferLength)
                    ExtendValueBuffer(_iLength);
                for (int i = 0; i < _iLength; i++)
                    _abValue[i] = abBuffer[iOffset + i];
            }
            return isReturn;
        }

        protected bool ReadUInt64(byte[] abBuffer, int iOffset)
        {
            bool isReturn = (abBuffer != null) && (iOffset >= 0) && (abBuffer.Length > (iOffset + 7));

            if (isReturn)
            {
                _eDataType = nDataType.UInt64;
                _iLength = 8;
                if (_iLength > _iValueBufferLength)
                    ExtendValueBuffer(_iLength);
                for (int i = 0; i < _iLength; i++)
                    _abValue[i] = abBuffer[iOffset + i];
            }
            return isReturn;
        }

        public int SetValue(byte[] abBuffer, int iOffset)
        {
            bool isSuccess = false;
            int iReturn = 0;

            if ((abBuffer != null) && (iOffset >= 0) && (abBuffer.Length > (iOffset + 2)))
            {
                switch (abBuffer[iOffset] >> 6)
                {
                    case 0: isSuccess = ReadInt32(abBuffer, iOffset + 1); iReturn = _iLength; break;
                    case 1: isSuccess = ReadUInt64(abBuffer, iOffset + 1); iReturn = _iLength; break;
                    case 2: isSuccess = ReadByteArray(abBuffer, iOffset + 1, nDataType.ByteArray); iReturn = _iLength; break;
                    case 3: isSuccess = ReadByteArray(abBuffer, iOffset + 1, nDataType.StringUtf8); iReturn = _iLength; break;
                    default: break;
                }
            }

            if (isSuccess)
            {
                _bId = (byte)(abBuffer[iOffset] & 0x3f);
                return iReturn + 1;
            }
            else
                return 0;
        }
        #endregion
    }
}
