namespace OpenDear.Crypto
{
    using System;


    public class Crc24
    {
        public const int ciCrc24Length = 3;

        private const int ciCrc24Init = 0x0b704ce;
        private const int ciCrc24Poly = 0x1864cfb;

        private readonly int _iCrc24;

        #region constructors

        public Crc24(byte[] abData, int iOffset = 0)
        {
            int i, j;

            _iCrc24 = ciCrc24Init;

            if (abData != null)
            {
                for (i = iOffset; i < abData.Length; i++)
                {
                    _iCrc24 ^= abData[i] << 16;
                    for (j = 0; j < 8; j++)
                    {
                        _iCrc24 <<= 1;
                        if ((_iCrc24 & 0x1000000) != 0)
                        {
                            _iCrc24 ^= ciCrc24Poly;
                        }
                    }
                }
            }
        }

        #endregion

        public int iCrc24
        {
            get { return _iCrc24; }
        }

        #region properties

        #endregion

        #region methods

        #endregion
    }
}
