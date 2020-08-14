namespace OpenDear.Crypto
{
    using System;
    using System.IO;
    using System.Text;


    public class PgpFile
    {
        private PgpArmor.nStatus _eStatus;


        #region constructors

        public PgpFile()
        {
            _eStatus = PgpArmor.nStatus.Undefined;
        }

        #endregion

        #region properties

        public PgpArmor.nStatus eStatus
        {
            get { return _eStatus; }
        }

        #endregion

        #region methods

        public byte[] GetBytes(string sFilePath)
        {
            bool isAscii = true;
            byte[] abReturn = null;
            byte[] abBuffer = new byte[0x1000];
            int i, iBytesRead;
            string sKeyString;
            PgpArmor KeyArmor;

            using (FileStream KeyFileStream = new FileStream(sFilePath, FileMode.Open, FileAccess.Read))
            {
                using (MemoryStream KeyMemoryStream = new MemoryStream())
                {
                    while ((iBytesRead = KeyFileStream.Read(abBuffer, 0, abBuffer.Length)) > 0)
                        KeyMemoryStream.Write(abBuffer, 0, iBytesRead);
                    abReturn = KeyMemoryStream.ToArray();
                }
            }

            if (abReturn != null)
            {
                _eStatus = PgpArmor.nStatus.OK;

                for (i = 0; i < abReturn.Length; i++)
                    isAscii = isAscii && ((abReturn[i] & 0x80) == 0);

                if (isAscii)
                {
                    KeyArmor = new PgpArmor();
                    sKeyString = Encoding.ASCII.GetString(abReturn);
                    abReturn = KeyArmor.Parse(sKeyString);
                    _eStatus = KeyArmor.eStatus;
                }
            }

            return abReturn;
        }

        #endregion
    }
}
