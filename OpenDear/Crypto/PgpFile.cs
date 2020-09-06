namespace OpenDear.Crypto
{
    using System;
    using System.IO;
    using System.Text;


    public class PgpFile
    {
        /// <summary>Maximum possible size of an armored PGP key file.</summary>
        public const long ckMaxKeyFileSize = ushort.MaxValue;   // TODO specify later

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

        /// <summary>Reads all bytes into memory and removes PGP armor if present.</summary>
        public byte[] GetBytes(string sFilePath, bool isKey)
        {
            bool isAscii = true;
            byte[] abReturn = null;
            byte[] abBuffer = new byte[0x1000];
            int i, iBytesRead;
            string sArmorString;
            PgpArmor Armor;

            // read the file into an array of bytes in working memory
            using (FileStream PgpFileStream = new FileStream(sFilePath, FileMode.Open, FileAccess.Read))
            {
                using (MemoryStream PgpMemoryStream = new MemoryStream())
                {
                    while ((iBytesRead = PgpFileStream.Read(abBuffer, 0, abBuffer.Length)) > 0)
                        PgpMemoryStream.Write(abBuffer, 0, iBytesRead);
                    abReturn = PgpMemoryStream.ToArray();
                }
            }

            if (abReturn != null)
            {
                _eStatus = PgpArmor.nStatus.OK;

                for (i = 0; i < abReturn.Length; i++)
                    isAscii = isAscii && ((abReturn[i] & 0x80) == 0);

                if (isAscii)
                {
                    Armor = new PgpArmor();
                    sArmorString = Encoding.ASCII.GetString(abReturn);
                    abReturn = Armor.Parse(sArmorString, isKey);
                    _eStatus = Armor.eStatus;
                }
            }

            return abReturn;
        }

        public long GetFileSize(string sFilePath)
        {
            FileInfo PgpFileInfo = new FileInfo(sFilePath);

            return PgpFileInfo.Length;
        }

        #endregion
    }
}
