namespace OpenDear.Crypto
{
    using System;
    using OpenDear.Model;
    using System.Collections.Generic;


    public class EncryptedDatabase : SQLiteDatabase
    {
        private readonly string[] casDatabaseTableNames = new string[4] { "key", "signature", "system", "user" };

        public enum nProperty { CreationDate = 1, Dummy = 999 };

        private const int ciIdSystemSaltOrSignature = 1;
        private const int ciIdSystemWrappedKey = 2;
        private const int ciIdSystemMinPropertyId = 256;

        protected byte[] _abAesKey;
        protected List<DatabaseVariable> _ltVariables;
        protected List<Property> _ltProperties;
        protected Queue<DatabaseVariable> _quVariablesStore;
        protected EncryptionServices _Cryptography;


        #region constructors

        public EncryptedDatabase(string sPath, EncryptionServices Cryptography = null) : base(sPath)
        {
            _abAesKey = null;
            _ltVariables = new List<DatabaseVariable>();
            _ltProperties = new List<Property>();
            _quVariablesStore = new Queue<DatabaseVariable>();
            _Cryptography = Cryptography ?? new EncryptionServices();
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abSalt
        {
            get
            {
                byte[] abReturn = base.Read("system", ciIdSystemSaltOrSignature);

                if ((abReturn == null) || (abReturn.Length != EncryptionServices.ciAesBlockLength))
                    return null;
                else
                    return abReturn;
            }

            set
            {
                if ((value == null) || (value.Length != EncryptionServices.ciAesBlockLength))
                    throw new FormatException("EncryptedDatabase.abSalt must be " + EncryptionServices.ciAesBlockLength.ToString() + " bytes long.");
                else if (IdExists("system", ciIdSystemSaltOrSignature.ToString()))
                    throw new InvalidOperationException("EncryptedDatabase.abSalt must not be overwritten.");
                else
                {
                    base.Write("system", ciIdSystemSaltOrSignature, value);
                    Close();
                }
            }
        }

        #endregion

        #region methods

        public void CreateTables()
        {
            AddTables(casDatabaseTableNames);
        }

        public new void Dispose()
        {
            base.Dispose();

            if (_abAesKey != null)
            {
                _Cryptography.GetRandomBytes(_abAesKey);
                _abAesKey = null;
            }
        }

        protected DatabaseVariable FetchEmptyDatabaseVariable()
        {
            if (_quVariablesStore.Count == 0)
                return new DatabaseVariable();
            else
                return _quVariablesStore.Dequeue();
        }

        public int GetFreeId(string sTable)
        {
            int iReturn;
        
            do
            {
                iReturn = GetRandomId();
            } while (IdExists(sTable, iReturn.ToString()));

            if ((sTable == "system") && (iReturn < ciIdSystemMinPropertyId))
                return GetFreeId(sTable);   // if id is in the reserved range, keep trying
            else
                return iReturn;
        }

        protected int GetRandomId()
        {
            byte[] abRandomBytes = new byte[4];
            uint uRandom;
        
            do
            {
                _Cryptography.GetRandomBytes(abRandomBytes);
                uRandom = BitConverter.ToUInt32(abRandomBytes, 0);
            }
            while (uRandom == 0);
        
            return (int)(uRandom & int.MaxValue);
        }

        public new List<DatabaseObject> Read(string sTable)
        {
            int iBytesRead, iCrc24Value, iOffset = Crc24.ciCrc24Length;
            byte[] abDecrypted;
            Crc24 Crc24Computed;
            DatabaseObject NewObject;
            DatabaseVariable NewVariable;
            List<Row> ltRows;
            List<DatabaseObject> ltReturn = new List<DatabaseObject>();

            _eState = nState.OK;

            if (sTable == "system")
                ltRows = base.Read(sTable, ciIdSystemMinPropertyId, int.MaxValue);
            else
                ltRows = base.Read(sTable);

            foreach (Row NewRow in ltRows)
            {
                if (_eState != nState.OK)
                    break;

                NewObject = null;
                NewVariable = FetchEmptyDatabaseVariable();
                abDecrypted = _Cryptography.DecryptAes(NewRow.abData, _abAesKey);

                if ((abDecrypted == null) || (abDecrypted.Length < (Crc24.ciCrc24Length + 2)))
                {
                    _eState = nState.CouldNotRead;
                }
                else
                {
                    iCrc24Value = (abDecrypted[0] << 16) | (abDecrypted[1] << 8) | abDecrypted[2];
                    Crc24Computed = new Crc24(abDecrypted, Crc24.ciCrc24Length);
                    if (iCrc24Value != Crc24Computed.iCrc24)
                    {
                        _eState = nState.CouldNotRead;
                    }
                    else
                    {
                        while ((iBytesRead = NewVariable.SetValue(abDecrypted, iOffset)) > 0)
                        {
                            _ltVariables.Add(NewVariable);
                            NewVariable = FetchEmptyDatabaseVariable();
                            iOffset += iBytesRead;
                        }

                        switch (sTable)
                        {
                            case "system": NewObject = new Property(NewRow.iId, _ltVariables); break;
                        }

                        if (NewObject != null)
                            ltReturn.Add(NewObject);

                        _ltVariables.Add(NewVariable);
                    }
                }
                RecycleDatabaseVariables();
            }
            return ltReturn;
        }

        public new byte[] Read(string sTable, int iId)
        {
            byte[] abEncrypted = base.Read(sTable, iId);
            return _Cryptography.DecryptAes(abEncrypted, _abAesKey);
        }

        protected void RecycleDatabaseVariables()
        {
            foreach (DatabaseVariable Variable in _ltVariables)
                _quVariablesStore.Enqueue(Variable);
            _ltVariables.Clear();
        }

        protected void ReadProperties()
        {
            List<DatabaseObject> ltObjects;

            _ltProperties.Clear();
            ltObjects = Read("system");

            if (_eState == nState.OK)
            {
                foreach (DatabaseObject NewProperty in ltObjects)
                    _ltProperties.Add((Property)NewProperty);
            }
        }

        public bool TryLogin(byte[] abAesKey)
        {
            bool isReturn = false;

            Console.WriteLine("CountRecords = " + CountRecords("system").ToString());

            if (_abAesKey == null)
            {
                _abAesKey = abAesKey;

                if (CountRecords("system") > 2)   // database is already set up
                {
                    ReadProperties();

                    if (_eState == nState.OK)
                    {
                        isReturn = true;
                    }
                    else   // if login was not successful, destroy the key to be absolutely safe
                    {
                        _Cryptography.GetRandomBytes(_abAesKey);
                        _abAesKey = null;
                    }
                }
                else   // this is a new database thet needs to be set up
                {
                    _ltProperties.Clear();
                    _ltProperties.Add(new Property(DateTime.Now, "CreationDate"));
                    _ltProperties.Add(new Property((int)nProperty.Dummy, 0, "Dummy"));   // TODO

                    foreach (Property NewProperty in _ltProperties)
                    {
                        NewProperty.iIdExternal = GetFreeId("system");
                        Write(NewProperty, "system");
                    }
                }
                Console.WriteLine("isReturn = " + isReturn.ToString() + " CountRecords = " + CountRecords("system").ToString());
            }

            return isReturn;
        }

        protected byte[] VariablesToBytes(List<DatabaseVariable> ltVariables, int iLength)
        {
            byte[] abBuffer, abReturn = new byte[Crc24.ciCrc24Length + iLength];
            int iFrom, iTo = Crc24.ciCrc24Length;
            Crc24 Crc24Computed;

            foreach (DatabaseVariable Variable in ltVariables)
            {
                abReturn[iTo++] = Variable.bTag;
                abBuffer = Variable.GetValue();
                for (iFrom = 0; iFrom < Variable.iLength; iFrom++)
                    abReturn[iTo++] = abBuffer[iFrom];
            }

            if (iTo == Crc24.ciCrc24Length + iLength)
            {
                Crc24Computed = new Crc24(abReturn, Crc24.ciCrc24Length);
                abReturn[0] = (byte)((Crc24Computed.iCrc24 >> 16) & 0xff);
                abReturn[1] = (byte)((Crc24Computed.iCrc24 >> 8) & 0xff);
                abReturn[2] = (byte)(Crc24Computed.iCrc24 & 0xff);
                return abReturn;
            }
            else
                throw new FormatException("Failed to complete EncryptedDatabase.VariablesToBytes().");
        }

        public new void Write(string sTable, int iId, byte[] abData)
        {
            byte[] abEncrypted = _Cryptography.EncryptAes(abData, _abAesKey);
            base.Write(sTable, iId, abEncrypted);
        }

        public void Write(DatabaseObject Object, string sTable)
        {
            byte[] abRow;
            int i, iLength;

            if (Object != null)
            {
                _ltVariables.Clear();
                for (i = 0; i < Object.VariablesToStore(); i++)
                    _ltVariables.Add(FetchEmptyDatabaseVariable());

                iLength = Object.GetDatabaseVariables(_ltVariables);
                abRow = VariablesToBytes(_ltVariables, iLength);
                Write(sTable, Object.iIdExternal, abRow);
                RecycleDatabaseVariables();
            }
        }

        public new void Update(string sTable, int iId, byte[] abData)
        {
            byte[] abEncrypted = _Cryptography.EncryptAes(abData, _abAesKey);
            base.Update(sTable, iId, abEncrypted);
        }

        #endregion
    }
}
