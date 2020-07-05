namespace OpenDear.Model
{
    using System;
    using System.IO;
    using System.Data;
    using System.Data.SQLite;
    using System.Collections.Generic;


    public struct Row
    {
        public int iId;
        public byte[] abData;
    }


    public class SQLiteDatabase
    {
        public enum nState { OK, DirectoryNotFound, FileNotFound, CouldNotCreate, CouldNotOpen, CouldNotRead, Undefined };

        public const int ciMemoryBufferLength = 0x4000;
        public const string csDatabaseExtension = ".sqlite";

        protected bool _isOpen;
        protected byte[] _abMemoryBuffer;
        protected nState _eState;
        protected string _sPath, _sConnectionString;
        protected SQLiteConnection _DatabaseConnection;


        #region constructors

        protected SQLiteDatabase()
        {
            _isOpen = false;
            _abMemoryBuffer = new byte[ciMemoryBufferLength];
            _eState = nState.Undefined;
            _sPath = _sConnectionString = string.Empty;
            _DatabaseConnection = null;
        }

        public SQLiteDatabase(string sPath) : this()
        {
            string sDirectoryName = Path.GetDirectoryName(sPath);

            if (string.IsNullOrEmpty(sPath))
            {
                _eState = nState.DirectoryNotFound;
            }
            else
            {
                if (!Directory.Exists(sDirectoryName))
                {
                    try { Directory.CreateDirectory(sDirectoryName); }
                    catch { };
                }

                if (Directory.Exists(sDirectoryName))
                {
                    _sPath = sPath;
                    _sConnectionString = "Data Source=" + _sPath;
                    _DatabaseConnection = new SQLiteConnection(_sConnectionString);

                    if (File.Exists(sPath))
                        _eState = nState.OK;
                    else
                        _eState = nState.FileNotFound;
                }
                else
                    _eState = nState.DirectoryNotFound;
            }
        }

        #endregion

        #region properties

        public string sPath
        {
            get { return _sPath; }
        }

        public nState eState
        {
            get { return _eState; }
        }
        #endregion

        #region commands and methods

        public void AddTables(string[] asTableNames)
        {
            int i = 0;
            string[] asSqlCommands;

            if (((_eState == nState.OK) || (_eState == nState.FileNotFound)) && (_DatabaseConnection != null) && (asTableNames != null) && (asTableNames.Length > 0))
            {
                _eState = nState.OK;
                asSqlCommands = new string[asTableNames.Length];

                foreach (string sTableName in asTableNames)
                    asSqlCommands[i++] = "CREATE TABLE IF NOT EXISTS " + sTableName + " ( id INT PRIMARY KEY NOT NULL, data BLOB )";
                CommandsNonQuery(asSqlCommands);
                Close();

                if (File.Exists(_sPath))
                    _eState = nState.OK;
                else
                    _eState = nState.FileNotFound;
            }
            else
                _eState = nState.CouldNotCreate;
        }

        public void Close()
        {
            if (_isOpen)
            {
                _DatabaseConnection.Close();
                _isOpen = false;
            }
        }

        public void CommandNonQuery(string sSqlCommand)
        {
            if (Open())
            {
                using (SQLiteCommand command = new SQLiteCommand(sSqlCommand, _DatabaseConnection))
                    command.ExecuteNonQuery();
            }
        }

        public void CommandNonQuery(string sSqlCommand, byte[] abData)
        {
            if (Open())
            {
                try
                {
                    using (SQLiteCommand command = new SQLiteCommand(sSqlCommand, _DatabaseConnection))
                    {
                        command.Parameters.Add("@data", DbType.Binary, abData.Length).Value = abData;
                        command.ExecuteNonQuery();
                    }
                }
                catch
                {
                    Console.WriteLine("Error in CommandNonQuery: " + sSqlCommand);
                }
            }
        }

        public object CommandScalar(string sSqlCommand)
        {
            object Result = null;
            if (Open())
            {
                using (SQLiteCommand Command = new SQLiteCommand(sSqlCommand, _DatabaseConnection))
                    Result = Command.ExecuteScalar();
            }
            return Result;
        }

        public void CommandsNonQuery(string[] sSqlCommands)
        {
            if (Open())
            {
                using (SQLiteCommand command = new SQLiteCommand(_DatabaseConnection))
                {
                    foreach (string sCommand in sSqlCommands)
                    {
                        command.CommandText = sCommand;
                        command.ExecuteNonQuery();
                    }
                }
            }
        }

        public int CountRecords(string sTable)
        {
            object Result = CommandScalar("SELECT COUNT(id) FROM " + sTable);

            return (Result == null) ? -1 : Convert.ToInt32(Result);
        }

        public void Delete(string sTable, int iId)
        {
            if (!string.IsNullOrEmpty(sTable))
                CommandNonQuery("DELETE FROM " + sTable + " WHERE id=" + iId.ToString());
        }

        public void Dispose()
        {
            Close();
            if (_DatabaseConnection != null)
            {
                _DatabaseConnection.Dispose();
                _DatabaseConnection = null;
            }
        }

        protected byte[] GetBytes(SQLiteDataReader Reader, int iIndex)
        {
            long kBytesRead, kFieldOffset = 0;

            using (MemoryStream stream = new MemoryStream())
            {
                while ((kBytesRead = Reader.GetBytes(iIndex, kFieldOffset, _abMemoryBuffer, 0, ciMemoryBufferLength)) > 0)
                {
                    stream.Write(_abMemoryBuffer, 0, (int)kBytesRead);
                    kFieldOffset += kBytesRead;
                }
                return stream.ToArray();
            }
        }

        public List<string> GetTableNames()
        {
            List<string> ltReturn = new List<string>();

            if ((_DatabaseConnection != null) && !string.IsNullOrEmpty(_sPath) && (File.Exists(_sPath)))
            {
                using (SQLiteCommand Command = new SQLiteCommand("SELECT name FROM sqlite_master WHERE type='table';", _DatabaseConnection))
                {
                    if (Open())
                    {
                        using (SQLiteDataReader Reader = Command.ExecuteReader())
                        {
                            while (Reader.Read())
                                ltReturn.Add(Reader.GetFieldValue<string>(0));
                        }
                        Close();
                    }
                }
            }
            return ltReturn;
        }

        public bool IdExists(string sTable, string sId)
        {
            return CommandScalar("SELECT id FROM " + sTable + " WHERE id=" + sId) != null;
        }

        public bool Open()
        {
            if (_eState == nState.OK)
            {
                if (!_isOpen)
                {
                    try
                    {
                        _DatabaseConnection.Open();
                        _isOpen = true;
                        _eState = nState.OK;
                    }
                    catch
                    {
                        _isOpen = false;
                        _eState = nState.CouldNotOpen;

                    }
                }
            }
            else
            {
                _isOpen = false;
                _eState = nState.CouldNotOpen;
                if (_DatabaseConnection != null)
                {
                    _DatabaseConnection.Close();
                    _DatabaseConnection = null;
                }
            }
            return _isOpen;
        }

        public List<Row> Read(string sTable)
        {
            Row NewRow;
            List<Row> ltReturn = new List<Row>();

            if (Open())
            {
                using (SQLiteCommand Command = new SQLiteCommand("SELECT id, data FROM " + sTable, _DatabaseConnection))
                {
                    using (SQLiteDataReader Reader = Command.ExecuteReader())
                    {
                        while (Reader.Read())
                        {
                            NewRow = new Row
                            {
                                iId = Reader.GetFieldValue<int>(0),
                                abData = GetBytes(Reader, 1)
                            };
                            ltReturn.Add(NewRow);
                        }
                    }
                }
            }
            return ltReturn;
        }

        public List<Row> Read(string sTable, int iMinId, int iMaxId)
        {
            Row NewRow;
            List<Row> ltReturn = new List<Row>();

            if (Open())
            {
                using (SQLiteCommand Command = new SQLiteCommand("SELECT id, data FROM " + sTable + " WHERE id>=" + iMinId.ToString() + " AND id <=" + iMaxId.ToString(), _DatabaseConnection))
                {
                    using (SQLiteDataReader Reader = Command.ExecuteReader())
                    {
                        while (Reader.Read())
                        {
                            NewRow = new Row
                            {
                                iId = Reader.GetFieldValue<int>(0),
                                abData = GetBytes(Reader, 1)
                            };
                            ltReturn.Add(NewRow);
                        }
                    }
                }
            }
            return ltReturn;
        }

        public byte[] Read(string sTable, int iId)
        {
            byte[] abReturn = null;

            if (Open())
            {
                using (SQLiteCommand Command = new SQLiteCommand("SELECT id, data FROM " + sTable + " WHERE id=" + iId.ToString(), _DatabaseConnection))
                {
                    using (SQLiteDataReader Reader = Command.ExecuteReader())
                    {
                        while (Reader.Read())
                            abReturn = GetBytes(Reader, 1);
                    }
                }
            }
            return abReturn;
        }

        public void Write(string sTable, int iId, byte[] abData)
        {
            string sId = iId.ToString();

            if (!string.IsNullOrEmpty(sTable) && (abData != null) && Open())
            {
                if (IdExists(sTable, sId))
                    CommandNonQuery("UPDATE " + sTable + " SET data=@data WHERE id=" + sId, abData);
                else
                    CommandNonQuery("INSERT INTO " + sTable + " ( id, data ) VALUES ( " + sId + ", @data )", abData);
            }
        }

        public void Update(string sTable, int iId, byte[] abData)
        {
            if (!string.IsNullOrEmpty(sTable) && (abData != null) && Open())
                CommandNonQuery("UPDATE " + sTable + " SET data=@data WHERE id=" + iId.ToString(), abData);
        }
        #endregion
    }
}
