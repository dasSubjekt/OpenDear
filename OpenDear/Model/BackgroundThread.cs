namespace OpenDear.Model
{
    using System;
    using OpenDear.Crypto;
    using System.Threading;
    using System.Collections.Concurrent;


    /// <summary>This class performs all tasks that may take longer than a second. Running them in the main window Thread would freeze the user interface.</summary>
    public class BackgroundThread
    {
        /// <summary>Enumerated type with the execution states of <c>BackgroundThread</c>.</summary>
        public enum nState { Idle, Working, CancelRequested };

        private readonly object StateLock = new object();

        private byte[] _abAesKey;
        private nState _eState;
        private Thread _AsyncThread;
        private readonly EncryptionServices _Cryptography;
        private readonly ConcurrentQueue<BackgroundMessage> _quCommand, _quReturn;


        #region constructors

        /// <summary>The constructor to initialize a <c>new BackgroundThread</c>.</summary>
        /// <param name=""></param>
        public BackgroundThread(EncryptionServices Cryptography = null)
        {
            _Cryptography = Cryptography ?? new EncryptionServices();
            _quCommand = new ConcurrentQueue<BackgroundMessage>();
            _quReturn = new ConcurrentQueue<BackgroundMessage>();
            _abAesKey = new byte[EncryptionServices.ciAes256KeyBytesLength];
            _Cryptography.GetRandomBytes(_abAesKey);
            Reset();
        }
        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abAesKey
        {
            get { return _abAesKey; }
        }

        /// <summary></summary>
        public ConcurrentQueue<BackgroundMessage> quReturn
        {
            get { return _quReturn; }
        }

        /// <summary></summary>
        public nState eState
        {
            get { return _eState; }
            private set
            {
                lock (StateLock)
                {
                    _eState = value;
                }
            }
        }
        #endregion

        #region methods

        /// <summary></summary>
        private void AsynchronousThreadMethod()
        {
            while (_quCommand.TryDequeue(out BackgroundMessage UserInterfaceMessage))
            {
                switch (UserInterfaceMessage.eType)
                {
                    case BackgroundMessage.nType.PasswordToKey: ExecutePasswordToKey(UserInterfaceMessage); break;
                    default: throw new NotImplementedException("command not implemented: " + UserInterfaceMessage.eType.ToString());
                }
                if (_eState == nState.CancelRequested)
                    Reset();
            }
            _quReturn.Enqueue(new BackgroundMessage(BackgroundMessage.nType.Stop));
            eState = nState.Idle;
            _AsyncThread = null;
        }

        public void Dispose()
        {
            if (_abAesKey != null)
            {
                _Cryptography.GetRandomBytes(_abAesKey);
                _abAesKey = null;
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        public void Enqueue(BackgroundMessage UserInterfaceMessage)
        {
            _quCommand.Enqueue(UserInterfaceMessage);
        }

        /// <summary></summary>
        /// <param name=""></param>
        private void ExecutePasswordToKey(BackgroundMessage UserInterfaceMessage)
        {
            byte[] abKey;

            if ((UserInterfaceMessage.abKeyOrPassword == null) || (UserInterfaceMessage.abSignatureOrSalt == null))
            {
                throw new ArgumentException("Argument in BackgroundThread.ExecutePasswordToKey must not be null.");
            }
            else
            {
                Console.WriteLine("ExecutePasswordToKey start " + DateTime.Now.ToString("mm:ss fff"));
                abKey = _Cryptography.PasswordToAesKey(_Cryptography.DecryptAes(UserInterfaceMessage.abKeyOrPassword, _abAesKey), UserInterfaceMessage.abSignatureOrSalt);
                Console.WriteLine("ExecutePasswordToKey end " + DateTime.Now.ToString("mm:ss fff"));
                UserInterfaceMessage.abKeyOrPassword = _Cryptography.EncryptAes(abKey, _abAesKey);
            }
            _quReturn.Enqueue(UserInterfaceMessage);
        }

        /// <summary></summary>
        /// <param name=""></param>
        private void ExecuteXYZ(BackgroundMessage UserInterfaceMessage)
        {

        }

        /// <summary></summary>
        public void RequestCancel()
        {
            eState = nState.CancelRequested;
        }

        /// <summary>Reset all variables.</summary>
        private void Reset()
        {
#pragma warning disable IDE0059   // Suppress warning that the value assigned to variable is never used
            if (!_quCommand.IsEmpty)
                while (_quCommand.TryDequeue(out BackgroundMessage MessageToDiscard)) ;

            if (!_quReturn.IsEmpty)
                while (_quReturn.TryDequeue(out BackgroundMessage MessageToDiscard)) ;
#pragma warning restore IDE0059   // re-enable message "Value assigned to variable is never used"

            eState = nState.Idle;
            _AsyncThread = null;
        }

        /// <summary></summary>
        public bool Start()
        {
            if ((_eState != nState.Idle) || _quCommand.IsEmpty)
            {
                return false;
            }
            else
            {
                eState = nState.Working;
                _AsyncThread = new Thread(() => AsynchronousThreadMethod());
                _AsyncThread.Start();
                return true;
            }
        }


        /// <summary></summary>
        /// <param name=""></param>
        public bool Start(BackgroundMessage UserInterfaceMessage)
        {
            _quCommand.Enqueue(UserInterfaceMessage);
            return Start();
        }
        #endregion
    }
}
