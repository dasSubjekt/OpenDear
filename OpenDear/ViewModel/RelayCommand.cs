// This class is based on RelayCommand.cs from the GalaSoft.MvvmLight Project by Laurent Bugnion
// <web>http://www.galasoft.ch/mvvm/</web>.
// This class could be replaced by installing the NuGet package MvvmLightLibs.


namespace OpenDear.ViewModel
{
    using System;
    using System.Windows.Input;


    /// <summary>A class that implements the ICommand interface in order to relay its
    /// functionality to other objects by invoking one or two delegate methods.</summary>
    public class RelayCommand : ICommand
    {
        private readonly Action _ExecuteMethod;
        private readonly Func<bool> _CanExecuteMethod;

        /// <summary>Initializes a new instance of the RelayCommand class that can always execute.</summary>
        /// <param name="ExecuteMethod">Method that contains the command's execution logic.</param>
        /// <exception cref="ArgumentNullException">If the ExecuteMethod argument is null.</exception>
        public RelayCommand(Action ExecuteMethod) : this(ExecuteMethod, null)
        {
        }

        /// <summary>Initializes a new instance of the RelayCommand class that executes conditionally.</summary>
        /// <param name="ExecuteMethod">Method that contains the command's execution logic.</param>
        /// <param name="CanExecuteMethod">Method that contains the command's execute condition logic.</param>
        /// <exception cref="ArgumentNullException">If the ExecuteMethod argument is null.</exception>
        public RelayCommand(Action ExecuteMethod, Func<bool> CanExecuteMethod)
        {
            _ExecuteMethod = ExecuteMethod ?? throw new ArgumentNullException("RelayCommand: ExecuteMethod must not be null.");
            _CanExecuteMethod = CanExecuteMethod;
        }

        /// <summary>Part of the ICommand interface, determines whether the command can execute in the current program state.</summary>
        /// <param name="oParameter">Data used by the command. If the command does not require data 
        /// to be passed, this object can be set to a null reference.</param>
        /// <returns>True if this command can be executed, false otherwise.</returns>
        public bool CanExecute(object oParameter)
        {
            return _CanExecuteMethod == null ? true : _CanExecuteMethod();
        }

        /// <summary>Part of the ICommand interface, defines the method to be called when the command is invoked.</summary>
        /// <param name="oParameter">Data used by the command. If the command does not
        /// require data to be passed, this object can be set to a null reference.</param>
        public void Execute(object oParameter)
        {
            _ExecuteMethod?.Invoke();
        }

        /// <summary>Part of the ICommand interface, invoked when changes occur that affect whether the command should execute.</summary>
        public event EventHandler CanExecuteChanged
        {
            add
            {
                if (_CanExecuteMethod != null)
                    CommandManager.RequerySuggested += value;
            }

            remove
            {
                if (_CanExecuteMethod != null)
                    CommandManager.RequerySuggested -= value;
            }
        }
    }
}
