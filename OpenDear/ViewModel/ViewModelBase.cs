// Sources of this class are the GalaSoft.MvvmLight Project by Laurent Bugnion:
// <web>http://www.galasoft.ch/mvvm/</web>
// and the WindowClosingDemo by Nish Sivakumar:
// <web>http://www.codeproject.com/Articles/73251/Handling-a-Window-s-Closed-and-Closing-events-in-t</web>
// Part of the functionality in this class could be replaced by installing the NuGet package MvvmLightLibs.

namespace OpenDear.ViewModel
{
    using System;
    using System.Linq;
    using OpenDear.Model;
    using System.Windows;
    using System.Collections;
    using System.Windows.Input;
    using System.ComponentModel;
    using System.Collections.Generic;


    /// <summary>Base class for implementing an MVVM pattern.</summary>
    public class ViewModelBase : INotifyDataErrorInfo, INotifyPropertyChanged
    {
        public enum nValidationType { First, Middle, Last, Single };

        private bool _isRaiseErrorsChanged;
        private bool? _isDesignMode;
        private int _iErrorId;
        private string _sErrorMessage;
        private List<Property> _ltValidationErrors;
        protected Dictionary<string, string> _dyTranslations;

        #region constructors

        /// <summary>Initializes a new instance of the ViewModelBase class.</summary>
        public ViewModelBase()
        {
            _isDesignMode = null;
            _isRaiseErrorsChanged = false;
            _iErrorId = 0;
            _sErrorMessage = string.Empty;
            _ltValidationErrors = new List<Property>();
            _dyTranslations = new Dictionary<string, string>();

            dcClose = new RelayCommand(ExecuteClose);
            dcIsClosing = new RelayCommand(ExecuteIsClosing, CanExecuteIsClosing);
            dcCancelClosing = new RelayCommand(ExecuteCancelClosing);
            dcWasClosed = new RelayCommand(ExecuteWasClosed);
        }
        #endregion

        #region properties

        /// <summary>Close command to be bound to event(s) in the user interface (read-only public property).</summary>
        public ICommand dcClose { get; }

        /// <summary>CancelClosing command that can be attached to a window's CancelClosing dependency property.
        /// To activate, insert in MainWindow.xaml: y:ViewModelBase.CancelClosing="{Binding dcCancelClosing}".</summary>     
        public ICommand dcCancelClosing { get; }

        public static readonly DependencyProperty CancelClosingProperty = DependencyProperty.RegisterAttached("CancelClosing", typeof(ICommand), typeof(ViewModelBase));

        public event EventHandler<DataErrorsChangedEventArgs> ErrorsChanged;

        /// <summary>IsClosing command that can be attached to a window's IsClosing dependency property.
        /// To activate, insert in MainWindow.xaml: y:ViewModelBase.IsClosing="{Binding dcIsClosing}".</summary>     
        public ICommand dcIsClosing { get; }

        public static readonly DependencyProperty IsClosingProperty = DependencyProperty.RegisterAttached("IsClosing", typeof(ICommand), typeof(ViewModelBase), new UIPropertyMetadata(new PropertyChangedCallback(IsClosingChanged)));

        /// <summary>True if the view model is being run in design mode (for instance in XAML preview),
        /// false if it is running in a full application. For example, this property may be needed to supply
        /// design-time data in situations when run-time data are not available (read-only public property).</summary>
        public bool isDesignMode
        {
            get
            {
                if (!_isDesignMode.HasValue)
                {
                    DependencyProperty DepProp = DesignerProperties.IsInDesignModeProperty;
                    _isDesignMode = (bool)DependencyPropertyDescriptor.FromProperty(DepProp, typeof(FrameworkElement)).Metadata.DefaultValue;
                }
                return _isDesignMode.Value;
            }
        }

        public string sErrorMessage
        {
            get { return _sErrorMessage; }
        }

        public bool HasErrors
        {
            get { return _ltValidationErrors.Count > 0; }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>WasClosed command that can be attached to a window's WasClosed dependency property.
        /// To activate, insert in MainWindow.xaml: y:ViewModelBase.WasClosed="{Binding dcWasClosed}".</summary>
        public ICommand dcWasClosed { get; }

        public static readonly DependencyProperty WasClosedProperty = DependencyProperty.RegisterAttached("WasClosed", typeof(ICommand), typeof(ViewModelBase), new UIPropertyMetadata(new PropertyChangedCallback(WasClosedChanged)));

        #endregion

        #region methods

        /// <summary>Delegate method that determines whether dcIsClosing can be executed.</summary>
        protected virtual bool CanExecuteIsClosing()
        {
            // return MessageBox.Show("OK to close?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes;
            return true;
        }

        public int ClearErrors(string sPropertyName)
        {
            int iReturn = _ltValidationErrors.RemoveAll(Item => Item.sName == sPropertyName);

            RequeryErrorMessage();

            return iReturn;
        }

        /// <summary>Delegate method invoked in a derived class by cmdCancelClosing.</summary>
        protected virtual void ExecuteCancelClosing()
        {
        }

        /// <summary>Delegate method invoked by dcClose.</summary>
        protected void ExecuteClose()
        {
            Application.Current.MainWindow.Close();   // trigger the MainWindow's Closing event
        }

        /// <summary>Delegate method invoked in a derived class by dcIsClosing.</summary>
        protected virtual void ExecuteIsClosing()
        {
        }

        /// <summary>Delegate method invoked in a derived class by dcWasClosed.</summary>
        protected virtual void ExecuteWasClosed()
        {
        }

        protected Property GetBindingListId(BindingList<Property> blList, int iId)
        {
            Property Return;
            IEnumerable<Property> qrProperties;

            if (blList == null)
                Return = null;
            else
            {
                qrProperties = from p in blList where p.iId == iId select p;
                Return = (qrProperties.Count() == 0) ? null : qrProperties.First();
            }
            return Return;
        }

        protected Property GetBindingListNumber(BindingList<Property> blList, int iNumber)
        {
            Property Return;
            IEnumerable<Property> qyProperties;

            if (blList == null)
                Return = null;
            else
            {
                qyProperties = from p in blList where p.iNumber == iNumber select p;
                Return = (qyProperties.Count() == 0) ? null : qyProperties.First();
            }
            return Return;
        }

        /// <summary>Gets the CancelClosing command attached to a DependencyObject window.</summary>
        /// <returns>The CancelClosing command.</returns>
        public static ICommand GetCancelClosing(DependencyObject WindowObject)
        {
            return (ICommand)WindowObject.GetValue(CancelClosingProperty);
        }

        public IEnumerable GetErrors(string sPropertyName)
        {
            IEnumerable<Property> qyValidationErrors;

            if (string.IsNullOrEmpty(sPropertyName))
                qyValidationErrors = _ltValidationErrors;
            else
                qyValidationErrors = from Item in _ltValidationErrors where Item.sName == sPropertyName select Item;

            return qyValidationErrors.ToList();
        }

        /// <summary>Gets the IsClosing command attached to a DependencyObject window.</summary>
        /// <returns>The IsClosing command.</returns>
        public static ICommand GetIsClosing(DependencyObject WindowObject)
        {
            return (ICommand)WindowObject.GetValue(IsClosingProperty);
        }

        /// <summary>Gets the WasClosed command attached to a DependencyObject window.</summary>
        /// <returns>The WasClosed command.</returns>
        public static ICommand GetWasClosed(DependencyObject WindowObject)
        {
            return (ICommand)WindowObject.GetValue(WasClosedProperty);
        }

        /// <summary>Callback method for adding the WindowIsClosing event handler to MainWindow.Closing.</summary>
        private static void IsClosingChanged(DependencyObject Target, DependencyPropertyChangedEventArgs EventArguments)
        {
            if (Target is Window Win)
            {
                if (EventArguments.NewValue != null)
                {
                    Win.Closing += WindowIsClosing;
                }
                else
                {
                    Win.Closing -= WindowIsClosing;
                }
            }
        }

        public void IterateRaisePropertyChanged(string sFormat, int iFrom, int iTo)
        {
            for (int iIndex = iFrom; iIndex <= iTo; iIndex++)
                RaisePropertyChanged(string.Format(sFormat, iIndex));
        }

        public bool PropertyHasErrors(string sPropertyName)
        {
            return _ltValidationErrors.Exists(Item => Item.sName == sPropertyName);
        }

        public void RaiseErrorsChanged(string sPropertyName)
        {
            _isRaiseErrorsChanged = false;
            ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(sPropertyName));
        }

        /// <summary>Notifies the user interface that the value of a property has changed.</summary>
        /// <param name="sPropertyName">name of the property to be requeried</param>
        public void RaisePropertyChanged(string sPropertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(sPropertyName));
        }

        protected void RequeryErrorMessage()
        {
            if (HasErrors)
                _sErrorMessage = _ltValidationErrors.First().sText;
            else
                _sErrorMessage = string.Empty;
        }

        public void ValidateRaiseErrorsChanged(nValidationType eValidationType, string sPropertyName, bool isValid, string sMessageIfInvalid)
        {
            if ((eValidationType == nValidationType.First) || (eValidationType == nValidationType.Single))
            {
                _isRaiseErrorsChanged = (ClearErrors(sPropertyName) > 0);
                _iErrorId = 0;
            }

            if (!isValid)
            {
                _ltValidationErrors.Add(new Property(_iErrorId++, 0, sPropertyName, sMessageIfInvalid));
                _sErrorMessage = sMessageIfInvalid;
                _isRaiseErrorsChanged = true;
            }

            if (((eValidationType == nValidationType.Single) || (eValidationType == nValidationType.Last)) && _isRaiseErrorsChanged)
                RaiseErrorsChanged(sPropertyName);
        }

        /// <summary>Sets the CancelClosing command attached to a DependencyObject window.</summary>
        public static void SetCancelClosing(DependencyObject WindowObject, ICommand BackgroundMessage)
        {
            WindowObject.SetValue(CancelClosingProperty, BackgroundMessage);
        }

        /// <summary>Sets the IsClosing command attached to a DependencyObject window.</summary>
        public static void SetIsClosing(DependencyObject WindowObject, ICommand BackgroundMessage)
        {
            WindowObject.SetValue(IsClosingProperty, BackgroundMessage);
        }

        /// <summary>Sets the WasClosed command attached to a DependencyObject window.</summary>
        public static void SetWasClosed(DependencyObject WindowObject, ICommand BackgroundMessage)
        {
            WindowObject.SetValue(WasClosedProperty, BackgroundMessage);
        }

        public string Translate(string sKey)
        {
            // Console.WriteLine("Translate(" + sKey + ")");
            return _dyTranslations[sKey];
        }

        /// <summary>Callback method for adding the WindowWasClosed event handler to MainWindow.Closed.</summary>
        private static void WasClosedChanged(DependencyObject Target, DependencyPropertyChangedEventArgs EventArgs)
        {
            if (Target is Window Win)
            {
                if (EventArgs.NewValue != null)
                    Win.Closed += WindowWasClosed;
                else
                    Win.Closed -= WindowWasClosed;
            }
        }

        /// <summary>Event handler for MainWindow's Window.Closing event.</summary>
        static void WindowIsClosing(object Sender, CancelEventArgs EventArguments)
        {
            ICommand IsClosing = GetIsClosing(Sender as Window);
            if (IsClosing != null)
            {
                if (IsClosing.CanExecute(null))
                {
                    IsClosing.Execute(null);
                }
                else
                {
                    ICommand CancelClosing = GetCancelClosing(Sender as Window);
                    if (CancelClosing != null)
                    {
                        CancelClosing.Execute(null);
                    }
                    EventArguments.Cancel = true;
                }
            }
        }

        /// <summary>Event handler for MainWindow's Window.Closed event.</summary>
        public static void WindowWasClosed(object Sender, EventArgs EventArguments)
        {
            ICommand WasClosed = GetWasClosed(Sender as Window);
            if (WasClosed != null)
                WasClosed.Execute(null);
        }
        #endregion
    }
}
