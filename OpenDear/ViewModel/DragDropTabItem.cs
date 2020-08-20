namespace OpenDear.ViewModel
{
    using System;
    using System.Windows;
    using System.Windows.Controls;


    public class DragDropTabItem : TabItem
    {

        #region constructors

        public DragDropTabItem() : base()
        {
            AllowDrop = true;
        }

        #endregion

        #region properties

        private static readonly DependencyProperty IsDragOverProperty = DependencyProperty.Register("IsDragOver", typeof(bool), typeof(DragDropTabItem));

        public bool IsDragOver
        {
            get { return (bool)GetValue(IsDragOverProperty); }
            set { SetValue(IsDragOverProperty, value); }
        }

        #endregion

        #region methods

        protected override void OnDragEnter(DragEventArgs Arguments)
        {
            Arguments.Effects = DragDropEffects.None;
            Arguments.Handled = true;
            IsDragOver = true;
        }

        protected override void OnDragLeave(DragEventArgs Arguments)
        {
            Arguments.Effects = DragDropEffects.None;
            Arguments.Handled = true;
            IsDragOver = false;
        }

        protected override void OnDragOver(DragEventArgs Arguments)
        {
            Arguments.Effects = DragDropEffects.None;
            Arguments.Handled = true;
            IsDragOver = true;
        }

        protected override void OnDrop(DragEventArgs Arguments)
        {
            Arguments.Effects = DragDropEffects.None;
            Arguments.Handled = true;
            IsDragOver = false;
        }
        #endregion
    }
}
