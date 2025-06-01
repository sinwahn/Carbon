using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace CarbonGui
{
	public partial class ProcessesPopup
	{
		public void Initialize(TargetSettings targetSettings, MainWindow mainWindow, InjectionHandler injectionHandler, ProcessTracker processTracker)
		{
			this.mainWindow = mainWindow;
			this.processTracker = processTracker;
			this.injectionHandler = injectionHandler;
			this.targetSettings = targetSettings;
			popupStackPanel = mainWindow.ProcessesPopupStackPanel;
			popup = mainWindow.ProcessesPopup;
		}

		public void OnAvailableProcessesUpdated()
		{
			Application.Current.Dispatcher.Invoke(() => RenderProcesses());
		}

		void OnProcessButtonClicked(object sender, RoutedEventArgs e)
		{
			popup.IsOpen = false;
			Button clickedButton = sender as Button;
			if (buttonToProcess.TryGetValue(clickedButton, out TrackedProcess process))
				targetSettings.SetProcess(process);
		}

		private void RenderProcesses()
		{
			popupStackPanel.Children.Clear();
			buttonToProcess.Clear();

			var existingProcessIds = new HashSet<uint>();
			foreach (var process in processTracker.GetTrackedProcesses())
			{
				var foregroundTextBrush = new SolidColorBrush(Color.FromArgb(0xFF, 0xD3, 0xD3, 0xD3));
				var backgroundBrush = new SolidColorBrush(Color.FromArgb(0xFF, 0x2D, 0x2D, 0x2D));

				StackPanel itemPanel = new StackPanel
				{
					Orientation = Orientation.Horizontal,
				};

				var margin = new Thickness(0, 5, 0, 0);

				Button stateButton = new Button
				{
					Content = $"{process.FormatInfo(30)}",
					VerticalAlignment = VerticalAlignment.Center,
					Margin = margin,
					Background = backgroundBrush,
					Foreground = foregroundTextBrush,
					BorderThickness = new Thickness(0),
					Style = mainWindow.FindResource("HoverBottomButton") as Style,
				};

				stateButton.Click += OnProcessButtonClicked;

				itemPanel.Children.Add(stateButton);
				popupStackPanel.Children.Add(itemPanel);
				buttonToProcess[stateButton] = process;
			}
		}

		private ProcessTracker processTracker = null;
		private InjectionHandler injectionHandler = null;
		private MainWindow mainWindow = null;
		private StackPanel popupStackPanel = null;
		private Popup popup = null;
		private Dictionary<Button, TrackedProcess> buttonToProcess = new Dictionary<Button, TrackedProcess>();
		private TargetSettings targetSettings = null;
	}
}