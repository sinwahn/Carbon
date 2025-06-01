using System.IO;
using System.Windows.Input;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;

namespace CarbonGui
{

	public partial class MainWindow : Window
	{
		public void Initialize(ProcessTracker processTracker, InjectionHandler injectionHandler, StatesPopup statesPopup, ProcessesPopup processesPopup, TargetSettings targetSettings)
		{
			this.processTracker = processTracker;
			this.injectionHandler = injectionHandler;
			this.injectionHandler = injectionHandler;
			this.statesPopup = statesPopup;
			this.processesPopup = processesPopup;
			this.targetSettings = targetSettings;

			InitializeComponent();
			InitializeWebViewAsync();
		}

		private async void InitializeWebViewAsync()
		{
			await CodeEditor.EnsureCoreWebView2Async(null);
			monacoEditor = new MonacoEditor(CodeEditor);
		}

		private void OnTopBarMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			if (e.ClickCount == 2)
			{
				if (WindowState == WindowState.Maximized)
					WindowState = WindowState.Normal;
				else
					WindowState = WindowState.Maximized;
			}
			else
			{
				DragMove();
			}
		}

		private void OnMinimizeButtonClicked(object sender, RoutedEventArgs e)
		{
			WindowState = WindowState.Minimized;
		}

		private void OnMaximizeButtonClicked(object sender, RoutedEventArgs e)
		{
			if (WindowState == WindowState.Maximized)
				WindowState = WindowState.Normal;
			else
				WindowState = WindowState.Maximized;
		}

		private void OnCloseButtonClicked(object sender, RoutedEventArgs e)
		{
			Close();
		}

		private async void OnExecuteButtonClicked(object sender, RoutedEventArgs e)
		{
			if (!CheckCanRunCode())
				return;

			TryRunScript(await monacoEditor.GetEditorContentAsync());
		}

		private void TryRunScript(string script)
		{
			var info = injectionHandler.RunScript(script);
			if (info != null)
				MessageBox.Show(info.error, "failed to run script", MessageBoxButton.OK, MessageBoxImage.Error);
		}

		private void OnClearButtonClicked(object sender, RoutedEventArgs e)
		{
			monacoEditor.SetEditorContent("");
		}

		private void OnOpenFileButtonClicked(object sender, RoutedEventArgs e)
		{
			var openFileDialog = new OpenFileDialog
			{
				Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
			};

			if (openFileDialog.ShowDialog() == true)
				monacoEditor.SetEditorContent(File.ReadAllText(openFileDialog.FileName));
		}

		private async void OnSaveFileButtonClicked(object sender, RoutedEventArgs e)
		{
			var saveFileDialog = new SaveFileDialog
			{
				Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
			};

			if (saveFileDialog.ShowDialog() == true)
				File.WriteAllText(saveFileDialog.FileName, await monacoEditor.GetEditorContentAsync());
		}

		private void OnExecuteFileButtonClicked(object sender, RoutedEventArgs e)
		{
			if (!CheckCanRunCode())
				return;

			var saveFileDialog = new OpenFileDialog
			{
				Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
			};

			if (saveFileDialog.ShowDialog() == true)
				TryRunScript(File.ReadAllText(saveFileDialog.FileName));
		}

		private void OnSettingsButtonClicked(object sender, RoutedEventArgs e)
		{
			MessageBox.Show("no settings yet", ":woah:", MessageBoxButton.OK, MessageBoxImage.Asterisk);
		}

		private void OnAttachButtonClicked(object sender, RoutedEventArgs e)
		{
			if (injectionHandler.GetInjectionState() == InjectionHandler.InjectState.None)
			{
				var info = injectionHandler.TryInject();
				if (info != null)
				{
					MessageBox.Show(info.error, "failed to inject", MessageBoxButton.OK, MessageBoxImage.Error);
					return;
				}
			}
			else if (injectionHandler.GetInjectionState() == InjectionHandler.InjectState.Injected)
			{
				tryOpenStatesWindow();
			}
		}

		public void OnScriptListBoxSelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (e.AddedItems.Count > 0)
			{
				string selectedFile = e.AddedItems[0] as string;
				OnScriptFileClicked(Path.Combine(PathConfig.Scripts, selectedFile));
			}
		}

		public void OnLuaStateButtonClicked(object sender, RoutedEventArgs e)
		{
			tryOpenStatesWindow();
		}

		public void OnScriptFileClicked(string filePath)
		{
			monacoEditor.SetEditorContent(File.ReadAllText(filePath));
		}

		public void OnTargetLuaStateChanged(LuaState state)
		{
			if (state == null)
			{
				LuaStateLabel.Text = "LuaState not set";
				return;
			}

			LuaStateLabel.Text = "LuaState: " + state.ToString();
		}

		public void OnTargetProcessChanged(TrackedProcess process)
		{
			if (process == null)
			{
				ProcessLabel.Text = "Process not set";
				return;
			}

			statesPopup.OnAvailableLuaStatesUpdated();
			SetProcessTitle(process);
		}

		public void SetProcessTitle(TrackedProcess process)
		{
			ProcessLabel.Text = process.FormatInfo(30);
		}

		private void tryOpenStatesWindow()
		{
			if (injectionHandler.GetInjectionState() == InjectionHandler.InjectState.None)
				MessageBox.Show("not attached", "cannot execute", MessageBoxButton.OK, MessageBoxImage.Error);
		}

		private bool CheckCanRunCode()
		{
			if (injectionHandler.GetInjectionState() == InjectionHandler.InjectState.None)
				MessageBox.Show("not attached", "cannot execute", MessageBoxButton.OK, MessageBoxImage.Error);

			return injectionHandler.GetInjectionState() == InjectionHandler.InjectState.Injected;
		}

		private ProcessTracker processTracker = null;
		private InjectionHandler injectionHandler = null;
		private MonacoEditor monacoEditor = null;
		private ProcessesPopup processesPopup = null;
		private StatesPopup statesPopup = null;
		private TargetSettings targetSettings = null;
		private const int MaxTargetProcessTitleLength = 30;
	}
}
