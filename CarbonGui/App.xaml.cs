using System;
using System.IO;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

namespace CarbonGui
{
	public class MainFileChecker
	{
		public void CheckDll()
		{
			if (!File.Exists(PathConfig.Dll))
				Raise("Missing DLL at path: " + Path.GetFullPath(PathConfig.Dll));
		}

		public void CheckDump()
		{
			if (File.Exists(PathConfig.Dump))
				return;

			Console.WriteLine("Missing dump file, creating new one");

			if (!File.Exists(PathConfig.AddressDumper))
				Raise("Missing dumper at path: ", Path.GetFullPath(PathConfig.AddressDumper));

			var processInfo = new ProcessStartInfo(PathConfig.AddressDumper, PathConfig.Dump)
			{
				UseShellExecute = false
			};

			using (var process = Process.Start(processInfo))
			{
				process.WaitForExit();
				if (process.ExitCode != 0)
					Raise("AddressDumper failed");
			}
		}

		public void CheckUserDirectory()
		{
			if (!Directory.Exists(PathConfig.UserDirectory))
				Directory.CreateDirectory(PathConfig.UserDirectory);
		}

		private void Raise(string message, string path = null)
		{
			throw new FileNotFoundException($"{message}: {path}");
		}

	}

	public class ScriptFolderWatcher
	{
		public ScriptFolderWatcher(MainWindow window, ListBox listBox)
		{
			CheckScriptDirectory();
			scriptFiles = new ObservableCollection<string>();
			listBox.ItemsSource = scriptFiles;
			listBox.SelectionChanged += window.OnScriptListBoxSelectionChanged;
			this.window = window;
			InitializeFileWatcher();
			LoadExistingFiles();
		}

		public void CheckScriptDirectory()
		{
			if (!Directory.Exists(PathConfig.Scripts))
				Directory.CreateDirectory(PathConfig.Scripts);
		}

		private void InitializeFileWatcher()
		{
			CheckScriptDirectory();

			fileWatcher = new FileSystemWatcher
			{
				Path = PathConfig.Scripts,
				NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
				Filter = "*.*"
			};

			fileWatcher.Created += OnFileChanged;
			fileWatcher.Deleted += OnFileChanged;
			fileWatcher.EnableRaisingEvents = true;
		}

		private void LoadExistingFiles()
		{
			scriptFiles.Clear();
			foreach (var file in Directory.GetFiles(PathConfig.Scripts))
			{
				scriptFiles.Add(Path.GetFileName(file));
			}
		}

		private void OnFileChanged(object sender, FileSystemEventArgs e)
		{
			Application.Current.Dispatcher.Invoke(() =>
			{
				switch (e.ChangeType)
				{
					case WatcherChangeTypes.Created:
						scriptFiles.Add(Path.GetFileName(e.FullPath));
						break;
					case WatcherChangeTypes.Deleted:
						scriptFiles.Remove(Path.GetFileName(e.FullPath));
						break;
				}
			});
		}

		private FileSystemWatcher fileWatcher;
		private ObservableCollection<string> scriptFiles;
		private MainWindow window;
	}

	public partial class App : Application
	{
		public void Application_Startup(object sender, StartupEventArgs e)
		{
			Environment.SetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--disable-features=MetricsReportingEnabled,EnablePersistentHistograms");
			Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", Path.GetTempPath());

			Logger.Initialize();

			CheckMainFiles();
			injectionHandler = new InjectionHandler();
			statesPopup = new StatesPopup();
			statesPopup = new StatesPopup();
			processesPopup = new ProcessesPopup();
			mainWindow = new MainWindow();
			commonPipe = new CommonServer(PipeNames.commonPipeName);
			processTracker = new ProcessTracker("RobloxStudioBeta", 1000);
			targetSettings = new TargetSettings();

			mainWindow.Initialize(processTracker, injectionHandler, statesPopup, processesPopup, targetSettings);

			statesPopup.Initialize(targetSettings, mainWindow, injectionHandler);
			processesPopup.Initialize(targetSettings, mainWindow, injectionHandler, processTracker);

			commonPipe.Initialize(injectionHandler, processTracker);
			injectionHandler.Initialize(processTracker, statesPopup, commonPipe, targetSettings);
			processTracker.Initialize(processesPopup, mainWindow, targetSettings);

			targetSettings.Initialize(mainWindow);

			scriptFolderWatcher = new ScriptFolderWatcher(mainWindow, mainWindow.ScriptFilesListBox);

			mainWindow.Show();
			commonPipe.StartReading();
		}

		private void CheckMainFiles()
		{
			var mainFileChecker = new MainFileChecker();
			mainFileChecker.CheckUserDirectory();
			mainFileChecker.CheckDll();
			mainFileChecker.CheckDump();
		}

		private CommonServer commonPipe = null;
		private InjectionHandler injectionHandler = null;
		private MainWindow mainWindow = null;
		private StatesPopup statesPopup = null;
		private ProcessesPopup processesPopup = null;
		private ScriptFolderWatcher scriptFolderWatcher = null;
		private ProcessTracker processTracker = null;
		private TargetSettings targetSettings = null;
	}
}
