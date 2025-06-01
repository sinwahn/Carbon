using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using static CarbonGui.TrackedProcess;

namespace CarbonGui
{
	public class TrackedProcess
	{
		public enum State
		{
			Running,
			Connecting,
			Connected,
			Dead,
		}

		public TrackedProcess(Process process)
		{
			state = State.Running;
			Id = (uint)process.Id;
			StartTime = process.StartTime;
			Update(process);
			Logger.Log(Logger.Category.Process, $"process created {Id}");
		}

		public void MarkAsConnecting()
		{
			state = State.Connecting;
		}

		public void MarkAsConnected()
		{
			state = State.Connected;
		}

		public void MarkAsDead()
		{
			state = State.Dead;
			Logger.Log(Logger.Category.Process, $"process died {Id}");
		}

		public string FormatInfo(int titleMaxLength)
		{
			return TrackedProcess.State.GetName(state.GetType(), state)
				+ " " + Id + " " + GetTrimmedTitle(titleMaxLength);
		}

		public string GetTrimmedTitle(int maxLength)
		{
			const string dots = "...";
			string title = MainWindowTitle;
			if (title.Length > maxLength - dots.Length)
				title = title.Substring(0, maxLength - dots.Length) + dots;
			return title;
		}

		public void Update(Process process)
		{
			MainWindowTitle = process.MainWindowTitle;
		}

		public State state = State.Dead;
		public uint Id = 0;
		public string MainWindowTitle;
		public DateTime StartTime;
	}

	public class ProcessTracker
	{
		public ProcessTracker(string targetProcessName, int pollingInterval)
		{
			this.targetProcessName = targetProcessName;
			this.pollingInterval = pollingInterval;
		}

		public void Initialize(ProcessesPopup processesPopup, MainWindow mainWindow, TargetSettings targetSettings)
		{
			this.processesPopup = processesPopup;
			this.mainWindow = mainWindow;
			this.targetSettings = targetSettings;
			cancellationTokenSource = new CancellationTokenSource();
			pollingTask = Task.Run(() => PollProcesses(cancellationTokenSource.Token),
				cancellationTokenSource.Token);
		}

		public void StopTracking()
		{
			cancellationTokenSource.Cancel();
			pollingTask.Wait();
		}

		private void PollProcesses(CancellationToken cancellationToken)
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				var currentProcesses = Process.GetProcessesByName(targetProcessName).ToList();

				for (int i = allProcesses.Count - 1; i >= 0; i--)
				{
					var trackedProcess = allProcesses[i];
					var process = currentProcesses.FirstOrDefault(proc => proc.Id == trackedProcess.Id);

					if (process != null)
					{
						trackedProcess.Update(process);
						if (targetSettings.GetProcess() == trackedProcess)
							Application.Current.Dispatcher.Invoke(() => mainWindow.SetProcessTitle(trackedProcess));
					}
					else
					{
						trackedProcess.MarkAsDead();
						allProcesses.RemoveAt(i);
					}
				}

				foreach (var process in currentProcesses)
					if (allProcesses.All(tp => tp.Id != process.Id))
						allProcesses.Add(new TrackedProcess(process));
				
				OnAvailableProcessesUpdated();
				Thread.Sleep(pollingInterval);
			}
		}

		private void OnAvailableProcessesUpdated()
		{
			processesPopup.OnAvailableProcessesUpdated();
			if (!allProcesses.Contains(targetSettings.GetProcess()))
				targetSettings.SetProcess(null);
		}

		public TrackedProcess GetProcessById(uint processId)
		{
			return allProcesses.First(process => process.Id == processId);
		}

		public IEnumerable<TrackedProcess> GetTrackedProcesses()
		{
			return allProcesses;
		}

		public IEnumerable<TrackedProcess> GetInjectableProcesses()
		{
			var result = new List<TrackedProcess>();
			foreach (var process in allProcesses.Where(process => process.state == State.Running))
				result.Add(process);
			return result;
		}

		private readonly string targetProcessName;
		private readonly int pollingInterval;
		private readonly List<TrackedProcess> allProcesses = new List<TrackedProcess>();
		private CancellationTokenSource cancellationTokenSource = null;
		private Task pollingTask = null;
		private ProcessesPopup processesPopup = null;
		private MainWindow mainWindow = null;
		private TargetSettings targetSettings = null;
	}
}
