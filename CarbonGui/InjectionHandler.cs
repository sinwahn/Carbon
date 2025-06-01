using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static CarbonGui.PrivateServer;
using static CarbonGui.TrackedProcess;

namespace CarbonGui
{
	public enum VmType
	{
		Unknown,
		Game = 2,
		Core = 3,
		Plugin = 5,
		BuiltinPlugin = 6,
	}

	public class LuaState
	{
		public ulong address = 0;
		public VmType vmType = VmType.Unknown;

		public override string ToString()
		{
			return $"{VmType.GetName(vmType.GetType(), vmType)} ({(int)vmType}) {address.ToString("X")}";
		}

		public void Update(LuaState other)
		{
			vmType = other.vmType;
		}
	}

	// keep in sync with DataModelWatcher.ixx
	public enum DataModelType
	{
		Invalid, // when type cannot be determined yet
		Server,
		Client,
		Unknown,
	};

	public class DataModel
	{
		public ulong address = 0;
		public DataModelType type = DataModelType.Invalid;
		public List<LuaState> states = new List<LuaState>();
	};

	class Injection
	{
		enum Progress
		{
			Injecting,
			AwaitingSignal,
		}

	};

	public class ConnectedProcessInfo
	{
		public ConnectedProcessInfo(TrackedProcess process, InjectionHandler injectionHandler)
		{
			this.process = process;
			this.injectionHandler = injectionHandler;
		}

		~ConnectedProcessInfo()
		{
			toServerPipe.StopReading();
		}

		public void InitializePipes()
		{
			toServerPipe = new PrivateServer(process, injectionHandler, Direction.ToServer);
			toClientPipe = new PrivateServer(process, injectionHandler, Direction.ToClient);
			toServerPipe.StartReading();
			toClientPipe.TryConnect();
		}

		private readonly InjectionHandler injectionHandler = null;
		public readonly TrackedProcess process = null;
		public readonly List<DataModel> dataModels = new List<DataModel>();
		public PrivateServer toServerPipe = null;
		public PrivateServer toClientPipe = null;
	}

	public class InjectApiResult
	{
		public InjectApiResult(string error)
		{
			this.error = error;
		}

		public static implicit operator bool(InjectApiResult what)
		{
			return !object.ReferenceEquals(what, null) && (what.error != null);
		}

		public string error;
	}

	public class InjectionHandler
	{
		public void Initialize(ProcessTracker processTracker, StatesPopup statesPopup, CommonServer pipeReader, TargetSettings targetSettings)
		{
			this.processTracker = processTracker;
			this.statesPopup = statesPopup;
			this.pipeReader = pipeReader;
			this.targetSettings = targetSettings;
		}

		public InjectApiResult RunScript(string data)
		{
			var targetState = targetSettings.GetLuaState();
			var targetProcess = targetSettings.GetProcess();

			if (targetProcess == null)
				return new InjectApiResult("process is not selected");

			if (targetProcess.state != TrackedProcess.State.Connected)
				return new InjectApiResult($"not connected to the process, current state: {targetProcess.state}");

			if (targetState == null)
				return new InjectApiResult("state is not selected");

			var writer = connectedProcesses[targetProcess].toClientPipe.CreateWriteBuffer(PipeOp.RunScript);
			writer.WriteU64(targetState.address);
			writer.WriteU64((ulong)data.Length);
			writer.WriteString(data);
			writer.Send();

			return null;
		}

		public InjectApiResult TryInject()
		{
			var candidates = processTracker.GetInjectableProcesses();
			if (!candidates.Any())
				return new InjectApiResult("process not found");

			var targetProcess = candidates.FirstOrDefault();
			var pathsBytes = new List<byte>();

			// keep in sync with Inject()
			pathsBytes.AddRange(SerializeWstring(PathConfig.Dll));
			pathsBytes.AddRange(SerializeWstring(PathConfig.Settings));
			pathsBytes.AddRange(SerializeWstring(PathConfig.Dump));
			pathsBytes.AddRange(SerializeWstring(PathConfig.AddressDumper));
			pathsBytes.AddRange(SerializeWstring(PathConfig.UserDirectory));
			pathsBytes.AddRange(SerializeWstring(PathConfig.DllLog));

			var size = (ulong)pathsBytes.Count;
			var arr = pathsBytes.ToArray();
			IntPtr result = Inject(targetProcess.Id, size, arr);

			if (result != IntPtr.Zero)
				return new InjectApiResult(Marshal.PtrToStringAnsi(result));

			onProcessInjected(targetProcess);

			return null;
		}

		public void onProcessDied(TrackedProcess process)
		{
			injectedProcesses.Remove(process);
			connectingProcesses.Remove(process);
			connectedProcesses.Remove(process);
		}

		public void onProcessInjected(TrackedProcess process)
		{
			Console.WriteLine($"injected in {process.Id}");
			var info = new ConnectedProcessInfo(process, this);
			connectingProcesses.Add(process, info);
			injectedProcesses.Add(process);
			process.MarkAsConnecting();
			info.InitializePipes();
		}

		public void onProcessConnected(TrackedProcess process)
		{
			if (!connectingProcesses.ContainsKey(process))
				throw new KeyNotFoundException($"process {process.Id} was not set as connecting one");
			
			var info = connectingProcesses[process];
			process.MarkAsConnected();
			connectedProcesses[process] = info;
		}

		public void OnAvailableStatesReportReceived(TrackedProcess process, PipeReadBuffer buffer)
		{
			var newDataModels = new List<DataModel>();

			// keep in sync with ::reportAvailableLuaStates()
			var dataModelCount = buffer.ReadU32();

			for (int i = 0; i < dataModelCount; i++)
			{
				var dataModel = new DataModel();
				dataModel.address = buffer.ReadU64();
				dataModel.type = (DataModelType)buffer.ReadU8();

				var luaStateCount = buffer.ReadU32();

				for (int j = 0; j < luaStateCount; j++)
				{
					var L = new LuaState();
					L.address = buffer.ReadU64();
					L.vmType = (VmType)buffer.ReadI32();
					dataModel.states.Add(L);
				}

				newDataModels.Add(dataModel);
			}

			SetNewDataModels(process, newDataModels);
		}

		private void SetNewDataModels(TrackedProcess process, List<DataModel> newModels)
		{
			var dataModels = connectedProcesses[process].dataModels;
			var existingDataModels = new List<DataModel>(dataModels);
			foreach (var existingModel in existingDataModels)
			{
				var newModel = newModels.Find(dm => dm.address == existingModel.address);
				if (newModel == null)
				{
					RemoveDataModelFromConnectedProcess(process, existingModel);
				}
				else
				{
					foreach (var existingState in existingModel.states)
					{
						if (!newModel.states.Exists(ls => ls.address == existingState.address))
						{
							OnLuaStateRemoved(existingState);
							existingModel.states.Remove(existingState);
						}
					}
				}
			}

			foreach (var newModel in newModels)
			{
				var existingModel = dataModels.Find(dm => dm.address == newModel.address);
				if (existingModel == null)
				{
					dataModels.Add(newModel);
				}
				else
				{
					foreach (var luaState in newModel.states)
					{
						var existingState = existingModel.states.Find(ls => ls.address == luaState.address);
						if (existingState == null)
							dataModels.Add(newModel);
						else
							existingState.Update(luaState);
					}
				}
			}

			OnAvailableLuaStatesUpdated(process);
		}

		private void RemoveDataModelFromConnectedProcess(TrackedProcess process, DataModel dataModel)
		{
			var dataModels = connectedProcesses[process].dataModels;
			foreach (var luaState in dataModel.states)
				OnLuaStateRemoved(luaState);
			OnDataModelRemoved(dataModel);
			dataModels.Remove(dataModel);
		}

		public void OnDataModelRemoved(DataModel dataModel)
		{

		}

		public void OnLuaStateRemoved(LuaState luaState)
		{

		}

		private bool ProcessHasState(TrackedProcess process, LuaState toFind)
		{
			foreach (var dataModel in connectedProcesses[process].dataModels)
				foreach (var state in dataModel.states)
					if (state == toFind)
						return true;

			return false;
		}

		public void OnAvailableLuaStatesUpdated(TrackedProcess forProcess)
		{
			if (targetSettings.GetProcess() != forProcess)
				return;

			statesPopup.OnAvailableLuaStatesUpdated();
			if (!ProcessHasState(forProcess, targetSettings.GetLuaState()))
				targetSettings.SetLuaState(null);
		}

		static private byte[] SerializeWstring(string path)
		{
			var absolutePath = Path.GetFullPath(path);
			var pathBytes = Encoding.Unicode.GetBytes(absolutePath);
			var lengthBytes = BitConverter.GetBytes((ulong)pathBytes.Length / 2);
			return lengthBytes.Concat(pathBytes).ToArray();
		}

		public enum InjectState
		{
			None,
			Injected,
		}

		public InjectState GetInjectionState()
		{
			if (connectedProcesses.Count > 0)
				return InjectState.Injected;

			return InjectState.None;
		}

		public IEnumerable<DataModel> GetDataModels()
		{
			var process = targetSettings.GetProcess();
			if (process == null || !connectedProcesses.TryGetValue(process, out var processInfo))
				return Enumerable.Empty<DataModel>();
			return processInfo.dataModels;
		}

		private readonly Dictionary<TrackedProcess, ConnectedProcessInfo> connectingProcesses = new Dictionary<TrackedProcess, ConnectedProcessInfo>();
		private readonly Dictionary<TrackedProcess, ConnectedProcessInfo> connectedProcesses = new Dictionary<TrackedProcess, ConnectedProcessInfo>();
		private StatesPopup statesPopup = null;
		private CommonServer pipeReader = null;
		private ProcessTracker processTracker = null;
		private readonly List<TrackedProcess> injectedProcesses = new List<TrackedProcess>();
		private TargetSettings targetSettings = null;

		[DllImport("Injector.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		private static extern IntPtr Inject(uint processId, ulong size, byte[] paths);

		[DllImport("Injector.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern void SendScript(ulong size, [MarshalAs(UnmanagedType.LPStr)] string data);
	}
}
