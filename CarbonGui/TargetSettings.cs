namespace CarbonGui
{
	public class TargetSettings
	{
		public TargetSettings()
		{
		}

		public void Initialize(MainWindow mainWindow)
		{
			this.mainWindow = mainWindow;
			mainWindow.OnTargetLuaStateChanged(null);
			mainWindow.OnTargetProcessChanged(null);
		}

		public LuaState GetLuaState() { return luaState; }
		public TrackedProcess GetProcess() { return process; }

		public void SetLuaState(LuaState newLuaState)
		{
			if (luaState == newLuaState)
				return;
			luaState = newLuaState;
			mainWindow.OnTargetLuaStateChanged(newLuaState);
		}

		public void SetProcess(TrackedProcess newProcess)
		{
			if (process == newProcess)
				return;
			process = newProcess;
			mainWindow.OnTargetProcessChanged(newProcess);
		}

		private LuaState luaState;
		private TrackedProcess process;

		private MainWindow mainWindow;
	}
}
