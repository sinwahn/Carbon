using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CarbonGui.TrackedProcess;

namespace CarbonGui
{
	public static class Logger
	{
		public enum Category
		{
			Pipes,
			Process,
		}

		public static void Initialize()
		{
			string logDirectory = Path.GetDirectoryName(logFilePath);
			if (!Directory.Exists(logDirectory))
				Directory.CreateDirectory(logDirectory);

			if (File.Exists(logFilePath))
				File.Delete(logFilePath);
		}

		public static void Log(Category category, string message)
		{
			string logEntry = $"{DateTime.Now:HH:mm:ss.fff} [{Category.GetName(category.GetType(), category)}] {message}";
			Console.Write(logEntry);
			AppendLogToFile(logEntry);
		}

		private static void AppendLogToFile(string logEntry)
		{
			try
			{
				using (StreamWriter writer = new StreamWriter(logFilePath, true))
				{
					writer.WriteLine(logEntry);
				}
			}
			catch (Exception)
			{
				
			}
		}

		private static readonly string logFilePath = "logs/CarbonGui.log";
	}
}
