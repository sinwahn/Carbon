using System;
using System.IO.Pipes;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows;
using System.Runtime.InteropServices;

namespace CarbonGui
{
	public class PipeReadBuffer
	{
		public PipeReadBuffer(MemoryStream data)
		{
			data.Seek(0, SeekOrigin.Begin);
			reader = new BinaryReader(data);
		}

		public sbyte ReadI8() { return reader.ReadSByte(); }
		public byte ReadU8() { return reader.ReadByte(); }
		public int ReadI32() { return reader.ReadInt32(); }
		public uint ReadU32() { return reader.ReadUInt32(); }
		public long ReadI64() { return reader.ReadInt64(); }
		public ulong ReadU64() { return reader.ReadUInt64(); }

		public byte[] ReadArray(int size) { return reader.ReadBytes(size); }

		public string ReadString(int size)
		{
			return Encoding.ASCII.GetString(ReadArray(size));
		}

		private BinaryReader reader;
	}

	public class PipeWriteBuffer
	{
		public PipeWriteBuffer(ServerPipeBase pipe, NamedPipeServerStream stream)
		{
			this.pipe = pipe;
			this.pipeStream = stream;
			memoryStream = new MemoryStream();
			writer = new BinaryWriter(memoryStream);
		}

		public void WriteI8(sbyte value) { writer.Write(value); }
		public void WriteU8(byte value) { writer.Write(value); }
		public void WriteI32(int value) { writer.Write(value); }
		public void WriteU32(uint value) { writer.Write(value); }
		public void WriteI64(long value) { writer.Write(value); }
		public void WriteU64(ulong value) { writer.Write(value); }

		public void WriteArray(byte[] array) { writer.Write(array); }

		public void WriteString(string value)
		{
			writer.Write(Encoding.ASCII.GetBytes(value));
		}

		// keep in sync with Pipes.ixx
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		private struct Header
		{
			public byte hasContinuation;
			public ushort dataSize;
		}

		public void Send()
		{
			memoryStream.Position = 0;

			long totalDataWritten = 0;
			long dataTotalSize = memoryStream.Length;

			const int writeBufferSize = 1024;
			byte[] buffer = new byte[writeBufferSize];
			int chunkDataMaxSize = writeBufferSize - Marshal.SizeOf(typeof(Header));

			while (totalDataWritten < dataTotalSize)
			{
				int dataSize = (int)Math.Min(chunkDataMaxSize, dataTotalSize - totalDataWritten);

				Header header;
				header.hasContinuation = (byte)((totalDataWritten + dataSize < dataTotalSize) ? 1 : 0);
				header.dataSize = (ushort)dataSize;

				using (var tempStream = new MemoryStream(buffer))
				{
					var tempWriter = new BinaryWriter(tempStream);
					tempWriter.Write(header.hasContinuation);
					tempWriter.Write(header.dataSize);

					memoryStream.Read(buffer, Marshal.SizeOf(typeof(Header)), dataSize);

					tempWriter.Close();
				}

				pipeStream.Write(buffer, 0, dataSize + Marshal.SizeOf(typeof(Header)));
				pipeStream.Flush();

				totalDataWritten += dataSize;
			}

			memoryStream.SetLength(0);

			Logger.Log(Logger.Category.Pipes, $"Sending {pipe.name}");
			memoryStream.Position = 0;
			memoryStream.CopyTo(pipeStream);
			memoryStream.SetLength(0);
			pipeStream.Flush();
		}

		private MemoryStream memoryStream = null;
		private BinaryWriter writer = null;
		private ServerPipeBase pipe = null;
		private NamedPipeServerStream pipeStream = null;
	}

	// keep in sync with Pipes.ixx
	public enum PipeOp
	{
		// common
		Nop,
		ProcessConnected,

		// private
		RunScript,
		ReportAvailableEnvironments,
	};

	static public class PipeNames
	{
		public const string commonPipeName = "carbon_delivery";
		public const string privatePipeNamePrefix = "carbon_gluon";
	}

	public abstract class ServerPipeBase
	{
		public ServerPipeBase(string pipeName)
		{
			name = pipeName;
			fullName = "\\\\.\\pipe\\" + pipeName;
			pipeStream = new NamedPipeServerStream(name, PipeDirection.InOut);
			pipeReader = new BinaryReader(pipeStream);
		}

		public void StartReading()
		{
			Logger.Log(Logger.Category.Pipes, $"StartReading {name}");
			readThread = new Thread(new ThreadStart(ReadLoop));
			readThread.IsBackground = true;
			readThread.Start();
		}

		public void StopReading()
		{
			Logger.Log(Logger.Category.Pipes, $"StopReading {name}");
			// TODO: :adam:
			readThread.Abort();
		}

		public PipeReadBuffer ReadDataAsync()
		{
			var memoryStream = new MemoryStream();
			while (true)
			{
				byte hasContinuation = pipeReader.ReadByte();
				uint dataSize = pipeReader.ReadUInt16();
				byte[] buffer = pipeReader.ReadBytes((int)dataSize);

				memoryStream.Write(buffer, 0, buffer.Length);

				if (hasContinuation == 0)
					break;
			}

			return new PipeReadBuffer(memoryStream);
		}
		
		public void TryConnect()
		{
			if (!pipeStream.IsConnected)
			{
				Logger.Log(Logger.Category.Pipes, $"{name} waiting for client");
				pipeStream.WaitForConnection();
				Logger.Log(Logger.Category.Pipes, $"{name} client connected");
			}
		}

		// keep in sync with Pipes.ixx
		const int readBufferSize = 1 * 1024;

		public PipeWriteBuffer CreateWriteBuffer(PipeOp op)
		{
			Logger.Log(Logger.Category.Pipes, $"{name} creating write buffer {op}");
			var buffer = new PipeWriteBuffer(this, pipeStream);
			buffer.WriteU8((byte)op);
			return buffer;
		}

		private void ReadLoop()
		{
			Logger.Log(Logger.Category.Pipes, $"{name} starting read loop");
			while (true)
			{
				try
				{
					TryConnect();

					var buffer = ReadDataAsync();
					var op = (PipeOp)buffer.ReadU8();
					ReadPacket(op, buffer);
				}
				catch (Exception e)
				{
					Logger.Log(Logger.Category.Pipes, $"{e.Message}\n{e.StackTrace}");

					var result = MessageBox.Show($"Pipe read exception: {e.Message}\n{e.StackTrace}\nignore error? 'no' - terminate program; 'cancel' - break pipe parsing", ":woah:",
						MessageBoxButton.YesNoCancel, MessageBoxImage.Asterisk, MessageBoxResult.Yes);

					if (result == MessageBoxResult.Yes)
					{
						// ignore
					}
					else if (result == MessageBoxResult.No)
					{
						Environment.Exit(1);
					}
					if (result == MessageBoxResult.Cancel)
					{
						break;
					}
				}
			}
		}

		protected abstract void ReadPacket(PipeOp op, PipeReadBuffer buffer);

		private NamedPipeServerStream pipeStream = null;
		private BinaryReader pipeReader = null;
		private Thread readThread = null;
		public readonly string name;
		public readonly string fullName;
	}

	public class CommonServer : ServerPipeBase
	{
		public CommonServer(string pipeName)
			: base(pipeName)
		{

		}

		public void Initialize(InjectionHandler injectionHandler, ProcessTracker processTracker)
		{
			this.processTracker = processTracker;
			this.injectionHandler = injectionHandler;
		}

		protected override void ReadPacket(PipeOp op, PipeReadBuffer buffer)
		{
			switch (op)
			{
				case PipeOp.ProcessConnected:
					var processId = buffer.ReadU32();
					var process = processTracker.GetProcessById(processId);
					injectionHandler.onProcessConnected(process);
					break;
				default:
					Logger.Log(Logger.Category.Pipes, $"Cannot handle op {op}");
					break;
			}
		}

		private InjectionHandler injectionHandler = null;
		private ProcessTracker processTracker = null;
	}

	// TODO add connection await limit
	public class PrivateServer : ServerPipeBase
	{
		public enum Direction
		{
			ToClient,
			ToServer,
		}

		public PrivateServer(TrackedProcess process, InjectionHandler injectionHandler, Direction direction)
			: base(PipeNames.privatePipeNamePrefix + process.Id + (direction == Direction.ToServer ? "ToServer" : "ToClient"))
		{
			this.process = process;
			this.injectionHandler = injectionHandler;
		}

		protected override void ReadPacket(PipeOp op, PipeReadBuffer buffer)
		{
			switch (op)
			{
				case PipeOp.ReportAvailableEnvironments:
					injectionHandler.OnAvailableStatesReportReceived(process, buffer);
					break;
				default:
					Logger.Log(Logger.Category.Pipes, $"Cannot handle op {op}");
					break;
			}
		}

		private readonly TrackedProcess process = null;
		private readonly InjectionHandler injectionHandler = null;
	}
}
