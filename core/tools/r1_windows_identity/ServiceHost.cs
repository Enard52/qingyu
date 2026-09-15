// Test-only SCM host. Build with .NET Framework System.ServiceProcess.dll.
// Installation, protected ACLs, service virtual accounts and RequiredPrivileges
// are deployment responsibilities. This host neither installs nor elevates.
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Threading;

internal sealed class AcceptanceService : ServiceBase
{
    private const string Deployment = @"C:\Program Files\Qingyu\ControlPlane\R1\Acceptance";
    private const string RuntimeService = "QingyuControlPlaneR1Acceptance";
    private const string MigratorService = "QingyuControlPlaneR1AcceptanceMigrator";
    private const int ProbeTimeoutMilliseconds = 120000;
    private const int CaptureLimitCharacters = 4194304;
    private readonly object processGate = new object();
    private readonly string evidenceDirectory;
    private Process child;
    private Thread worker;
    private volatile bool stopping;

    private AcceptanceService(string serviceName)
    {
        ServiceName = serviceName;
        CanStop = true;
        AutoLog = false;
        evidenceDirectory = @"C:\ProgramData\QingyuR1IdentityEvidence\" + serviceName;
    }

    public static int Main(string[] args)
    {
        // Only the two predeclared service identities can select a probe role.
        if (args.Length != 1 || (args[0] != "runtime" && args[0] != "migrator"))
            return 2;
        ServiceBase.Run(new AcceptanceService(args[0] == "runtime" ? RuntimeService : MigratorService));
        return 0;
    }

    protected override void OnStart(string[] args)
    {
        if (args.Length != 0)
            throw new InvalidOperationException("Service start arguments are not supported.");
        worker = new Thread(RunProbe);
        worker.IsBackground = true;
        worker.Start();
    }

    protected override void OnStop()
    {
        stopping = true;
        KillChild();
        if (worker != null && worker != Thread.CurrentThread)
            worker.Join(10000);
    }

    private void KillChild()
    {
        lock (processGate)
        {
            try { if (child != null && !child.HasExited) child.Kill(); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }
    }

    private sealed class Capture
    {
        internal readonly StringBuilder Text = new StringBuilder();
        internal bool Overflow;
        internal bool Failed;

        internal void Read(StreamReader reader)
        {
            try
            {
                char[] buffer = new char[4096];
                int count;
                while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                {
                    int remaining = CaptureLimitCharacters - Text.Length;
                    if (count > remaining) Overflow = true;
                    if (remaining > 0) Text.Append(buffer, 0, Math.Min(count, remaining));
                }
            }
            catch (IOException) { Failed = true; }
            catch (ObjectDisposedException) { Failed = true; }
        }
    }

    private void RunProbe()
    {
        string outcome = "host_error";
        int probeExit = -1;
        try
        {
            // Directories must already exist with the deployment's protected ACLs.
            if (!Directory.Exists(evidenceDirectory))
                throw new InvalidOperationException("Evidence directory is missing.");
            // Remove previous stdout before attempting this run, so an early failure
            // cannot be mistaken for a successful result from this invocation.
            File.WriteAllText(Path.Combine(evidenceDirectory, "result.json"), "", new UTF8Encoding(false));
            WriteStatus("running", -1);
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = Deployment + @"\runtime\python.exe";
            start.Arguments = "-I \"" + Deployment + @"\probe.py" + "\" " + ServiceName;
            start.WorkingDirectory = Deployment;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.StandardOutputEncoding = Encoding.UTF8;
            start.StandardErrorEncoding = Encoding.UTF8;
            start.EnvironmentVariables.Clear();
            start.EnvironmentVariables["SystemRoot"] = @"C:\Windows";
            start.EnvironmentVariables["WINDIR"] = @"C:\Windows";

            lock (processGate)
            {
                if (stopping) { outcome = "stopped"; return; }
                child = new Process();
                child.StartInfo = start;
                if (!child.Start()) throw new InvalidOperationException("Probe did not start.");
                child.StandardInput.Close();
            }

            Capture stdout = new Capture();
            Capture stderr = new Capture();
            Thread outputReader = new Thread(delegate() { stdout.Read(child.StandardOutput); });
            Thread errorReader = new Thread(delegate() { stderr.Read(child.StandardError); });
            outputReader.IsBackground = true;
            errorReader.IsBackground = true;
            outputReader.Start();
            errorReader.Start();
            bool exited = child.WaitForExit(ProbeTimeoutMilliseconds);
            if (!exited) KillChild();
            bool terminated = exited || child.WaitForExit(5000);
            bool outputDone = outputReader.Join(5000);
            bool errorDone = errorReader.Join(5000);
            if (terminated) probeExit = child.ExitCode;

            if (stopping) outcome = "stopped";
            else if (!exited) outcome = "timeout";
            else if (!outputDone || !errorDone || stdout.Failed || stderr.Failed) outcome = "capture_error";
            else if (stdout.Overflow || stderr.Overflow) outcome = "capture_limit";
            else
            {
                // The fixed probe owns the JSON schema and emits no secrets.
                // Deliberately do not persist arbitrary stderr or exception details.
                File.WriteAllText(Path.Combine(evidenceDirectory, "result.json"), stdout.Text.ToString(), new UTF8Encoding(false));
                outcome = probeExit == 0 ? "completed" : "probe_failed";
            }
        }
        catch (Exception)
        {
            outcome = "host_error";
        }
        finally
        {
            KillChild();
            try { WriteStatus(outcome, probeExit); }
            catch (Exception) { ExitCode = 1; }
            if (outcome != "completed") ExitCode = 1;
            // Stop without joining the current worker from OnStop.
            Stop();
        }
    }

    private void WriteStatus(string outcome, int probeExit)
    {
        string json = "{\"service\":\"" + ServiceName + "\",\"outcome\":\"" + outcome
            + "\",\"probe_exit_code\":" + probeExit.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + ",\"utc\":\"" + DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture) + "\"}";
        File.WriteAllText(Path.Combine(evidenceDirectory, "host-status.json"), json, new UTF8Encoding(false));
    }
}
