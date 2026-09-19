using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TraceXLauncher
{
    public class MainForm : Form
    {
        private Button btnStart;
        private Button btnStop;
        private Button btnInstall;
        private Button btnOpenBrowser;
        private Button btnOpenDocs;
        private Button btnRunTests;
        private TextBox txtLog;
        private Label lblStatusBackend;
        private Label lblStatusFrontend;
        private Label lblTitle;
        private Label lblSubTitle;

        private Process backendProcess = null;
        private Process frontendProcess = null;
        private System.Windows.Forms.Timer statusTimer;

        private string projectRoot;
        private string pythonExe;
        private string venvPythonExe;
        private string npmExe = "npm.cmd";

        public MainForm()
        {
            projectRoot = AppDomain.CurrentDomain.BaseDirectory;
            venvPythonExe = Path.Combine(projectRoot, "backend", "venv", "Scripts", "python.exe");

            DetectPython();
            InitializeComponent();

            statusTimer = new System.Windows.Forms.Timer();
            statusTimer.Interval = 2500;
            statusTimer.Tick += StatusTimer_Tick;
            statusTimer.Start();

            this.FormClosing += MainForm_FormClosing;
        }

        private void DetectPython()
        {
            if (File.Exists(venvPythonExe))
            {
                pythonExe = venvPythonExe;
                return;
            }

            string userLocalPy = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs", "Python", "Python311", "python.exe"
            );

            if (File.Exists(userLocalPy))
            {
                pythonExe = userLocalPy;
                return;
            }

            pythonExe = "python.exe";
        }

        private void InitializeComponent()
        {
            this.Text = "TRACE-X Pro - Launcher & Manager";
            this.Size = new Size(820, 620);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(15, 23, 42); // Dark slate theme
            this.ForeColor = Color.FromArgb(241, 245, 249);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // Header Title
            lblTitle = new Label();
            lblTitle.Text = "TRACE-X PRO";
            lblTitle.Font = new Font("Segoe UI", 18f, FontStyle.Bold);
            lblTitle.ForeColor = Color.FromArgb(56, 189, 248); // Cyan
            lblTitle.Location = new Point(24, 20);
            lblTitle.AutoSize = true;
            this.Controls.Add(lblTitle);

            lblSubTitle = new Label();
            lblSubTitle.Text = "AI-Powered Email Threat Detection & Google Workspace Ingestion Platform";
            lblSubTitle.Font = new Font("Segoe UI", 10f, FontStyle.Regular);
            lblSubTitle.ForeColor = Color.FromArgb(148, 163, 184);
            lblSubTitle.Location = new Point(26, 56);
            lblSubTitle.AutoSize = true;
            this.Controls.Add(lblSubTitle);

            // Status Panel
            Panel pnlStatus = new Panel();
            pnlStatus.BackColor = Color.FromArgb(30, 41, 59);
            pnlStatus.Location = new Point(24, 90);
            pnlStatus.Size = new Size(756, 44);
            this.Controls.Add(pnlStatus);

            lblStatusBackend = new Label();
            lblStatusBackend.Text = "Backend API: Stopped";
            lblStatusBackend.Location = new Point(16, 12);
            lblStatusBackend.AutoSize = true;
            lblStatusBackend.ForeColor = Color.FromArgb(248, 113, 113); // Red
            pnlStatus.Controls.Add(lblStatusBackend);

            lblStatusFrontend = new Label();
            lblStatusFrontend.Text = "Frontend UI: Stopped";
            lblStatusFrontend.Location = new Point(260, 12);
            lblStatusFrontend.AutoSize = true;
            lblStatusFrontend.ForeColor = Color.FromArgb(248, 113, 113);
            pnlStatus.Controls.Add(lblStatusFrontend);

            // Action Buttons
            btnStart = CreateStyledButton("Start TRACE-X", new Point(24, 150), Color.FromArgb(16, 185, 129)); // Green
            btnStart.Click += BtnStart_Click;
            this.Controls.Add(btnStart);

            btnStop = CreateStyledButton("Stop Services", new Point(154, 150), Color.FromArgb(239, 68, 68)); // Red
            btnStop.Click += BtnStop_Click;
            this.Controls.Add(btnStop);

            btnInstall = CreateStyledButton("Install / Repair", new Point(284, 150), Color.FromArgb(99, 102, 241)); // Indigo
            btnInstall.Click += BtnInstall_Click;
            this.Controls.Add(btnInstall);

            btnOpenBrowser = CreateStyledButton("Open Web UI", new Point(414, 150), Color.FromArgb(14, 165, 233)); // Sky
            btnOpenBrowser.Click += (s, e) => Process.Start("http://localhost:5173");
            this.Controls.Add(btnOpenBrowser);

            btnOpenDocs = CreateStyledButton("API Swagger", new Point(544, 150), Color.FromArgb(59, 130, 246));
            btnOpenDocs.Click += (s, e) => Process.Start("http://localhost:8000/docs");
            this.Controls.Add(btnOpenDocs);

            btnRunTests = CreateStyledButton("Run Tests", new Point(674, 150), Color.FromArgb(168, 85, 247)); // Purple
            btnRunTests.Click += BtnRunTests_Click;
            this.Controls.Add(btnRunTests);

            // Output Console Log
            txtLog = new TextBox();
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.BackColor = Color.FromArgb(10, 15, 26);
            txtLog.ForeColor = Color.FromArgb(226, 232, 240);
            txtLog.Font = new Font("Consolas", 9f);
            txtLog.Location = new Point(24, 206);
            txtLog.Size = new Size(756, 350);
            this.Controls.Add(txtLog);

            Log("TRACE-X Pro Launcher initialized.");
            Log("Project Directory: " + projectRoot);
            Log("Python Path: " + pythonExe);
            Log("Click 'Start TRACE-X' to run both Backend & Frontend.");
        }

        private Button CreateStyledButton(string text, Point location, Color color)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Location = location;
            btn.Size = new Size(120, 38);
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderSize = 0;
            btn.BackColor = color;
            btn.ForeColor = Color.White;
            btn.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btn.Cursor = Cursors.Hand;
            return btn;
        }

        private void Log(string message)
        {
            if (txtLog.InvokeRequired)
            {
                txtLog.Invoke(new Action<string>(Log), message);
                return;
            }
            string time = DateTime.Now.ToString("HH:mm:ss");
            txtLog.AppendText("[" + time + "] " + message + Environment.NewLine);
        }

        private async void BtnStart_Click(object sender, EventArgs e)
        {
            Log("Starting TRACE-X Pro services...");

            // 1. Ensure backend virtualenv exists
            if (!File.Exists(venvPythonExe))
            {
                Log("Virtual environment not found. Running auto-install first...");
                await RunInstallRoutine();
            }

            // 2. Start Backend API
            StartBackend();

            // 3. Start Frontend UI
            StartFrontend();

            // 4. Wait 3 seconds and open browser
            await Task.Delay(3500);
            try
            {
                Process.Start("http://localhost:5173");
                Log("Browser opened to http://localhost:5173");
            }
            catch { }
        }

        private void StartBackend()
        {
            if (backendProcess != null && !backendProcess.HasExited)
            {
                Log("Backend is already running.");
                return;
            }

            try
            {
                string backendDir = Path.Combine(projectRoot, "backend");
                string py = File.Exists(venvPythonExe) ? venvPythonExe : pythonExe;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = py;
                psi.Arguments = "-m uvicorn app.main:app --host 127.0.0.1 --port 8000";
                psi.WorkingDirectory = backendDir;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                backendProcess = new Process();
                backendProcess.StartInfo = psi;
                backendProcess.OutputDataReceived += (s, e) => { if (e.Data != null) Log("[API] " + e.Data); };
                backendProcess.ErrorDataReceived += (s, e) => { if (e.Data != null) Log("[API] " + e.Data); };

                backendProcess.Start();
                backendProcess.BeginOutputReadLine();
                backendProcess.BeginErrorReadLine();

                Log("FastAPI Backend started on http://127.0.0.1:8000 (PID: " + backendProcess.Id + ")");
            }
            catch (Exception ex)
            {
                Log("ERROR starting backend: " + ex.Message);
            }
        }

        private void StartFrontend()
        {
            if (frontendProcess != null && !frontendProcess.HasExited)
            {
                Log("Frontend is already running.");
                return;
            }

            try
            {
                string frontendDir = Path.Combine(projectRoot, "frontend");

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c npm run dev";
                psi.WorkingDirectory = frontendDir;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                frontendProcess = new Process();
                frontendProcess.StartInfo = psi;
                frontendProcess.OutputDataReceived += (s, e) => { if (e.Data != null) Log("[UI] " + e.Data); };
                frontendProcess.ErrorDataReceived += (s, e) => { if (e.Data != null) Log("[UI] " + e.Data); };

                frontendProcess.Start();
                frontendProcess.BeginOutputReadLine();
                frontendProcess.BeginErrorReadLine();

                Log("Vite Frontend started on http://localhost:5173 (PID: " + frontendProcess.Id + ")");
            }
            catch (Exception ex)
            {
                Log("ERROR starting frontend: " + ex.Message);
            }
        }

        private void BtnStop_Click(object sender, EventArgs e)
        {
            StopServices();
        }

        private void StopServices()
        {
            Log("Stopping services...");

            if (backendProcess != null && !backendProcess.HasExited)
            {
                try
                {
                    backendProcess.Kill();
                    Log("Backend process stopped.");
                }
                catch { }
                backendProcess = null;
            }

            if (frontendProcess != null && !frontendProcess.HasExited)
            {
                try
                {
                    // Kill process tree
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "taskkill.exe",
                        Arguments = "/PID " + frontendProcess.Id + " /T /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    Log("Frontend process stopped.");
                }
                catch { }
                frontendProcess = null;
            }

            lblStatusBackend.Text = "Backend API: Stopped";
            lblStatusBackend.ForeColor = Color.FromArgb(248, 113, 113);
            lblStatusFrontend.Text = "Frontend UI: Stopped";
            lblStatusFrontend.ForeColor = Color.FromArgb(248, 113, 113);
        }

        private async void BtnInstall_Click(object sender, EventArgs e)
        {
            await RunInstallRoutine();
        }

        private async Task RunInstallRoutine()
        {
            Log("==== Starting Automated Installation & Environment Setup ====");

            await Task.Run(() =>
            {
                try
                {
                    string backendDir = Path.Combine(projectRoot, "backend");
                    string venvDir = Path.Combine(backendDir, "venv");
                    string reqFile = Path.Combine(backendDir, "requirements.txt");

                    // 1. Create virtualenv
                    if (!File.Exists(venvPythonExe))
                    {
                        Log("Creating Python virtual environment in backend\\venv...");
                        Process p = Process.Start(new ProcessStartInfo
                        {
                            FileName = pythonExe,
                            Arguments = "-m venv \"" + venvDir + "\"",
                            WorkingDirectory = backendDir,
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                        p.WaitForExit();
                        Log("Virtual environment created successfully.");
                    }

                    // 2. Install requirements
                    Log("Installing backend dependencies from requirements.txt...");
                    Process pip = Process.Start(new ProcessStartInfo
                    {
                        FileName = Path.Combine(venvDir, "Scripts", "pip.exe"),
                        Arguments = "install -r \"" + reqFile + "\"",
                        WorkingDirectory = backendDir,
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    pip.WaitForExit();
                    Log("Backend requirements installation completed.");

                    // 3. Setup .env file
                    string envFile = Path.Combine(backendDir, ".env");
                    string envExample = Path.Combine(backendDir, ".env.example");
                    if (!File.Exists(envFile) && File.Exists(envExample))
                    {
                        File.Copy(envExample, envFile);
                        Log("Created backend\\.env configuration from template.");
                    }

                    Log("==== Installation Complete! Ready to Launch. ====");
                }
                catch (Exception ex)
                {
                    Log("Installation error: " + ex.Message);
                }
            });
        }

        private async void BtnRunTests_Click(object sender, EventArgs e)
        {
            Log("Running pytest test suite across TRACE-X Pro...");

            await Task.Run(() =>
            {
                try
                {
                    string backendDir = Path.Combine(projectRoot, "backend");
                    string py = File.Exists(venvPythonExe) ? venvPythonExe : pythonExe;

                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = py;
                    psi.Arguments = "-m pytest tests -v";
                    psi.WorkingDirectory = backendDir;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;
                    psi.CreateNoWindow = true;

                    Process p = new Process();
                    p.StartInfo = psi;
                    p.OutputDataReceived += (s, args) => { if (args.Data != null) Log(args.Data); };
                    p.ErrorDataReceived += (s, args) => { if (args.Data != null) Log(args.Data); };

                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    p.WaitForExit();

                    Log("Test suite completed with exit code: " + p.ExitCode);
                }
                catch (Exception ex)
                {
                    Log("Error running tests: " + ex.Message);
                }
            });
        }

        private async void StatusTimer_Tick(object sender, EventArgs e)
        {
            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromMilliseconds(1200);

                // Check Backend
                try
                {
                    HttpResponseMessage resp = await client.GetAsync("http://127.0.0.1:8000/health");
                    if (resp.IsSuccessStatusCode)
                    {
                        lblStatusBackend.Text = "Backend API: ONLINE (Port 8000)";
                        lblStatusBackend.ForeColor = Color.FromArgb(52, 211, 153); // Green
                    }
                    else
                    {
                        lblStatusBackend.Text = "Backend API: Degraded";
                        lblStatusBackend.ForeColor = Color.FromArgb(251, 191, 36); // Yellow
                    }
                }
                catch
                {
                    lblStatusBackend.Text = "Backend API: Stopped";
                    lblStatusBackend.ForeColor = Color.FromArgb(248, 113, 113);
                }

                // Check Frontend
                try
                {
                    HttpResponseMessage resp = await client.GetAsync("http://localhost:5173");
                    if (resp.IsSuccessStatusCode)
                    {
                        lblStatusFrontend.Text = "Frontend UI: ONLINE (Port 5173)";
                        lblStatusFrontend.ForeColor = Color.FromArgb(52, 211, 153);
                    }
                    else
                    {
                        lblStatusFrontend.Text = "Frontend UI: Degraded";
                        lblStatusFrontend.ForeColor = Color.FromArgb(251, 191, 36);
                    }
                }
                catch
                {
                    lblStatusFrontend.Text = "Frontend UI: Stopped";
                    lblStatusFrontend.ForeColor = Color.FromArgb(248, 113, 113);
                }
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopServices();
        }

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
