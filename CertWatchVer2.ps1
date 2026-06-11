#Requires -Version 5.1
<#
.SYNOPSIS
    CertWatch - SSL/TLS Certificate Scanner for Windows Networks
.DESCRIPTION
    Scans an IP range, checks which servers are alive, and retrieves
    certificates from LocalMachine\My (Personal) via PowerShell Remoting (WinRM)
.NOTES
    No installation required - runs on any Windows machine with PowerShell 5.1+
    Run as Administrator for best results
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ─── Colors ──────────────────────────────────────────────
$Dark       = [System.Drawing.Color]::FromArgb(13,  17,  23)
$Panel      = [System.Drawing.Color]::FromArgb(22,  27,  34)
$Card       = [System.Drawing.Color]::FromArgb(33,  38,  45)
$Blue       = [System.Drawing.Color]::FromArgb(56,  139, 253)
$Green      = [System.Drawing.Color]::FromArgb(63,  185, 80)
$Yellow     = [System.Drawing.Color]::FromArgb(210, 153, 34)
$Red        = [System.Drawing.Color]::FromArgb(248, 81,  73)
$TextLight  = [System.Drawing.Color]::FromArgb(230, 237, 243)
$TextMuted  = [System.Drawing.Color]::FromArgb(139, 148, 158)
$Border     = [System.Drawing.Color]::FromArgb(48,  54,  61)

# ─── Global Data ─────────────────────────────────────────
$Global:ScanResults  = [System.Collections.Generic.List[PSObject]]::new()
$Global:AllCertRows  = [System.Collections.Generic.List[PSObject]]::new()
$Global:IsRunning    = $false
$Global:ScanWorker   = $null

# ─── Helper Functions ─────────────────────────────────────

function Parse-IPRange {
    param([string]$RangeStr)
    $ips = [System.Collections.Generic.List[string]]::new()
    $RangeStr = $RangeStr.Trim()

    if ($RangeStr -match '^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$') {
        $prefix = $Matches[1]
        $start  = [int]$Matches[2]
        $end    = [int]$Matches[3]
        for ($i = $start; $i -le $end; $i++) { $ips.Add("$prefix$i") }
    }
    elseif ($RangeStr -match '/') {
        $parts   = $RangeStr -split '/'
        $baseIP  = $parts[0]
        $prefix  = [int]$parts[1]
        $mask    = [uint32]([uint32]::MaxValue -shl (32 - $prefix))
        $ipInt   = [uint32]([System.Net.IPAddress]::Parse($baseIP).Address)
        if ([System.BitConverter]::IsLittleEndian) {
            $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
        }
        $network = $ipInt -band $mask
        $count   = [uint32]([uint32]::MaxValue - $mask) - 1
        for ($i = 1; $i -le $count; $i++) {
            $hostInt   = $network + $i
            $hostBytes = [System.BitConverter]::GetBytes([uint32]$hostInt)
            [Array]::Reverse($hostBytes)
            $ips.Add(([System.Net.IPAddress]::new($hostBytes)).ToString())
        }
    }
    elseif ($RangeStr -match ',') {
        foreach ($ip in ($RangeStr -split ',')) { $ips.Add($ip.Trim()) }
    }
    else {
        $ips.Add($RangeStr)
    }
    return $ips
}

function Get-CertStatus {
    param([int]$DaysLeft, [int]$Critical, [int]$Warning, [int]$Notice)
    if     ($DaysLeft -lt 0)         { return @{ Label="Expired";    Tag="expired";  Color=$TextMuted } }
    elseif ($DaysLeft -le $Critical) { return @{ Label="Critical";   Tag="critical"; Color=$Red      } }
    elseif ($DaysLeft -le $Warning)  { return @{ Label="Warning";    Tag="warning";  Color=$Yellow   } }
    elseif ($DaysLeft -le $Notice)   { return @{ Label="Notice";     Tag="notice";   Color=$Blue     } }
    else                             { return @{ Label="OK";         Tag="ok";       Color=$Green    } }
}

# ─── Build UI ─────────────────────────────────────────────

$Form = New-Object System.Windows.Forms.Form
$Form.Text            = "CertWatch — Network Certificate Scanner"
$Form.Size            = New-Object System.Drawing.Size(1300, 820)
$Form.MinimumSize     = New-Object System.Drawing.Size(900, 600)
$Form.BackColor       = $Dark
$Form.ForeColor       = $TextLight
$Form.StartPosition   = "CenterScreen"
$Form.Font            = New-Object System.Drawing.Font("Segoe UI", 9)

# ── Header ──
$Header = New-Object System.Windows.Forms.Panel
$Header.Dock      = "Top"
$Header.Height    = 55
$Header.BackColor = $Panel
$Form.Controls.Add($Header)

$TitleLbl = New-Object System.Windows.Forms.Label
$TitleLbl.Text      = "🔐  CertWatch"
$TitleLbl.Font      = New-Object System.Drawing.Font("Consolas", 16, [System.Drawing.FontStyle]::Bold)
$TitleLbl.ForeColor = $Blue
$TitleLbl.AutoSize  = $true
$TitleLbl.Location  = New-Object System.Drawing.Point(20, 14)
$Header.Controls.Add($TitleLbl)

$SubLbl = New-Object System.Windows.Forms.Label
$SubLbl.Text      = "SSL/TLS Certificate Scanner for Windows Networks  |  PowerShell Edition"
$SubLbl.ForeColor = $TextMuted
$SubLbl.AutoSize  = $true
$SubLbl.Location  = New-Object System.Drawing.Point(230, 20)
$Header.Controls.Add($SubLbl)

$StatusLbl = New-Object System.Windows.Forms.Label
$StatusLbl.Text      = "Ready"
$StatusLbl.ForeColor = $Green
$StatusLbl.AutoSize  = $true
$StatusLbl.Location  = New-Object System.Drawing.Point(1150, 20)
$Header.Controls.Add($StatusLbl)

# ── Split Container ──
$Split = New-Object System.Windows.Forms.SplitContainer
$Split.Dock             = "Fill"
$Split.SplitterWidth    = 4
$Split.BackColor        = $Border
$Split.Panel1.BackColor = $Panel
$Split.Panel2.BackColor = $Dark
$Split.SplitterDistance = 270
$Form.Controls.Add($Split)

# ════════════════════════════════
# LEFT PANEL — Controls
# ════════════════════════════════
$lp = $Split.Panel1

function Add-SectionLabel($parent, $text, $y) {
    $sep = New-Object System.Windows.Forms.Panel
    $sep.Location  = New-Object System.Drawing.Point(10, $y)
    $sep.Size      = New-Object System.Drawing.Size(240, 1)
    $sep.BackColor = $Border
    $parent.Controls.Add($sep)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text      = $text
    $lbl.ForeColor = $TextMuted
    $lbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $lbl.AutoSize  = $true
    $lbl.Location  = New-Object System.Drawing.Point(10, ($y + 4))
    $parent.Controls.Add($lbl)
    return $y + 24
}

function Add-Label($parent, $text, $y) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text      = $text
    $lbl.ForeColor = $TextMuted
    $lbl.AutoSize  = $true
    $lbl.Location  = New-Object System.Drawing.Point(10, $y)
    $parent.Controls.Add($lbl)
    return $y + 18
}

function Add-TextBox($parent, $default, $y) {
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Text        = $default
    $tb.BackColor   = $Card
    $tb.ForeColor   = $TextLight
    $tb.BorderStyle = "FixedSingle"
    $tb.Font        = New-Object System.Drawing.Font("Consolas", 9)
    $tb.Location    = New-Object System.Drawing.Point(10, $y)
    $tb.Size        = New-Object System.Drawing.Size(240, 22)
    $parent.Controls.Add($tb)
    return $tb
}

function Add-NumericUpDown($parent, $val, $min, $max, $y) {
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Value     = $val; $n.Minimum = $min; $n.Maximum = $max
    $n.BackColor = $Card; $n.ForeColor = $TextLight
    $n.Location  = New-Object System.Drawing.Point(10, $y)
    $n.Size      = New-Object System.Drawing.Size(100, 22)
    $parent.Controls.Add($n)
    return $n
}

$cy = 10
$cy = Add-SectionLabel $lp "🌐  Network Scan" $cy
$cy += 10
$cy = Add-Label $lp "IP Range  (e.g. 192.168.1.1-254)" $cy
$IpRangeBox = Add-TextBox $lp "192.168.1.1-254" $cy; $cy += 28
$cy = Add-Label $lp "Ping Timeout (seconds)" $cy
$PingTimeout = Add-NumericUpDown $lp 1 1 10 $cy; $cy += 30
$cy = Add-Label $lp "Parallel Threads" $cy
$ThreadsNum = Add-NumericUpDown $lp 30 1 100 $cy; $cy += 30

$cy = Add-SectionLabel $lp "🔑  WinRM / Credentials" ($cy + 6)
$cy += 10

$UseCurrentChk = New-Object System.Windows.Forms.CheckBox
$UseCurrentChk.Text      = "Use Current User (Domain)"
$UseCurrentChk.ForeColor = $TextLight
$UseCurrentChk.BackColor = $Panel
$UseCurrentChk.Checked   = $true
$UseCurrentChk.Location  = New-Object System.Drawing.Point(10, $cy)
$UseCurrentChk.Size      = New-Object System.Drawing.Size(240, 20)
$lp.Controls.Add($UseCurrentChk); $cy += 26

$cy = Add-Label $lp "Username (DOMAIN\user)" $cy
$UserBox = Add-TextBox $lp "" $cy; $UserBox.Enabled = $false; $cy += 28
$cy = Add-Label $lp "Password" $cy
$PassBox = Add-TextBox $lp "" $cy
$PassBox.UseSystemPasswordChar = $true
$PassBox.Enabled = $false
$cy += 28

$UseCurrentChk.Add_CheckedChanged({
    $UserBox.Enabled = -not $UseCurrentChk.Checked
    $PassBox.Enabled = -not $UseCurrentChk.Checked
})

$cy = Add-SectionLabel $lp "⚠️  Alert Thresholds (days)" ($cy + 6)
$cy += 10

foreach ($cfg in @(
    @{Label="🔴  Critical";  Default=30},
    @{Label="🟡  Warning";   Default=60},
    @{Label="🔵  Notice";    Default=90}
)) {
    $cy = Add-Label $lp $cfg.Label $cy
    $n = Add-NumericUpDown $lp $cfg.Default 1 365 $cy
    switch ($cfg.Label) {
        {$_ -match "Critical"} { $Global:CritNum   = $n }
        {$_ -match "Warning"}  { $Global:WarnNum   = $n }
        {$_ -match "Notice"}   { $Global:NoticeNum = $n }
    }
    $cy += 30
}

# Buttons
$cy += 6
$ScanBtn = New-Object System.Windows.Forms.Button
$ScanBtn.Text      = "▶  Start Scan"
$ScanBtn.BackColor = $Blue
$ScanBtn.ForeColor = [System.Drawing.Color]::White
$ScanBtn.FlatStyle = "Flat"
$ScanBtn.Font      = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$ScanBtn.Location  = New-Object System.Drawing.Point(10, $cy)
$ScanBtn.Size      = New-Object System.Drawing.Size(240, 34)
$ScanBtn.Cursor    = "Hand"
$lp.Controls.Add($ScanBtn); $cy += 40

$StopBtn = New-Object System.Windows.Forms.Button
$StopBtn.Text      = "⏹  Stop"
$StopBtn.BackColor = $Card
$StopBtn.ForeColor = $TextMuted
$StopBtn.FlatStyle = "Flat"
$StopBtn.Enabled   = $false
$StopBtn.Location  = New-Object System.Drawing.Point(10, $cy)
$StopBtn.Size      = New-Object System.Drawing.Size(240, 28)
$StopBtn.Cursor    = "Hand"
$lp.Controls.Add($StopBtn); $cy += 34

$ExportBtn = New-Object System.Windows.Forms.Button
$ExportBtn.Text      = "💾  Export CSV"
$ExportBtn.BackColor = $Card
$ExportBtn.ForeColor = $TextLight
$ExportBtn.FlatStyle = "Flat"
$ExportBtn.Location  = New-Object System.Drawing.Point(10, $cy)
$ExportBtn.Size      = New-Object System.Drawing.Size(240, 28)
$ExportBtn.Cursor    = "Hand"
$lp.Controls.Add($ExportBtn); $cy += 40

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Location  = New-Object System.Drawing.Point(10, $cy)
$ProgressBar.Size      = New-Object System.Drawing.Size(240, 14)
$ProgressBar.Style     = "Continuous"
$ProgressBar.BackColor = $Card
$ProgressBar.ForeColor = $Blue
$lp.Controls.Add($ProgressBar); $cy += 20

$ProgLbl = New-Object System.Windows.Forms.Label
$ProgLbl.Text      = ""
$ProgLbl.ForeColor = $TextMuted
$ProgLbl.AutoSize  = $true
$ProgLbl.Location  = New-Object System.Drawing.Point(10, $cy)
$lp.Controls.Add($ProgLbl)

# ════════════════════════════════
# RIGHT PANEL — Tabs
# ════════════════════════════════
$Tabs = New-Object System.Windows.Forms.TabControl
$Tabs.Dock       = "Fill"
$Tabs.BackColor  = $Dark
$Tabs.Appearance = "Normal"
$Split.Panel2.Controls.Add($Tabs)

# ── Tab 1: Certificates ──
$CertsTab = New-Object System.Windows.Forms.TabPage
$CertsTab.Text      = "  🔐  Certificates  "
$CertsTab.BackColor = $Dark
$Tabs.Controls.Add($CertsTab)

# Filter bar
$FilterPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$FilterPanel.Dock      = "Top"
$FilterPanel.Height    = 38
$FilterPanel.BackColor = $Panel
$FilterPanel.Padding   = New-Object System.Windows.Forms.Padding(6, 6, 6, 0)
$CertsTab.Controls.Add($FilterPanel)

$Global:FilterValue = "all"
foreach ($f in @(
    @{Text="All";           Val="all";      Color=$TextLight},
    @{Text="🔴 Critical";   Val="critical"; Color=$Red},
    @{Text="🟡 Warning";    Val="warning";  Color=$Yellow},
    @{Text="🔵 Notice";     Val="notice";   Color=$Blue},
    @{Text="✅ OK";         Val="ok";       Color=$Green}
)) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text      = $f.Text
    $btn.ForeColor = $f.Color
    $btn.BackColor = $Card
    $btn.FlatStyle = "Flat"
    $btn.Size      = New-Object System.Drawing.Size(85, 24)
    $btn.Cursor    = "Hand"
    $btn.Tag       = $f.Val
    $btn.Add_Click({
        $Global:FilterValue = $this.Tag
        Apply-Filter
    })
    $FilterPanel.Controls.Add($btn)
}

$SearchBox = New-Object System.Windows.Forms.TextBox
$SearchBox.BackColor   = $Card
$SearchBox.ForeColor   = $TextLight
$SearchBox.BorderStyle = "FixedSingle"
$SearchBox.Font        = New-Object System.Drawing.Font("Consolas", 9)
$SearchBox.Size        = New-Object System.Drawing.Size(160, 24)
$SearchBox.Add_TextChanged({ Apply-Filter })
$FilterPanel.Controls.Add($SearchBox)

# ListView
$ListView = New-Object System.Windows.Forms.ListView
$ListView.Dock          = "Fill"
$ListView.View          = "Details"
$ListView.FullRowSelect = $true
$ListView.GridLines     = $true
$ListView.BackColor     = $Card
$ListView.ForeColor     = $TextLight
$ListView.BorderStyle   = "None"
$ListView.Font          = New-Object System.Drawing.Font("Consolas", 8.5)

foreach ($col in @(
    @{Text="IP Address";  Width=115},
    @{Text="Hostname";    Width=140},
    @{Text="Subject";     Width=200},
    @{Text="Issuer";      Width=160},
    @{Text="Expires On";  Width=100},
    @{Text="Days Left";   Width=90},
    @{Text="Status";      Width=90}
)) {
    [void]$ListView.Columns.Add($col.Text, $col.Width)
}
$CertsTab.Controls.Add($ListView)

# ── Tab 2: Summary ──
$SummaryTab = New-Object System.Windows.Forms.TabPage
$SummaryTab.Text      = "  📊  Summary  "
$SummaryTab.BackColor = $Dark
$Tabs.Controls.Add($SummaryTab)

$SummaryText = New-Object System.Windows.Forms.RichTextBox
$SummaryText.Dock        = "Fill"
$SummaryText.BackColor   = $Dark
$SummaryText.ForeColor   = $TextLight
$SummaryText.Font        = New-Object System.Drawing.Font("Consolas", 10)
$SummaryText.ReadOnly    = $true
$SummaryText.BorderStyle = "None"
$SummaryText.Text        = "`n  Run a scan to see the summary..."
$SummaryTab.Controls.Add($SummaryText)

# ── Tab 3: Scan Log ──
$LogTab = New-Object System.Windows.Forms.TabPage
$LogTab.Text      = "  📋  Scan Log  "
$LogTab.BackColor = $Dark
$Tabs.Controls.Add($LogTab)

$LogBox = New-Object System.Windows.Forms.RichTextBox
$LogBox.Dock        = "Fill"
$LogBox.BackColor   = $Card
$LogBox.ForeColor   = $TextMuted
$LogBox.Font        = New-Object System.Drawing.Font("Consolas", 8.5)
$LogBox.ReadOnly    = $true
$LogBox.BorderStyle = "None"
$LogTab.Controls.Add($LogBox)

# ─── UI Functions ─────────────────────────────────────────

function Write-Log {
    param([string]$Msg, [string]$Level = "info")
    $ts    = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "ok"    { $Green  }
        "warn"  { $Yellow }
        "err"   { $Red    }
        "info"  { $Blue   }
        default { $TextMuted }
    }
    $Form.Invoke([Action]{
        $LogBox.SelectionStart  = $LogBox.TextLength
        $LogBox.SelectionLength = 0
        $LogBox.SelectionColor  = $TextMuted
        $LogBox.AppendText("[$ts] ")
        $LogBox.SelectionColor  = $color
        $LogBox.AppendText("$Msg`n")
        $LogBox.ScrollToCaret()
    })
}

function Set-Status {
    param([string]$Msg, $Color = $TextLight)
    $Form.Invoke([Action]{ $StatusLbl.Text = $Msg; $StatusLbl.ForeColor = $Color })
}

function Apply-Filter {
    $flt    = $Global:FilterValue
    $search = $SearchBox.Text.ToLower()
    $ListView.BeginUpdate()
    $ListView.Items.Clear()
    foreach ($r in $Global:AllCertRows) {
        if ($flt -ne "all" -and $r.Tag -ne $flt) { continue }
        $match = $true
        if ($search) {
            $match = $false
            foreach ($sv in $r.SubItems) {
                if ($sv.Text.ToLower().Contains($search)) { $match = $true; break }
            }
        }
        if ($match) { [void]$ListView.Items.Add($r) }
    }
    $ListView.EndUpdate()
}

function Add-CertRow {
    param($IP, $Hostname, $Subject, $Issuer, $NotAfter, $DaysLeft, $StatusLabel, $StatusTag, $StatusColor)
    $item = New-Object System.Windows.Forms.ListViewItem($IP)
    $item.ForeColor = $StatusColor
    $item.Tag       = $StatusTag
    foreach ($v in @($Hostname, $Subject, $Issuer, $NotAfter, $DaysLeft, $StatusLabel)) {
        [void]$item.SubItems.Add($v.ToString())
    }
    $Global:AllCertRows.Add($item)
    $Form.Invoke([Action]{ [void]$ListView.Items.Add($item) })
}

function Update-Summary {
    $tags    = $Global:AllCertRows | ForEach-Object { $_.Tag }
    $crit    = ($tags | Where-Object { $_ -eq "critical" }).Count
    $warn    = ($tags | Where-Object { $_ -eq "warning"  }).Count
    $notice  = ($tags | Where-Object { $_ -eq "notice"   }).Count
    $ok      = ($tags | Where-Object { $_ -eq "ok"       }).Count
    $expired = ($tags | Where-Object { $_ -eq "expired"  }).Count
    $hosts   = $Global:ScanResults.Count

    $Form.Invoke([Action]{
        $SummaryText.Clear()
        $SummaryText.SelectionFont  = New-Object System.Drawing.Font("Consolas", 13, [System.Drawing.FontStyle]::Bold)
        $SummaryText.SelectionColor = $TextLight
        $SummaryText.AppendText("`n  📊  Scan Summary`n`n")

        $lines = @(
            @{ Label="  Active Servers   "; Val=$hosts;   Color=$Blue     },
            @{ Label="  Expired          "; Val=$expired; Color=$TextMuted },
            @{ Label="  🔴  Critical     "; Val=$crit;   Color=$Red      },
            @{ Label="  🟡  Warning      "; Val=$warn;   Color=$Yellow   },
            @{ Label="  🔵  Notice       "; Val=$notice; Color=$Blue     },
            @{ Label="  ✅  OK           "; Val=$ok;     Color=$Green    }
        )
        foreach ($l in $lines) {
            $SummaryText.SelectionFont  = New-Object System.Drawing.Font("Consolas", 11)
            $SummaryText.SelectionColor = $TextMuted
            $SummaryText.AppendText($l.Label)
            $SummaryText.SelectionFont  = New-Object System.Drawing.Font("Consolas", 18, [System.Drawing.FontStyle]::Bold)
            $SummaryText.SelectionColor = $l.Color
            $SummaryText.AppendText("  $($l.Val)`n")
        }
    })
}

function Update-Progress {
    param([int]$Done, [int]$Total)
    $pct = [int](($Done / $Total) * 100)
    $Form.Invoke([Action]{
        $ProgressBar.Value = [Math]::Min($pct, 100)
        $ProgLbl.Text      = "$Done/$Total  ($pct%)"
    })
}

# ─── Scan Logic ───────────────────────────────────────────

function Start-Scan {
    try { $ips = Parse-IPRange $IpRangeBox.Text }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Invalid IP range: $_", "Error")
        return
    }

    $Global:ScanResults.Clear()
    $Global:AllCertRows.Clear()
    $ListView.Items.Clear()

    $Global:IsRunning  = $true
    $ScanBtn.Enabled   = $false
    $StopBtn.Enabled   = $true
    $ProgressBar.Value = 0
    Set-Status "Scanning..." $Yellow
    Write-Log "Starting scan of $($ips.Count) IP addresses" "info"

    $timeout    = [int]$PingTimeout.Value
    $maxThreads = [int]$ThreadsNum.Value
    $useCurrent = $UseCurrentChk.Checked
    $username   = $UserBox.Text
    $password   = $PassBox.Text
    $critDays   = [int]$Global:CritNum.Value
    $warnDays   = [int]$Global:WarnNum.Value
    $noticeDays = [int]$Global:NoticeNum.Value
    $total      = $ips.Count

    $runspace = [RunspaceFactory]::CreateRunspacePool(1, $maxThreads)
    $runspace.Open()

    $jobs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ip in $ips) {
        if (-not $Global:IsRunning) { break }

        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $runspace

        [void]$ps.AddScript({
            param($IP, $TimeoutMS, $UseCurrent, $User, $Pass)

            function Test-Ping($ip, $ms) {
                try {
                    $p = New-Object System.Net.NetworkInformation.Ping
                    ($p.Send($ip, $ms)).Status -eq 'Success'
                } catch { $false }
            }

            function Get-ShortHostname($ip) {
                try { ([System.Net.Dns]::GetHostEntry($ip).HostName -split '\.')[0] }
                catch { $ip }
            }

            if (-not (Test-Ping $IP $TimeoutMS)) { return $null }

            $hn    = Get-ShortHostname $IP
            $certs = @()

            $script = {
                $certs = Get-ChildItem -Path Cert:\LocalMachine\My -EA SilentlyContinue
                foreach ($c in $certs) {
                    [PSCustomObject]@{
                        Subject      = $c.Subject
                        Issuer       = $c.Issuer
                        NotAfter     = $c.NotAfter.ToString("yyyy-MM-dd")
                        DaysLeft     = [int]($c.NotAfter - (Get-Date)).TotalDays
                        FriendlyName = $c.FriendlyName
                    }
                }
            }

            try {
                if ($UseCurrent) {
                    $certs = Invoke-Command -ComputerName $IP -ScriptBlock $script -EA Stop
                } else {
                    $sp    = ConvertTo-SecureString $Pass -AsPlainText -Force
                    $cred  = New-Object PSCredential($User, $sp)
                    $certs = Invoke-Command -ComputerName $IP -Credential $cred -ScriptBlock $script -EA Stop
                }
            } catch { }

            [PSCustomObject]@{ IP=$IP; Hostname=$hn; Certs=@($certs) }
        })

        [void]$ps.AddArgument($ip)
        [void]$ps.AddArgument($timeout * 1000)
        [void]$ps.AddArgument($useCurrent)
        [void]$ps.AddArgument($username)
        [void]$ps.AddArgument($password)

        $jobs.Add(@{ PS=$ps; Handle=$ps.BeginInvoke() })
    }

    # Collect results in background thread
    $collector = {
        param($jobs, $total, $critDays, $warnDays, $noticeDays)
        $done = 0
        foreach ($job in $jobs) {
            $result = $job.PS.EndInvoke($job.Handle)
            $job.PS.Dispose()
            $done++
            if ($null -eq $result) { Update-Progress $done $total; continue }

            $Global:ScanResults.Add($result)
            Write-Log "OK  $($result.IP)  ($($result.Hostname))  — $($result.Certs.Count) certificate(s)" "ok"

            if ($result.Certs.Count -eq 0) {
                Add-CertRow $result.IP $result.Hostname "(no certificates)" "" "" "" "—" "ok" $Green
            } else {
                foreach ($cert in $result.Certs) {
                    $st   = Get-CertStatus $cert.DaysLeft $critDays $warnDays $noticeDays
                    $subj = if ($cert.Subject.Length -gt 60) { $cert.Subject.Substring(0,60) } else { $cert.Subject }
                    $issr = if ($cert.Issuer.Length  -gt 50) { $cert.Issuer.Substring(0,50)  } else { $cert.Issuer  }
                    Add-CertRow $result.IP $result.Hostname $subj $issr $cert.NotAfter $cert.DaysLeft $st.Label $st.Tag $st.Color
                }
            }
            Update-Progress $done $total
        }

        $crit = ($Global:AllCertRows | Where-Object { $_.Tag -eq "critical" }).Count
        $warn = ($Global:AllCertRows | Where-Object { $_.Tag -eq "warning"  }).Count
        Write-Log "Scan complete — $($Global:ScanResults.Count) servers | $crit critical | $warn warning" "ok"
        Set-Status "Done | $crit Critical | $warn Warning" $(if ($crit -gt 0) { $Red } else { $Green })
        $Form.Invoke([Action]{
            $ScanBtn.Enabled  = $true
            $StopBtn.Enabled  = $false
            $Global:IsRunning = $false
        })
        Update-Summary
        $runspace.Close()
    }

    $collectorPS = [PowerShell]::Create()
    [void]$collectorPS.AddScript($collector)
    [void]$collectorPS.AddArgument($jobs)
    [void]$collectorPS.AddArgument($total)
    [void]$collectorPS.AddArgument($critDays)
    [void]$collectorPS.AddArgument($warnDays)
    [void]$collectorPS.AddArgument($noticeDays)
    [void]$collectorPS.BeginInvoke()
}

# ─── Button Events ────────────────────────────────────────

$ScanBtn.Add_Click({ Start-Scan })

$StopBtn.Add_Click({
    $Global:IsRunning = $false
    Set-Status "Stopped" $Yellow
    Write-Log "Scan stopped by user" "warn"
    $ScanBtn.Enabled = $true
    $StopBtn.Enabled = $false
})

$ExportBtn.Add_Click({
    if ($Global:AllCertRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to export.", "Export")
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter           = "CSV files (*.csv)|*.csv"
    $dlg.FileName         = "cert_report_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq "OK") {
        $headers = "IP Address,Hostname,Subject,Issuer,Expires On,Days Left,Status"
        $lines   = @($headers)
        foreach ($r in $Global:AllCertRows) {
            $vals   = @($r.Text) + ($r.SubItems | Select-Object -Skip 1 | ForEach-Object { $_.Text })
            $lines += ($vals -join ",")
        }
        $lines | Out-File -FilePath $dlg.FileName -Encoding UTF8
        Write-Log "CSV exported: $($dlg.FileName)" "ok"
        [System.Windows.Forms.MessageBox]::Show("File saved:`n$($dlg.FileName)", "Export")
    }
})

# ─── Launch ───────────────────────────────────────────────
Write-Log "CertWatch ready — PowerShell Edition" "info"
Write-Log "Set your IP range and click Start Scan" "info"

[void]$Form.ShowDialog()
