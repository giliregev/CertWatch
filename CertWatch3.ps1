#Requires -Version 5.1
<#
.SYNOPSIS
    CertWatch - SSL/TLS Certificate Scanner for Windows Networks
.DESCRIPTION
    Scans an IP range, checks which servers are alive, and retrieves
    certificates from LocalMachine\My (Personal) via WinRM / PowerShell Remoting
.NOTES
    No installation required - runs on any Windows machine with PowerShell 5.1+
    Run as Administrator for best results
    To run: powershell -ExecutionPolicy Bypass -File CertWatch.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ─── Colors ──────────────────────────────────────────────
$clrBg       = [System.Drawing.Color]::FromArgb(18,  18,  24)
$clrPanel    = [System.Drawing.Color]::FromArgb(28,  30,  40)
$clrCard     = [System.Drawing.Color]::FromArgb(40,  42,  54)
$clrBorder   = [System.Drawing.Color]::FromArgb(60,  63,  80)
$clrBlue     = [System.Drawing.Color]::FromArgb(82,  148, 255)
$clrGreen    = [System.Drawing.Color]::FromArgb(80,  200, 120)
$clrYellow   = [System.Drawing.Color]::FromArgb(230, 180,  50)
$clrRed      = [System.Drawing.Color]::FromArgb(240,  80,  80)
$clrText     = [System.Drawing.Color]::FromArgb(220, 225, 240)
$clrMuted    = [System.Drawing.Color]::FromArgb(130, 135, 160)
$clrWhite    = [System.Drawing.Color]::White

# ─── Global State ─────────────────────────────────────────
$Global:AllRows    = [System.Collections.Generic.List[PSObject]]::new()
$Global:Results    = [System.Collections.Generic.List[PSObject]]::new()
$Global:IsRunning  = $false

# ─────────────────────────────────────────────────────────
# MAIN FORM
# ─────────────────────────────────────────────────────────
$Form                  = New-Object System.Windows.Forms.Form
$Form.Text             = "CertWatch  —  SSL/TLS Certificate Scanner"
$Form.Size             = New-Object System.Drawing.Size(1200, 750)
$Form.MinimumSize      = New-Object System.Drawing.Size(900, 580)
$Form.BackColor        = $clrBg
$Form.ForeColor        = $clrText
$Form.StartPosition    = "CenterScreen"
$Form.Font             = New-Object System.Drawing.Font("Segoe UI", 9)
$Form.RightToLeft      = "No"

# ─────────────────────────────────────────────────────────
# HEADER BAR
# ─────────────────────────────────────────────────────────
$pnlHeader             = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock        = "Top"
$pnlHeader.Height      = 52
$pnlHeader.BackColor   = $clrPanel
$Form.Controls.Add($pnlHeader)

$lblTitle              = New-Object System.Windows.Forms.Label
$lblTitle.Text         = "  CertWatch"
$lblTitle.Font         = New-Object System.Drawing.Font("Consolas", 17, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor    = $clrBlue
$lblTitle.AutoSize     = $true
$lblTitle.Location     = New-Object System.Drawing.Point(8, 11)
$pnlHeader.Controls.Add($lblTitle)

$lblSub                = New-Object System.Windows.Forms.Label
$lblSub.Text           = "SSL/TLS Certificate Scanner  |  PowerShell Edition"
$lblSub.ForeColor      = $clrMuted
$lblSub.AutoSize       = $true
$lblSub.Location       = New-Object System.Drawing.Point(210, 18)
$pnlHeader.Controls.Add($lblSub)

$lblStatus             = New-Object System.Windows.Forms.Label
$lblStatus.Text        = "Ready"
$lblStatus.ForeColor   = $clrGreen
$lblStatus.AutoSize    = $true
$lblStatus.Font        = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblStatus.Anchor      = "Top,Right"
$lblStatus.Location    = New-Object System.Drawing.Point(1060, 18)
$pnlHeader.Controls.Add($lblStatus)

# ─────────────────────────────────────────────────────────
# BOTTOM STATUS BAR
# ─────────────────────────────────────────────────────────
$pnlBottom             = New-Object System.Windows.Forms.Panel
$pnlBottom.Dock        = "Bottom"
$pnlBottom.Height      = 28
$pnlBottom.BackColor   = $clrPanel

$lblBottom             = New-Object System.Windows.Forms.Label
$lblBottom.Text        = "  Ready. Configure the IP range and click Start Scan."
$lblBottom.ForeColor   = $clrMuted
$lblBottom.AutoSize    = $true
$lblBottom.Location    = New-Object System.Drawing.Point(4, 6)
$pnlBottom.Controls.Add($lblBottom)
$Form.Controls.Add($pnlBottom)

# ─────────────────────────────────────────────────────────
# SPLITTER
# ─────────────────────────────────────────────────────────
$split                       = New-Object System.Windows.Forms.SplitContainer
$split.Dock                  = "Fill"
$split.Orientation           = "Vertical"
$split.SplitterWidth         = 5
$split.SplitterDistance      = 285
$split.BackColor             = $clrBorder
$split.Panel1.BackColor      = $clrPanel
$split.Panel2.BackColor      = $clrBg
$split.Panel1MinSize         = 240
$split.Panel2MinSize         = 400
$split.IsSplitterFixed       = $false
$Form.Controls.Add($split)

# ─────────────────────────────────────────────────────────
# LEFT PANEL  — Settings
# ─────────────────────────────────────────────────────────
$pnlLeft = $split.Panel1

# helper: add a grey section title
function New-SectionTitle([string]$text, [int]$y) {
    $lbl            = New-Object System.Windows.Forms.Label
    $lbl.Text       = $text
    $lbl.ForeColor  = $clrMuted
    $lbl.BackColor  = $clrPanel
    $lbl.Font       = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $lbl.AutoSize   = $true
    $lbl.Location   = New-Object System.Drawing.Point(12, $y)
    $pnlLeft.Controls.Add($lbl)

    $line           = New-Object System.Windows.Forms.Panel
    $line.BackColor = $clrBorder
    $line.Location  = New-Object System.Drawing.Point(12, ($y + 18))
    $line.Size      = New-Object System.Drawing.Size(248, 1)
    $pnlLeft.Controls.Add($line)
    return ($y + 26)
}

# helper: label + textbox pair
function New-LabeledTextBox([string]$label, [string]$default, [int]$y) {
    $lbl            = New-Object System.Windows.Forms.Label
    $lbl.Text       = $label
    $lbl.ForeColor  = $clrMuted
    $lbl.AutoSize   = $true
    $lbl.Location   = New-Object System.Drawing.Point(12, $y)
    $pnlLeft.Controls.Add($lbl)

    $tb             = New-Object System.Windows.Forms.TextBox
    $tb.Text        = $default
    $tb.BackColor   = $clrCard
    $tb.ForeColor   = $clrText
    $tb.BorderStyle = "FixedSingle"
    $tb.Font        = New-Object System.Drawing.Font("Consolas", 10)
    $tb.Location    = New-Object System.Drawing.Point(12, ($y + 17))
    $tb.Size        = New-Object System.Drawing.Size(254, 24)
    $tb.TabStop     = $true
    $pnlLeft.Controls.Add($tb)
    return $tb
}

# helper: label + numeric
function New-LabeledNumeric([string]$label, [int]$default, [int]$min, [int]$max, [int]$y) {
    $lbl            = New-Object System.Windows.Forms.Label
    $lbl.Text       = $label
    $lbl.ForeColor  = $clrMuted
    $lbl.AutoSize   = $true
    $lbl.Location   = New-Object System.Drawing.Point(12, $y)
    $pnlLeft.Controls.Add($lbl)

    $num            = New-Object System.Windows.Forms.NumericUpDown
    $num.Minimum    = $min
    $num.Maximum    = $max
    $num.Value      = $default
    $num.BackColor  = $clrCard
    $num.ForeColor  = $clrText
    $num.BorderStyle= "FixedSingle"
    $num.Font       = New-Object System.Drawing.Font("Consolas", 10)
    $num.Location   = New-Object System.Drawing.Point(12, ($y + 17))
    $num.Size       = New-Object System.Drawing.Size(110, 24)
    $num.TabStop    = $true
    $pnlLeft.Controls.Add($num)
    return $num
}

$y = 10

# ── Network Scan ──
$y = New-SectionTitle "NETWORK SCAN" $y
$y += 4
$tbIPRange   = New-LabeledTextBox "IP Range  (e.g. 192.168.1.1-254  or  /24)" "192.168.1.1-254" $y
$y += 50
$numTimeout  = New-LabeledNumeric "Ping Timeout (seconds)" 1 1 30 $y
$y += 50
$numThreads  = New-LabeledNumeric "Parallel Threads" 30 1 100 $y
$y += 52

# ── Credentials ──
$y = New-SectionTitle "WINRM / CREDENTIALS" $y
$y += 4

$chkCurrentUser            = New-Object System.Windows.Forms.CheckBox
$chkCurrentUser.Text       = "Use current logged-on user (Domain)"
$chkCurrentUser.ForeColor  = $clrText
$chkCurrentUser.BackColor  = $clrPanel
$chkCurrentUser.Checked    = $true
$chkCurrentUser.Location   = New-Object System.Drawing.Point(12, $y)
$chkCurrentUser.Size       = New-Object System.Drawing.Size(256, 20)
$chkCurrentUser.TabStop    = $true
$pnlLeft.Controls.Add($chkCurrentUser)
$y += 28

$tbUsername  = New-LabeledTextBox "Username  (DOMAIN\user)" "" $y
$tbUsername.Enabled = $false
$y += 50
$tbPassword  = New-LabeledTextBox "Password" "" $y
$tbPassword.UseSystemPasswordChar = $true
$tbPassword.Enabled = $false
$y += 52

$chkCurrentUser.Add_CheckedChanged({
    $tbUsername.Enabled = -not $chkCurrentUser.Checked
    $tbPassword.Enabled = -not $chkCurrentUser.Checked
})

# ── Alert Thresholds ──
$y = New-SectionTitle "ALERT THRESHOLDS (days)" $y
$y += 4
$numCritical = New-LabeledNumeric "Critical  (red)" 30 1 365 $y
$y += 50
$numWarning  = New-LabeledNumeric "Warning  (yellow)" 60 1 365 $y
$y += 50
$numNotice   = New-LabeledNumeric "Notice  (blue)" 90 1 365 $y
$y += 52

# ── Buttons ──
function New-ActionButton([string]$text, [int]$bY, $bg, $fg) {
    $btn            = New-Object System.Windows.Forms.Button
    $btn.Text       = $text
    $btn.BackColor  = $bg
    $btn.ForeColor  = $fg
    $btn.FlatStyle  = "Flat"
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font       = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btn.Location   = New-Object System.Drawing.Point(12, $bY)
    $btn.Size       = New-Object System.Drawing.Size(254, 34)
    $btn.Cursor     = "Hand"
    $btn.TabStop    = $true
    $pnlLeft.Controls.Add($btn)
    return $btn
}

$btnScan   = New-ActionButton "▶  Start Scan"   $y $clrBlue  $clrWhite; $y += 42
$btnStop   = New-ActionButton "⏹  Stop"         $y $clrCard  $clrMuted; $btnStop.Enabled = $false; $y += 42
$btnExport = New-ActionButton "💾  Export CSV"  $y $clrCard  $clrText;  $y += 42

# progress
$progBar            = New-Object System.Windows.Forms.ProgressBar
$progBar.Style      = "Continuous"
$progBar.BackColor  = $clrCard
$progBar.ForeColor  = $clrBlue
$progBar.Location   = New-Object System.Drawing.Point(12, $y)
$progBar.Size       = New-Object System.Drawing.Size(254, 12)
$pnlLeft.Controls.Add($progBar)
$y += 18

$lblProgress        = New-Object System.Windows.Forms.Label
$lblProgress.Text   = ""
$lblProgress.ForeColor = $clrMuted
$lblProgress.AutoSize  = $true
$lblProgress.Location  = New-Object System.Drawing.Point(12, $y)
$pnlLeft.Controls.Add($lblProgress)

# ─────────────────────────────────────────────────────────
# RIGHT PANEL  — Tabs
# ─────────────────────────────────────────────────────────
$tabs               = New-Object System.Windows.Forms.TabControl
$tabs.Dock          = "Fill"
$tabs.Font          = New-Object System.Drawing.Font("Segoe UI", 9)
$tabs.BackColor     = $clrBg
$split.Panel2.Controls.Add($tabs)

function New-Tab([string]$title) {
    $tab            = New-Object System.Windows.Forms.TabPage
    $tab.Text       = "  $title  "
    $tab.BackColor  = $clrBg
    $tab.ForeColor  = $clrText
    $tabs.Controls.Add($tab)
    return $tab
}

# ── Tab 1: Certificates ──
$tabCerts   = New-Tab "🔐  Certificates"

# filter bar
$pnlFilter  = New-Object System.Windows.Forms.Panel
$pnlFilter.Dock      = "Top"
$pnlFilter.Height    = 42
$pnlFilter.BackColor = $clrPanel
$tabCerts.Controls.Add($pnlFilter)

$filterX = 8
$Global:ActiveFilter = "all"

foreach ($f in @(
    @{T="All";           V="all";      C=$clrText  },
    @{T="🔴 Critical";  V="critical"; C=$clrRed   },
    @{T="🟡 Warning";   V="warning";  C=$clrYellow},
    @{T="🔵 Notice";    V="notice";   C=$clrBlue  },
    @{T="✅ OK";        V="ok";       C=$clrGreen }
)) {
    $fb = New-Object System.Windows.Forms.Button
    $fb.Text      = $f.T
    $fb.ForeColor = $f.C
    $fb.BackColor = $clrCard
    $fb.FlatStyle = "Flat"
    $fb.FlatAppearance.BorderSize = 0
    $fb.Size      = New-Object System.Drawing.Size(88, 26)
    $fb.Location  = New-Object System.Drawing.Point($filterX, 8)
    $fb.Cursor    = "Hand"
    $fb.Tag       = $f.V
    $fb.Add_Click({ $Global:ActiveFilter = $this.Tag; Apply-Filter })
    $pnlFilter.Controls.Add($fb)
    $filterX += 92
}

$tbSearch           = New-Object System.Windows.Forms.TextBox
$tbSearch.BackColor = $clrCard
$tbSearch.ForeColor = $clrText
$tbSearch.BorderStyle = "FixedSingle"
$tbSearch.Font      = New-Object System.Drawing.Font("Consolas", 9)
$tbSearch.Size      = New-Object System.Drawing.Size(180, 24)
$tbSearch.Location  = New-Object System.Drawing.Point(($filterX + 10), 10)
$tbSearch.Add_TextChanged({ Apply-Filter })
$pnlFilter.Controls.Add($tbSearch)

# listview
$lvCerts                = New-Object System.Windows.Forms.ListView
$lvCerts.Dock           = "Fill"
$lvCerts.View           = "Details"
$lvCerts.FullRowSelect  = $true
$lvCerts.GridLines      = $true
$lvCerts.BackColor      = $clrCard
$lvCerts.ForeColor      = $clrText
$lvCerts.BorderStyle    = "None"
$lvCerts.Font           = New-Object System.Drawing.Font("Consolas", 9)
$lvCerts.HideSelection  = $false

foreach ($col in @(
    @{N="IP Address";  W=115},
    @{N="Hostname";    W=150},
    @{N="Subject";     W=220},
    @{N="Issuer";      W=170},
    @{N="Expires On";  W=100},
    @{N="Days Left";   W=85},
    @{N="Status";      W=85}
)) { [void]$lvCerts.Columns.Add($col.N, $col.W) }

$tabCerts.Controls.Add($lvCerts)

# ── Tab 2: Summary ──
$tabSummary = New-Tab "📊  Summary"
$rtbSummary = New-Object System.Windows.Forms.RichTextBox
$rtbSummary.Dock        = "Fill"
$rtbSummary.BackColor   = $clrBg
$rtbSummary.ForeColor   = $clrText
$rtbSummary.Font        = New-Object System.Drawing.Font("Consolas", 10)
$rtbSummary.ReadOnly    = $true
$rtbSummary.BorderStyle = "None"
$rtbSummary.Text        = "`n  Run a scan to see the summary..."
$tabSummary.Controls.Add($rtbSummary)

# ── Tab 3: Scan Log ──
$tabLog = New-Tab "📋  Scan Log"
$rtbLog = New-Object System.Windows.Forms.RichTextBox
$rtbLog.Dock        = "Fill"
$rtbLog.BackColor   = $clrCard
$rtbLog.ForeColor   = $clrMuted
$rtbLog.Font        = New-Object System.Drawing.Font("Consolas", 8.5)
$rtbLog.ReadOnly    = $true
$rtbLog.BorderStyle = "None"
$tabLog.Controls.Add($rtbLog)

# ─────────────────────────────────────────────────────────
# UI HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Msg, [string]$Level = "info")
    $ts = Get-Date -Format "HH:mm:ss"
    $c  = switch ($Level) {
        "ok"   { $clrGreen  }
        "warn" { $clrYellow }
        "err"  { $clrRed    }
        "info" { $clrBlue   }
        default{ $clrMuted  }
    }
    $Form.Invoke([Action]{
        $rtbLog.SelectionStart  = $rtbLog.TextLength
        $rtbLog.SelectionColor  = $clrMuted
        $rtbLog.AppendText("[$ts]  ")
        $rtbLog.SelectionColor  = $c
        $rtbLog.AppendText("$Msg`n")
        $rtbLog.ScrollToCaret()
    })
}

function Set-Status {
    param([string]$Msg, $Color = $clrText)
    $Form.Invoke([Action]{
        $lblStatus.Text      = $Msg
        $lblStatus.ForeColor = $Color
        $lblBottom.Text      = "  $Msg"
    })
}

function Set-Progress {
    param([int]$Done, [int]$Total)
    $pct = if ($Total -gt 0) { [int](($Done / $Total) * 100) } else { 0 }
    $Form.Invoke([Action]{
        $progBar.Value      = [Math]::Min($pct, 100)
        $lblProgress.Text   = "$Done / $Total  ($pct%)"
    })
}

function Apply-Filter {
    $flt    = $Global:ActiveFilter
    $search = $tbSearch.Text.Trim().ToLower()
    $lvCerts.BeginUpdate()
    $lvCerts.Items.Clear()
    foreach ($row in $Global:AllRows) {
        if ($flt -ne "all" -and $row.Tag -ne $flt) { continue }
        if ($search -ne "") {
            $hit = $false
            foreach ($si in $row.SubItems) {
                if ($si.Text.ToLower().Contains($search)) { $hit = $true; break }
            }
            if (-not $hit) { continue }
        }
        [void]$lvCerts.Items.Add($row)
    }
    $lvCerts.EndUpdate()
}

function Add-Row {
    param($IP, $Host, $Subject, $Issuer, $Expires, $Days, $StatusText, $StatusTag, $Color)
    $item           = New-Object System.Windows.Forms.ListViewItem($IP)
    $item.ForeColor = $Color
    $item.Tag       = $StatusTag
    foreach ($v in @($Host, $Subject, $Issuer, $Expires, $Days, $StatusText)) {
        [void]$item.SubItems.Add("$v")
    }
    $Global:AllRows.Add($item)
    $Form.Invoke([Action]{ [void]$lvCerts.Items.Add($item) })
}

function Update-Summary {
    $tags    = $Global:AllRows | ForEach-Object { $_.Tag }
    $crit    = @($tags | Where-Object { $_ -eq "critical" }).Count
    $warn    = @($tags | Where-Object { $_ -eq "warning"  }).Count
    $notice  = @($tags | Where-Object { $_ -eq "notice"   }).Count
    $ok      = @($tags | Where-Object { $_ -eq "ok"       }).Count
    $exp     = @($tags | Where-Object { $_ -eq "expired"  }).Count
    $hosts   = $Global:Results.Count

    $Form.Invoke([Action]{
        $rtbSummary.Clear()
        $rtbSummary.SelectionFont  = New-Object System.Drawing.Font("Consolas", 14, [System.Drawing.FontStyle]::Bold)
        $rtbSummary.SelectionColor = $clrText
        $rtbSummary.AppendText("`n  Scan Summary`n`n")

        foreach ($row in @(
            @{L="  Active Servers";  V=$hosts;  C=$clrBlue   },
            @{L="  Expired        "; V=$exp;    C=$clrMuted  },
            @{L="  Critical       "; V=$crit;   C=$clrRed    },
            @{L="  Warning        "; V=$warn;   C=$clrYellow },
            @{L="  Notice         "; V=$notice; C=$clrBlue   },
            @{L="  OK             "; V=$ok;     C=$clrGreen  }
        )) {
            $rtbSummary.SelectionFont  = New-Object System.Drawing.Font("Consolas", 11)
            $rtbSummary.SelectionColor = $clrMuted
            $rtbSummary.AppendText($row.L)
            $rtbSummary.SelectionFont  = New-Object System.Drawing.Font("Consolas", 20, [System.Drawing.FontStyle]::Bold)
            $rtbSummary.SelectionColor = $row.C
            $rtbSummary.AppendText("  $($row.V)`n")
        }
    })
}

# ─────────────────────────────────────────────────────────
# IP RANGE PARSER
# ─────────────────────────────────────────────────────────
function Parse-IPRange([string]$s) {
    $list = [System.Collections.Generic.List[string]]::new()
    $s    = $s.Trim()
    if ($s -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$') {
        $pre = $Matches[1]; $a = [int]$Matches[2]; $b = [int]$Matches[3]
        for ($i = $a; $i -le $b; $i++) { $list.Add("$pre$i") }
    } elseif ($s -match '/') {
        $p   = $s -split '/'; $base = $p[0]; $bits = [int]$p[1]
        $msk = [uint32]([uint32]::MaxValue -shl (32 - $bits))
        $raw = [System.Net.IPAddress]::Parse($base).GetAddressBytes(); [Array]::Reverse($raw)
        $net = [System.BitConverter]::ToUInt32($raw, 0) -band $msk
        $cnt = [uint32]([uint32]::MaxValue - $msk) - 1
        for ($i = 1; $i -le $cnt; $i++) {
            $b2 = [System.BitConverter]::GetBytes([uint32]($net + $i)); [Array]::Reverse($b2)
            $list.Add(([System.Net.IPAddress]::new($b2)).ToString())
        }
    } elseif ($s -match ',') {
        foreach ($ip in ($s -split ',')) { $list.Add($ip.Trim()) }
    } else { $list.Add($s) }
    return $list
}

# ─────────────────────────────────────────────────────────
# CERT STATUS
# ─────────────────────────────────────────────────────────
function Get-CertStatus([int]$days, [int]$crit, [int]$warn, [int]$notice) {
    if     ($days -lt 0)      { @{L="Expired";  T="expired";  C=$clrMuted  } }
    elseif ($days -le $crit)  { @{L="Critical"; T="critical"; C=$clrRed    } }
    elseif ($days -le $warn)  { @{L="Warning";  T="warning";  C=$clrYellow } }
    elseif ($days -le $notice){ @{L="Notice";   T="notice";   C=$clrBlue   } }
    else                      { @{L="OK";       T="ok";       C=$clrGreen  } }
}

# ─────────────────────────────────────────────────────────
# SCAN ENGINE
# ─────────────────────────────────────────────────────────
function Start-Scan {
    # validate
    if ($tbIPRange.Text.Trim() -eq "") {
        [System.Windows.Forms.MessageBox]::Show("Please enter an IP range.", "Missing Input",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    try   { $ips = Parse-IPRange $tbIPRange.Text }
    catch { [System.Windows.Forms.MessageBox]::Show("Invalid IP range: $_","Error"); return }

    # reset UI
    $Global:AllRows.Clear()
    $Global:Results.Clear()
    $lvCerts.Items.Clear()
    $progBar.Value     = 0
    $lblProgress.Text  = ""
    $Global:IsRunning  = $true
    $btnScan.Enabled   = $false
    $btnStop.Enabled   = $true
    Set-Status "Scanning $($ips.Count) addresses..." $clrYellow
    Write-Log "Scan started — $($ips.Count) IP addresses" "info"
    $tabs.SelectedTab  = $tabCerts

    # capture settings
    $maxT   = [int]$numThreads.Value
    $toutMS = [int]$numTimeout.Value * 1000
    $useMe  = $chkCurrentUser.Checked
    $uname  = $tbUsername.Text
    $upass  = $tbPassword.Text
    $cDays  = [int]$numCritical.Value
    $wDays  = [int]$numWarning.Value
    $nDays  = [int]$numNotice.Value
    $total  = $ips.Count

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $maxT)
    $pool.Open()
    $jobs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ip in $ips) {
        if (-not $Global:IsRunning) { break }
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($IP, $ToutMS, $UseMe, $User, $Pass)
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                if (($ping.Send($IP, $ToutMS)).Status -ne 'Success') { return $null }
            } catch { return $null }
            try { $hn = ([System.Net.Dns]::GetHostEntry($IP).HostName -split '\.')[0] }
            catch { $hn = $IP }
            $sb = {
                Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue | ForEach-Object {
                    [PSCustomObject]@{
                        Subject  = $_.Subject
                        Issuer   = $_.Issuer
                        NotAfter = $_.NotAfter.ToString("yyyy-MM-dd")
                        DaysLeft = [int]($_.NotAfter - (Get-Date)).TotalDays
                    }
                }
            }
            $certs = @()
            try {
                if ($UseMe) { $certs = @(Invoke-Command -ComputerName $IP -ScriptBlock $sb -EA Stop) }
                else {
                    $sp    = ConvertTo-SecureString $Pass -AsPlainText -Force
                    $cred  = New-Object PSCredential($User, $sp)
                    $certs = @(Invoke-Command -ComputerName $IP -Credential $cred -ScriptBlock $sb -EA Stop)
                }
            } catch {}
            [PSCustomObject]@{ IP=$IP; Hostname=$hn; Certs=$certs }
        })
        [void]$ps.AddArgument($ip)
        [void]$ps.AddArgument($toutMS)
        [void]$ps.AddArgument($useMe)
        [void]$ps.AddArgument($uname)
        [void]$ps.AddArgument($upass)
        $jobs.Add(@{ PS=$ps; H=$ps.BeginInvoke() })
    }

    # collector thread
    $col = [PowerShell]::Create()
    [void]$col.AddScript({
        param($jobs, $total, $cDays, $wDays, $nDays, $pool)
        $done = 0
        foreach ($j in $jobs) {
            $r = $j.PS.EndInvoke($j.H); $j.PS.Dispose(); $done++
            if ($null -eq $r) { Set-Progress $done $total; continue }
            $Global:Results.Add($r)
            if ($r.Certs.Count -eq 0) {
                Write-Log "ALIVE  $($r.IP)  ($($r.Hostname))  — no certificates" "ok"
                Add-Row $r.IP $r.Hostname "(no certificates)" "" "" "" "—" "ok" $clrGreen
            } else {
                Write-Log "ALIVE  $($r.IP)  ($($r.Hostname))  — $($r.Certs.Count) cert(s)" "ok"
                foreach ($c in $r.Certs) {
                    $st   = Get-CertStatus $c.DaysLeft $cDays $wDays $nDays
                    $subj = if ($c.Subject.Length -gt 55) { $c.Subject.Substring(0,55)+"…" } else { $c.Subject }
                    $issr = if ($c.Issuer.Length  -gt 45) { $c.Issuer.Substring(0,45)+"…"  } else { $c.Issuer  }
                    Add-Row $r.IP $r.Hostname $subj $issr $c.NotAfter $c.DaysLeft $st.L $st.T $st.C
                }
            }
            Set-Progress $done $total
        }
        $crit = @($Global:AllRows | Where-Object { $_.Tag -eq "critical" }).Count
        $warn = @($Global:AllRows | Where-Object { $_.Tag -eq "warning"  }).Count
        Write-Log "Scan complete — $($Global:Results.Count) servers alive  |  $crit critical  |  $warn warning" "ok"
        $sc = if ($crit -gt 0) { $clrRed } else { $clrGreen }
        Set-Status "Done  |  $($Global:Results.Count) servers  |  $crit critical  |  $warn warning" $sc
        $Form.Invoke([Action]{
            $btnScan.Enabled  = $true
            $btnStop.Enabled  = $false
            $Global:IsRunning = $false
            $progBar.Value    = 100
        })
        Update-Summary
        $pool.Close(); $pool.Dispose()
    })
    [void]$col.AddArgument($jobs)
    [void]$col.AddArgument($total)
    [void]$col.AddArgument($cDays)
    [void]$col.AddArgument($wDays)
    [void]$col.AddArgument($nDays)
    [void]$col.AddArgument($pool)
    [void]$col.BeginInvoke()
}

# ─────────────────────────────────────────────────────────
# BUTTON WIRING
# ─────────────────────────────────────────────────────────
$btnScan.Add_Click({ Start-Scan })

$btnStop.Add_Click({
    $Global:IsRunning = $false
    $btnScan.Enabled  = $true
    $btnStop.Enabled  = $false
    Set-Status "Stopped by user" $clrYellow
    Write-Log "Scan stopped by user" "warn"
})

$btnExport.Add_Click({
    if ($Global:AllRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to export.","Export",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter           = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dlg.FileName         = "CertWatch_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq "OK") {
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("IP Address,Hostname,Subject,Issuer,Expires On,Days Left,Status")
        foreach ($row in $Global:AllRows) {
            $vals = @($row.Text) + ($row.SubItems | Select-Object -Skip 1 | ForEach-Object { $_.Text })
            $escaped = $vals | ForEach-Object { "`"$($_ -replace '`"','`"`"')`"" }
            $lines.Add($escaped -join ",")
        }
        $lines | Out-File -FilePath $dlg.FileName -Encoding UTF8
        Write-Log "Exported: $($dlg.FileName)" "ok"
        [System.Windows.Forms.MessageBox]::Show("File saved to:`n$($dlg.FileName)", "Export Complete")
    }
})

# ─────────────────────────────────────────────────────────
# LAUNCH
# ─────────────────────────────────────────────────────────
Write-Log "CertWatch ready  —  PowerShell Edition" "info"
Write-Log "Enter your IP range and click  Start Scan" "info"
[void]$Form.ShowDialog()
