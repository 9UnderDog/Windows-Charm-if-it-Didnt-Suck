Imports System, System.Data, System.IO, System.Linq, System.Net
Imports System.Runtime.InteropServices, System.Threading.Tasks
Imports System.Windows.Forms, System.Windows.Interop
Imports Windows_Charm_if_it_Didnt_Suck.BlurTest
Imports Microsoft.VisualBasic.Constants, Microsoft.VisualBasic.Interaction


#Region "Blur Effect"
Namespace BlurTest
    Enum AccentState
        ACCENT_DISABLED = 0
        ACCENT_ENABLE_GRADIENT = 1
        ACCENT_ENABLE_TRANSPARENTGRADIENT = 2
        ACCENT_ENABLE_BLURBEHIND = 3
        ACCENT_INVALID_STATE = 4
    End Enum

    Structure AccentPolicy
        Public AccentState As AccentState
        Public AccentFlags As Integer
        Public GradientColor As Integer
        Public AnimationId As Integer
    End Structure

    Structure WindowCompositionAttributeData
        Public Attribute As WindowCompositionAttribute
        Public Data As IntPtr
        Public SizeOfData As Integer
    End Structure

    Enum WindowCompositionAttribute
        WCA_ACCENT_POLICY = 19
    End Enum
End Namespace
#End Region

Public Class MainWindow
#Region "Universal Variables"
    'Universal Stuff
    'single instance
    Private AppMutex As Threading.Mutex
    'Taskview
    Dim WS_EX_TOOLWINDOW As Integer = &H80
    Dim GWL_EXSTYLE As Integer = -20
    'has initialised - for settings mainly
    Dim Initialised As Boolean = False
    'NotifyIcon
    Private TrayIcon As System.Windows.Forms.NotifyIcon
    'is window already visible
    Public Shared WindowVisible As Boolean = False
    'Sizes
    Dim xLeft
    Dim Sx As Integer = Screen.PrimaryScreen.Bounds.Width
    Dim Sy As Integer = Screen.PrimaryScreen.Bounds.Height
    'Mouse
    Dim MxM As Integer
    Dim Mx1 As Integer
    Dim Mx2 As Integer
    Dim MouseClick As String = ""
    'Form
    Dim DoNotDeactivate As Boolean = False
    Dim WidthSetting As Integer
    'Time
    Dim TIME_mdown As Boolean = False
    'Search
    Dim VSearchList As New ListBox
    Dim searchbar2 As String
    Dim StopSearch As Integer = 0
    'VirusTotal
    Dim VTPath As String
    Dim VTVirtualResults As New RichTextBox
    Dim VTWaitTime As Integer = My.Settings.VT_WaitTime * 1000
    Dim VTIsRunning As Integer = 0
    Dim VTCancel As Integer = 0
    Private mScanner As VirusTotalScanner
    Private mResults As List(Of ScanResult)
    Private mResultIndex As Integer
    Private mMD5 As String
    Private mSHA256 As String
    Private mSHA512 As String
    'Settings - Search
    Dim RebuildTime As Integer = 0
    'numeric textboxes
    Dim MaxResultsInt As Integer
    Dim ysizeint As Integer
    Dim yoffsetint As Integer
    Dim xwideint As Integer
#End Region

#Region "Hide From Taskview // Blur Effect // TrayIcon"
    'Taskview
    <DllImport("user32.dll", EntryPoint:="SetWindowLong")>
    Private Shared Function SetWindowLong(ByVal hWnd As IntPtr, ByVal nIndex As Integer, ByVal dwNewLong As Integer) As Integer
    End Function

    'Blur
    <DllImport("user32.dll")>
    Friend Shared Function SetWindowCompositionAttribute(ByVal hwnd As IntPtr, ByRef data As WindowCompositionAttributeData) As Integer
    End Function
    Sub EnableBlur()
        Dim windowHelper = New WindowInteropHelper(Me)
        Dim accent = New AccentPolicy()
        accent.AccentState = AccentState.ACCENT_ENABLE_BLURBEHIND
        Dim accentStructSize = Marshal.SizeOf(accent)
        Dim accentPtr = Marshal.AllocHGlobal(accentStructSize)
        Marshal.StructureToPtr(accent, accentPtr, False)
        Dim Data = New WindowCompositionAttributeData()
        Data.Attribute = WindowCompositionAttribute.WCA_ACCENT_POLICY
        Data.SizeOfData = accentStructSize
        Data.Data = accentPtr
        SetWindowCompositionAttribute(windowHelper.Handle, Data)
        Marshal.FreeHGlobal(accentPtr)
    End Sub
#End Region

#Region "Window Loaded"
    Private Sub Window_Loaded(sender As Object, e As RoutedEventArgs)
        'Single instance
        AppMutex = New Threading.Mutex(False, "WCDS")
        If AppMutex.WaitOne(0, False) = False Then
            AppMutex.Close()
            AppMutex = Nothing
            MessageBox.Show("Error: Aready Running", "Windows Charm if it Didn't Suck", MessageBoxButtons.OK, MessageBoxIcon.Error)
            Close()
        End If


        'Hide from taskview
        Dim MeI = New WindowInteropHelper(Me)
        Call SetWindowLong(MeI.Handle, GWL_EXSTYLE, WS_EX_TOOLWINDOW)
        'Blur effect
        EnableBlur()

        'Set up size of form
        ChangeWidth()
        Left = Sx
        Top = 0
        WindowState = WindowState.Normal
        If My.Settings.SL_CoverTaskBar = True Then Height = Sy Else Height = My.Computer.Screen.WorkingArea.Height


        'TrayIcon
        TrayIcon = New NotifyIcon()
        TrayIcon.Icon = My.Resources.WC
        AddHandler TrayIcon.MouseClick, AddressOf TrayIcon_Click
        AddHandler TrayIcon.MouseDoubleClick, AddressOf TrayIcon_DoubleClick
        TrayIcon.Visible = True

        'multi-thread stuff needed
        CLib.NewThread(AddressOf OpenWindow)
        CLib.NewThread(AddressOf UpdateTime)
        CLib.NewThread(AddressOf MeasureMouseMovement)

        'Search
        UpdateSearch()
        On Error Resume Next

        'memo text
        M_Text.Text = CLib.AES_Decrypt(My.Settings.MemoText)

        'update public IP
        CLib.NewThread(AddressOf GrabIPs)

        'VT API and things
        VT_APIKey.Text = My.Settings.VT_API
        VT_rb1Upload.IsChecked = True
        VT_rb2Scan.IsChecked = True

        'load settings
        SL_CoverTaskBar.IsChecked = My.Settings.SL_CoverTaskBar
        SE_ResetToMainOnDeactivate.IsChecked = My.Settings.SE_ResetToMainOnDeactivate
        SS_MaxResults.Text = My.Settings.SS_MaxResult
        If My.Settings.OpenMethod = 1 Then
            SE_SlideMouseDown.IsChecked = True
        ElseIf My.Settings.OpenMethod = 2 Then
            SE_DragOpen.IsChecked = True
        End If
        SE_ysize.Text = My.Settings.OPENZONE_ysize
        SE_yoffset.Text = My.Settings.OPENZONE_yoffset
        SE_xwide.Text = My.Settings.OPENZONE_xwide
        SS_ClearSearchOnDeactivation.IsChecked = My.Settings.SS_ClearSearchOnDeactivate
        SE_VTWaitTime.Text = My.Settings.VT_WaitTime

        'hide all grids except main
        GMain.Visibility = Visibility.Visible
        GSearch.Visibility = Visibility.Hidden
        GSettings.Visibility = Visibility.Hidden
        GMemo.Visibility = Visibility.Hidden
        GNetworkTools.Visibility = Visibility.Hidden
        GVirusTotal.Visibility = Visibility.Hidden

        GWidgets.Visibility = Visibility.Hidden
    End Sub

    Private Sub MainDesign_Initialized(sender As Object, e As EventArgs) Handles MainDesign.Initialized
        Initialised = True
    End Sub

    Private Sub UpdateSearch()
        On Error Resume Next
        Dim WholeCatalog As String = FileSystem.ReadAllText("SearchCatalog.txt")
        Dim WholeCatalogArray() As String = WholeCatalog.Split("*")
        Dim WholeCatalogList As List(Of String) = WholeCatalogArray.ToList()
        For i = 0 To WholeCatalogList.Count - 1
            VSearchList.Items.Add(WholeCatalogList.Item(i))
        Next
        Dim FolderCatalog As String = FileSystem.ReadAllText("FoldersCatalog.txt")
        Dim FolderCatalogArray() As String = FolderCatalog.Split("*")
        Dim FolderCatalogList As List(Of String) = FolderCatalogArray.ToList()
        For i = 0 To FolderCatalogList.Count - 1
            If Not FolderCatalogList.Item(i) = "" Then
                SS_IndexedFolders.Items.Add(FolderCatalogList.Item(i))
            End If
        Next
    End Sub


#End Region

#Region "TrayIcon Click"
    Private Sub TrayIcon_Click(sender As Object, e As MouseEventArgs)
        If e.Button.ToString = "Left" Then
            If WindowVisible = False Then
                CLib.SlideIn(Me, WidthSetting)
            End If
        End If
    End Sub

    Private Sub TrayIcon_DoubleClick(sender As Object, e As MouseEventArgs)
        If e.Button.ToString = "Right" Then
            Close()
        End If
    End Sub
#End Region

#Region "Time Updater"
    Private Async Sub UpdateTime()
        Dim Count As Integer = 0 'this is for gc
        Do
            Await Task.Delay(1000)
            Count += 1
            CLib.OnDiffThread(Sub() TIME.Content = DateTime.Now.TimeOfDay.ToString("hh\:mm\:ss"), Me)
            If Count = 600 Then 'every 10 minutes do gc
                GC.Collect() 'keep memory mostly clean
                Count = 0
            End If
        Loop
    End Sub
#End Region

#Region "Open/Close Window"
    Private Async Sub OpenWindow()
        'code for opening the form:
        '1 = slide mouse down right side of screen
        '2 = drag window into view on right side
        'this is here because i was going to add more open methods on the left side. too lazy.

UpdateOpenMethod:
        Dim ysize As Integer = My.Settings.OPENZONE_ysize 'pixels wide
        Dim xwide As Integer = My.Settings.OPENZONE_xwide 'pixels wide
        Dim yoffset As Integer = My.Settings.OPENZONE_yoffset 'pixels down
        Dim MouseMoveValue As Integer = 10 'basically the speed that the mouse has to achieve before it can open/close the form without hitting a boundary that opens/closes it anyway

        Dim xresettime As Integer = 1 'seconds to reset (when sliding down to open)


        If My.Settings.OpenMethod = 1 Then
            Dim Mx As Integer
            Dim my_ As Integer
            ysize = My.Settings.OPENZONE_ysize 'pixels wide
            xwide = My.Settings.OPENZONE_xwide 'pixels wide
            yoffset = My.Settings.OPENZONE_yoffset 'pixels down
            Dim Ftime As DateTime = DateTime.Now
            Dim O1, O2, O3, O4, O5, O6 As Integer
            Do
                Await Task.Delay(1)
                If My.Settings.OpenMethod = 1 Then Else GoTo UpdateOpenMethod
                If Ftime.Second <= DateTime.Now.Second Then
                    O1 = 0 : O2 = 0 : O3 = 0 : O4 = 0 : O5 = 0 : O6 = 0
                End If
                Mx = Control.MousePosition.X
                my_ = Control.MousePosition.Y
                If O1 = 0 AndAlso my_ > yoffset And my_ < ((ysize - yoffset) / 6 + yoffset) AndAlso Mx = (Sx - 1) Then
                    Ftime = DateTime.Now.AddSeconds(xresettime)
                    O1 = 1
                ElseIf O2 = 0 AndAlso my_ > ((ysize - yoffset) / 6 + yoffset) And my_ < ((ysize - yoffset) / 6 * 2 + yoffset) AndAlso Mx = (Sx - 1) Then
                    O2 = 1
                ElseIf O3 = 0 AndAlso my_ > ((ysize - yoffset) / 6 * 2 + yoffset) And my_ < ((ysize - yoffset) / 6 * 3 + yoffset) AndAlso Mx = (Sx - 1) Then
                    O3 = 1
                ElseIf O4 = 0 AndAlso my_ > ((ysize - yoffset) / 6 * 3 + yoffset) And my_ < ((ysize - yoffset) / 6 * 4 + yoffset) AndAlso Mx = (Sx - 1) Then
                    O4 = 1
                ElseIf O5 = 0 AndAlso my_ > ((ysize - yoffset) / 6 * 4 + yoffset) And my_ < ((ysize - yoffset) / 6 * 5 + yoffset) AndAlso Mx = (Sx - 1) Then
                    O5 = 1
                ElseIf O6 = O6 AndAlso my_ > ((ysize - yoffset) / 6 * 5 + yoffset) And my_ < ((ysize - yoffset) / 6 * 6 + yoffset) AndAlso Mx = (Sx - 1) Then
                    O6 = 1
                ElseIf O1 + O2 + O3 + O4 + O5 + O6 = 6 Then
                    CLib.SlideIn(Me, WidthSetting)
                    O1 = 0 : O2 = 0 : O3 = 0 : O4 = 0 : O5 = 0 : O6 = 0
                End If
            Loop
        ElseIf My.Settings.OpenMethod = 2 Then
            Dim Mx As Integer
            Dim my_ As Integer
            Dim Md As Integer
            Dim Mda As Integer = 0
            Dim MnD As Boolean = True
            Do
                Await Task.Delay(1)
                ysize = My.Settings.OPENZONE_ysize 'pixels wide
                xwide = My.Settings.OPENZONE_xwide 'pixels wide
                yoffset = My.Settings.OPENZONE_yoffset 'pixels down
                Mx = Control.MousePosition.X
                my_ = Control.MousePosition.Y
                If My.Settings.OpenMethod = 2 Then Else GoTo UpdateOpenMethod
                If Mx < (Sx - xwide) AndAlso Control.MouseButtons.ToString = "Left" Then
                    MnD = False
                ElseIf Control.MouseButtons.ToString = "None" Then
                    MnD = True
                End If
                If my_ > yoffset And my_ < (ysize + yoffset) AndAlso Mx >= (Sx - xwide) AndAlso Control.MouseButtons.ToString = "Left" AndAlso MnD = True Then
                    Do While Control.MouseButtons.ToString = "Left"
                        Mx = Control.MousePosition.X + 1
                        If Sx - Mx + 1 >= WidthSetting Then
                            Mx = Sx - WidthSetting
                        End If
                        CLib.OnDiffThread(Sub() Left = Mx, Me)
                        Md = 1
                    Loop
                Else 'mouse released
                    If Md = 1 Then
                        CLib.OnDiffThread(Sub() xLeft = Left, Me)
                        If MxM > MouseMoveValue Then
                            CLib.SlideIn(Me, WidthSetting, Sx - xLeft)
                            Md = 0
                        ElseIf MxM < (-1 * MouseMoveValue) Then
                            CLib.SlideOut(Me)
                            Md = 0
                        ElseIf Md = 1 AndAlso Sx - xLeft < WidthSetting And Sx - xLeft > (WidthSetting / 3) Or Sx - xLeft = WidthSetting Then
                            CLib.SlideIn(Me, WidthSetting, Sx - xLeft)
                            Md = 0
                        ElseIf Md = 1 Then
                            CLib.SlideOut(Me)
                            Md = 0
                        End If
                    End If
                End If
            Loop
        End If
    End Sub

    Private Sub Window_Closing(sender As Object, e As System.ComponentModel.CancelEventArgs)
        TrayIcon.Icon.Dispose()
        Process.GetCurrentProcess.Kill()
    End Sub

    Private Async Sub MeasureMouseMovement()
        Do
            '-ve = Mouse going right -> // +ve Mouse going left <-
            '(It is like this because currently the window only opens from the right)
            Mx1 = Control.MousePosition.X
            Await Task.Delay(50)
            Mx2 = Control.MousePosition.X
            MxM = Mx1 - Mx2
        Loop
    End Sub

    Private Sub MainDesign_Deactivated(sender As Object, e As EventArgs) Handles MainDesign.Deactivated
        If StayActive.IsChecked = True Then
            Exit Sub
        ElseIf DoNotDeactivate = False Then
            CLib.SlideOut(Me)
        ElseIf DoNotDeactivate = True Then
            Exit Sub
        End If
        If My.Settings.SS_ClearSearchOnDeactivate = True Then
            S_SearchBar.Text = Nothing
        End If
        If My.Settings.SE_ResetToMainOnDeactivate = True Then
            GMain.Visibility = Visibility.Visible
            GSearch.Visibility = Visibility.Hidden
            GSettings.Visibility = Visibility.Hidden
            GMemo.Visibility = Visibility.Hidden
            GNetworkTools.Visibility = Visibility.Hidden
            GVirusTotal.Visibility = Visibility.Hidden

            GWidgets.Visibility = Visibility.Hidden
        End If
    End Sub
#End Region




#Region "Main Menu Buttons"
    Private Sub btn_search_Click(sender As Object, e As RoutedEventArgs) Handles btn_search.Click
        GMain.Visibility = Visibility.Hidden
        GSearch.Visibility = Visibility.Visible
    End Sub

    Private Sub TIME_MouseLeftButtonUp(sender As Object, e As MouseButtonEventArgs) Handles TIME.MouseLeftButtonUp
        If TIME_mdown = True Then
            GMain.Visibility = Visibility.Visible
            GSearch.Visibility = Visibility.Hidden
            GMemo.Visibility = Visibility.Hidden
            GNetworkTools.Visibility = Visibility.Hidden
            GVirusTotal.Visibility = Visibility.Hidden
            GSettings.Visibility = Visibility.Hidden

            GWidgets.Visibility = Visibility.Hidden
            TIME_mdown = False
        End If
    End Sub

    Private Sub TIME_MouseLeftButtonDown(sender As Object, e As MouseButtonEventArgs) Handles TIME.MouseLeftButtonDown
        TIME_mdown = True
    End Sub


    Private Sub btn_memo_Click(sender As Object, e As RoutedEventArgs) Handles btn_memo.Click
        GMain.Visibility = Visibility.Hidden
        GMemo.Visibility = Visibility.Visible
    End Sub

    Private Sub btn_networktools_Click(sender As Object, e As RoutedEventArgs) Handles btn_networktools.Click
        GMain.Visibility = Visibility.Hidden
        GNetworkTools.Visibility = Visibility.Visible
    End Sub


    Private Sub btn_virustotal_Click(sender As Object, e As RoutedEventArgs) Handles btn_virustotal.Click
        GMain.Visibility = Visibility.Hidden
        GVirusTotal.Visibility = Visibility.Visible
    End Sub

    Private Sub btn_settings_Click(sender As Object, e As RoutedEventArgs) Handles btn_settings.Click
        GMain.Visibility = Visibility.Hidden
        GSettings.Visibility = Visibility.Visible
    End Sub

    Private Sub btn_widgets_Click(sender As Object, e As RoutedEventArgs) Handles btn_widgets.Click
        GWidgets.Visibility = Visibility.Visible
        GMain.Visibility = Visibility.Hidden
    End Sub




    Private Sub W_Web_Browser_Click(sender As Object, e As RoutedEventArgs) Handles W_Web_Browser.Click
        Dim WBLoad As New WBrowser
        WBLoad.Show()
    End Sub


#End Region

#Region "Search"


    Private Sub S_SearchBar_TextChanged(sender As Object, e As TextChangedEventArgs) Handles S_SearchBar.TextChanged
        searchbar2 = S_SearchBar.Text
        CLib.NewThread(AddressOf Searching)
    End Sub

    Private Async Sub Searching()
        If searchbar2 = "" Then
            CLib.OnDiffThread(Sub() S_ListView.Items.Clear(), Me)
            StopSearch = 1
            Exit Sub
        Else
            StopSearch = 0
        End If
        CLib.OnDiffThread(Sub() S_ListView.Items.Clear(), Me)
        Dim count As Integer = VSearchList.Items.Count - 1
        Dim Match As String
        Dim MatchFile
        Dim itemnumber As Integer = 0

        Do Until S_ListView.Items.Count = My.Settings.SS_MaxResult
            If StopSearch = 1 Then
                Exit Do
            End If
            itemnumber += 1
            Try
                Match = VSearchList.Items.Item(itemnumber)
            Catch
                Exit Do
            End Try
            Try
                MatchFile = IO.Path.GetFileName(Match)
                If MatchFile.ToLower.Contains(searchbar2.ToLower) Xor searchbar2 = "" Then
                    Try
                        CLib.OnDiffThread(Sub() S_ListView.Items.Add(S_DataTable(IO.Path.GetFileName(Match), IO.Path.GetFullPath(Match))), Me)
                    Catch
                    End Try
                End If
            Catch
            End Try
        Loop
        If StopSearch = 1 Then
            CLib.OnDiffThread(Sub() S_ListView.Items.Clear(), Me)
        End If
    End Sub

    Private Function S_DataTable(ByVal FileName As String, ByVal FilePath As String) As DataTable
        Dim InputData As DataTable = New DataTable()
        InputData.Columns.Add("File")
        InputData.Columns.Add("Path")
        InputData.Rows.Add(FileName, FilePath)
        Return InputData
    End Function

    Private Sub S_ListView_MouseDoubleClick(sender As Object, e As MouseButtonEventArgs) Handles S_ListView.MouseDoubleClick
        Dim GetText As DataTable = New DataTable()
        If Control.MouseButtons.ToString = "Left" Then
            GetText = S_ListView.SelectedItem
            Process.Start(GetText.Rows(0)(1))
        ElseIf Control.MouseButtons.ToString = "Right" Then
            GetText = S_ListView.SelectedItem
            Clipboard.SetText(GetText.Rows(0)(1))
        End If
    End Sub
#End Region

#Region "Memo"
    Private Sub M_Text_TextChanged(sender As Object, e As TextChangedEventArgs) Handles M_Text.TextChanged
        If Initialised = True Then
            My.Settings.MemoText = CLib.AES_Encrypt(M_Text.Text)
            My.Settings.Save()
        End If
    End Sub
#End Region

#Region "Network Tools"
    Private Sub GrabIPs()
        Dim Hostname As IPHostEntry = Dns.GetHostByName("")
        Dim lIP As IPAddress() = Hostname.AddressList
        CLib.OnDiffThread(Sub() NT_LocalIP.Content = "Local IP Address: " & lIP(0).ToString, Me)

        CLib.OnDiffThread(Sub() NT_PublicIP.Content = "Public IP Address: Refreshing", Me)
        Dim client As New WebClient
        client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR1.0.3705;)")
        Dim ifproxy As IWebProxy = WebRequest.GetSystemWebProxy()
        ifproxy.Credentials = CredentialCache.DefaultNetworkCredentials
        client.Proxy = ifproxy
        Dim webdata As Stream
        Try
            webdata = client.OpenRead("http://checkip.dyndns.org/")
        Catch ex As Exception
            Exit Sub
        End Try
        Dim readweb As StreamReader = New StreamReader(webdata)
        Dim final As String = readweb.ReadToEnd()
        webdata.Close()
        readweb.Close()
        final = final.Replace("<html><head><title>Current IP Check</title></head><body>", "").Replace("</body></html>", "").ToString()
        final = final.Replace("Current IP Address: ", "")
        final = final.Replace(Environment.NewLine, "")
        CLib.OnDiffThread(Sub() NT_PublicIP.Content = "Public IP Address: " & final, Me)
    End Sub

    Private Sub NT_PublicIP_MouseDoubleClick(sender As Object, e As MouseButtonEventArgs) Handles NT_PublicIP.MouseDoubleClick
        If MouseClick = "" Then
        ElseIf MouseClick = "Left" Then
            Clipboard.SetText(NT_PublicIP.Content.ToString.Replace("Public IP Address: ", ""))
        ElseIf MouseClick = "Right" Then
            CLib.NewThread(AddressOf GrabIPs)
        End If
        MouseClick = ""
    End Sub

    Private Sub NT_LocalIP_MouseDoubleClick(sender As Object, e As MouseButtonEventArgs) Handles NT_LocalIP.MouseDoubleClick
        If MouseClick = "" Then
        ElseIf MouseClick = "Left" Then
            Clipboard.SetText(NT_PublicIP.Content.ToString.Replace("Local IP Address: ", ""))
        ElseIf MouseClick = "Right" Then
            CLib.NewThread(AddressOf GrabIPs)
        End If
        MouseClick = ""
    End Sub

    Private Sub NT_PublicIP_MouseLeftButtonDown(sender As Object, e As MouseButtonEventArgs) Handles NT_PublicIP.MouseLeftButtonDown
        MouseClick = "Left"
    End Sub

    Private Sub NT_PublicIP_MouseRightButtonDown(sender As Object, e As MouseButtonEventArgs) Handles NT_PublicIP.MouseRightButtonDown
        MouseClick = "Right"
    End Sub

    Private Sub NT_Local_IP_MouseLeftButtonDown(sender As Object, e As MouseButtonEventArgs) Handles NT_LocalIP.MouseLeftButtonDown
        MouseClick = "Left"
    End Sub

    Private Sub NT_Local_IP_MouseRightButtonDown(sender As Object, e As MouseButtonEventArgs) Handles NT_LocalIP.MouseRightButtonDown
        MouseClick = "Right"
    End Sub

    Private Sub NT_GetIPDNS_Click(sender As Object, e As RoutedEventArgs) Handles NT_DNSGetIP.Click
        Try
            Dim Hostname As IPHostEntry = Dns.GetHostByName(NT_DNSDNS.Text)
            Dim ip As IPAddress() = Hostname.AddressList
            NT_DNSIP.Text = ip(0).ToString
        Catch ex As Exception
            DoNotDeactivate = True
            MessageBox.Show("Error: " & ex.Message, "Network Tools", MessageBoxButtons.OK, MessageBoxIcon.Error)
            DoNotDeactivate = False
        End Try
    End Sub

    Private Sub NT_DNS_KeyDown(sender As Object, e As Input.KeyEventArgs) Handles NT_DNSDNS.KeyDown
        If e.Key.ToString = "Enter" Or e.Key.ToString = "Return" Then
            NT_GetIPDNS_Click(sender, e)
        End If
    End Sub
#End Region

#Region "Virus Total Scanner"



    Private Sub VT_APIKey_TextChanged(sender As Object, e As TextChangedEventArgs) Handles VT_APIKey.TextChanged
        My.Settings.VT_API = VT_APIKey.Text
        My.Settings.Save()
    End Sub

    Private Sub VT_Filebtn_Click(sender As Object, e As RoutedEventArgs) Handles VT_Filebtn.Click
        DoNotDeactivate = True
        Dim VT_FileDialog As New OpenFileDialog
        VT_FileDialog.AddExtension = True
        VT_FileDialog.CheckFileExists = True
        VT_FileDialog.DereferenceLinks = True
        VT_FileDialog.Title = "VirusTotal File Dialog"
        If VT_FileDialog.ShowDialog = Windows.Forms.DialogResult.OK Then
            VT_FilePath.Text = "File: " & VT_FileDialog.FileName
        End If
        DoNotDeactivate = False
    End Sub

    Private Sub VT_APIHelp_Click(sender As Object, e As RoutedEventArgs) Handles VT_APIHelp.Click
        DoNotDeactivate = True
        If vbYes = MsgBox("You Will Need An API Key, Get Yours Free At Http://VirusTotal.com. Open Page In Browser?", vbYesNo, "VirusTotal Scanner") Then
            Process.Start("https://developers.virustotal.com/v2.0/reference")
        End If
        DoNotDeactivate = False
    End Sub

    Private Sub VT_Start_Click(sender As Object, e As RoutedEventArgs) Handles VT_Start.Click
        VTVirtualResults.Clear()
        Dim APIKey As String
        If VT_APIKey.Text = "" Then
            DoNotDeactivate = True
            MessageBox.Show("Error: No API Key", "Virus Total Scanner", MessageBoxButtons.OK, MessageBoxIcon.Error)
            DoNotDeactivate = False
            Exit Sub
        Else
            APIKey = VT_APIKey.Text
        End If

        VTPath = VT_FilePath.Text.ToString.Replace("File: ", "")

        mScanner = New VirusTotalScanner(APIKey)

        mScanner.UseTLS = True
        If VT_rb1Upload.IsChecked = True Then
            If VT_rb2Scan.IsChecked Then
                mResults = mScanner.RescanFile(mSHA256)
                CLib.NewThread(AddressOf Submitted)
                VTIsRunning = 1
            Else
                mSHA256 = FileHasher.GetSHA256(VTPath)
                Dim Report As Report
                Try
                    Report = mScanner.GetFileReport(mSHA256)
                Catch ex As Exception
                    DoNotDeactivate = True
                    MessageBox.Show("Error: " & ex.Message, "Virus Total Scanner", MessageBoxButtons.OK, MessageBoxIcon.Error)
                    DoNotDeactivate = False
                    Exit Sub
                End Try
                VT_ListView.Items.Add(VT_DataTable(IO.Path.GetFileName(VTPath), Report.Positives & "/" & Report.Total, Report.Permalink, VTPath, "--"))
            End If
        ElseIf VT_rb1ScanAll.IsChecked = True Then
            CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning All Processes", Me)
            CLib.NewThread(AddressOf ScanAll)
            VTIsRunning = 1
        End If
    End Sub

    Private Sub ScanAll()
        Dim NumberOfScanned As Integer = 0

        For Each p As Process In Process.GetProcesses()
            If VTCancel = 1 Then
                CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Cancelled", Me)
                VTCancel = 0
                Exit Sub
            End If

            Dim VTPPath As String
            Dim VTPName As String
            Dim VTScanDate As String
            Dim Report As Report

            mScanner.UseTLS = True
            Dim VTLBItems As Integer

            Try
                Try
                    VTPName = p.ProcessName & ".exe"
                Catch
                    VTPName = p.Id
                End Try
                Try
                    VTPPath = p.MainModule.FileName
                    mSHA256 = FileHasher.GetSHA256(VTPPath)
                    CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning All Processes - Uploading", Me)
                    mScanner.SubmitFile(VTPPath)
                    CLib.OnDiffThread(Sub() VT_ListView.Items.Add(VT_DataTable(VTPName, "Uploaded", "--", VTPPath, "--")), Me)
                    NumberOfScanned += 1
                Catch
                    GoTo VTFilenameError
                End Try

                CLib.OnDiffThread(Sub() VTLBItems = VT_ListView.Items.Count, Me)
                CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning All Processes - Waiting To Get Report", Me)
                Threading.Thread.Sleep(VTWaitTime)


                Report = mScanner.GetFileReport(mSHA256)

                If Report.Total = 0 Then
                    'no previous scan
                    CLib.OnDiffThread(Sub() VT_ListView.Items(VTLBItems - 1) = VT_DataTable(VTPName, "No Recent Scan", Report.ScanDate, VTPPath, Report.Permalink), Me)
                ElseIf Report.Positives = 0 Then
                    'completely clean
                    CLib.OnDiffThread(Sub() VT_ListView.Items(VTLBItems - 1) = VT_DataTable(VTPName, "Recent: Clean" & " (" & Report.Total & ")", Report.ScanDate, VTPPath, Report.Permalink), Me)
                ElseIf Report.Positives > 0 Then
                    'has previous scan
                    CLib.OnDiffThread(Sub() VT_ListView.Items(VTLBItems - 1) = VT_DataTable(VTPName, "Recent: " & Report.Positives & "/" & Report.Total, Report.ScanDate, VTPPath, Report.Permalink), Me)
                End If


                VTVirtualResults.Text += ">>" & VTLBItems & "|H|" & mSHA256 & "|F|" & VTPName & "|D|" & Report.ScanDate & "|P|" & VTPath & "|L|" & Report.Permalink & "|END|" & Environment.NewLine
                CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning All Processes - Waiting To Upload", Me)
                Threading.Thread.Sleep(VTWaitTime)
            Catch ex As Exception
                If VTPName = "" Then VTPName = "N/A"
                CLib.OnDiffThread(Sub() VT_ListView.Items(VTLBItems - 1) = VT_DataTable(VTPName, "Failed: " & ex.Message, "--", VTPPath, mScanner.GetPublicFileScanLink(mSHA256)), Me)
                CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning All Processes - Waiting Due To Error", Me)
                Threading.Thread.Sleep(VTWaitTime)
            End Try
VTFilenameError:
        Next

        'view reports
        Dim rLine As String
        Dim rName As String
        Dim rHash256 As String
        Dim rScanDate As String
        Dim rPath As String
        Dim rLink As String
        For EachProcess As Integer = 1 To NumberOfScanned
            If VTCancel = 1 Then
                CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Cancelled", Me)
                VTCancel = 0
                Exit Sub
            End If

            rLine = CLib.FindString(VTVirtualResults.Text, ">>" & EachProcess, Environment.NewLine)
            rName = CLib.FindString(rLine, "|F|", "|D|")
            rHash256 = CLib.FindString(rLine, "|H|", "|F|")
            rScanDate = CLib.FindString(rLine, "|D|", "|P|")
            rPath = CLib.FindString(rLine, "|P|", "|L|")
            rLink = CLib.FindString(rLine, "|L|", "|END|")


            Try
                Dim Report As Report
                Report = mScanner.GetFileReport(rHash256)
                If Report.ScanDate.ToString = rScanDate Then
                    CLib.OnDiffThread(Sub() VT_ListView.Items(EachProcess - 1) = VT_DataTable(rName, "Recent*: " & Report.Positives & "/" & Report.Total, Report.ScanDate, rPath, Report.Permalink), Me)
                Else
                    CLib.OnDiffThread(Sub() VT_ListView.Items(EachProcess - 1) = VT_DataTable(rName, "Rescanned: " & Report.Positives & "/" & Report.Total, Report.ScanDate, rPath, Report.Permalink), Me)
                End If


                Threading.Thread.Sleep(VTWaitTime)
            Catch ex As Exception
                CLib.OnDiffThread(Sub() VT_Status.Content = "Error on viewing report: (" & rName & ") " & ex.Message, Me)
                Threading.Thread.Sleep(VTWaitTime)
            End Try
        Next
        CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanned All Processes", Me)
        VTIsRunning = 0
    End Sub


    Private Sub Submitted()
        CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Scanning File", Me)
        mMD5 = FileHasher.GetMD5(VTPath)
        mSHA256 = FileHasher.GetSHA256(VTPath)
        mSHA512 = FileHasher.GetSHA512(VTPath)
        ' Try
        'Dim ScanTime
        'Dim Report As Report
        'Report = mScanner.GetFileReport(mSHA256)
        'ScanTime = Report.ScanDate.ToString
        Dim Report As Report
        Report = mScanner.GetFileReport(mSHA256)

        Dim uFile As String = IO.Path.GetFileName(VTPath)
        Dim uDate As String = Report.ScanDate.ToString
        Dim uResult As String = "Waiting"
        Dim uLink As String = mScanner.GetPublicFileScanLink(mSHA256)
        Dim VTLBItems As Integer

        CLib.OnDiffThread(Sub() VT_ListView.Items.Add(VT_DataTable(uFile, uResult, uDate, VTPath, uLink)), Me)
        CLib.OnDiffThread(Sub() VTLBItems = VT_ListView.Items.Count, Me)
        VTVirtualResults.Text += ">>" & VTLBItems & "|F|" & uFile & "|D|" & uDate & "|P|" & VTPath & "|L|" & uLink & "|END|" & Environment.NewLine


        Dim ScanTime1 = Report.ScanDate.ToString
        Try
            Threading.Thread.Sleep(VTWaitTime)
            Getresult(VTLBItems, 1)
        Catch ex As Exception
        End Try
        CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Waiting For Scanner To Complete", Me)
RepeatCheck:

        If VTCancel = 1 Then
            CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Cancelled", Me)
            VTCancel = 0
            Exit Sub
        End If
        Threading.Thread.Sleep(VTWaitTime)
        Report = mScanner.GetFileReport(mSHA256)
        If ScanTime1 = Report.ScanDate.ToString Then
            GoTo RepeatCheck
        Else
            Getresult(VTLBItems, 2)
        End If
    End Sub

    Private Sub Getresult(ByVal i As Integer, ByVal type As Integer)
        '1 = old
        '2 = new
        Dim Report As Report
        Report = mScanner.GetFileReport(mSHA256)

        Dim uFile As String = IO.Path.GetFileName(VTPath)
        Dim uLink As String = mScanner.GetPublicFileScanLink(mSHA256)

        Dim rLine As String = CLib.FindString(VTVirtualResults.Text, ">>" & i, Environment.NewLine)
        Dim rFile As String = CLib.FindString(rLine, "|F|", "|D|")
        Dim rDate As String = Report.ScanDate
        Dim rPath As String = CLib.FindString(rLine, "|P|", "|L|")
        Dim rLink As String = CLib.FindString(rLine, "|L|", "|END|")
        Dim typestring As String
        If type = 1 Then typestring = "Recent: " Else typestring = "Rescanned: "
        CLib.OnDiffThread(Sub() VT_ListView.Items(i - 1) = VT_DataTable(uFile, typestring & Report.Positives & "/" & Report.Total, rDate, VTPath, uLink), Me)
        CLib.OnDiffThread(Sub() VT_Status.Content = "Status: Finished", Me)
        VTIsRunning = 0
    End Sub

    Private Function VT_DataTable(ByVal N As String, ByVal R As String, ByVal D As String, ByVal P As String, ByVal L As String) As DataTable
        Dim InputData As DataTable = New DataTable()
        InputData.Columns.Add("Name")
        InputData.Columns.Add("Result")
        InputData.Columns.Add("Date")
        InputData.Columns.Add("Path")
        InputData.Columns.Add("Link")
        InputData.Rows.Add(N, R, D, P, L)
        Return InputData
    End Function

    Private Sub VT_Stop_Click(sender As Object, e As RoutedEventArgs) Handles VT_Stop.Click
        If VTIsRunning = 1 Then
            VTCancel = 1
            VT_Status.Content = "Status: Cancelling..."
            VTIsRunning = 0
        End If
    End Sub

    Private Sub VT_rb1ScanAll_Checked(sender As Object, e As RoutedEventArgs) Handles VT_rb1ScanAll.Checked
        VT_G2.Visibility = Visibility.Hidden
    End Sub

    Private Sub VT_rb1Upload_Checked(sender As Object, e As RoutedEventArgs) Handles VT_rb1Upload.Checked
        VT_G2.Visibility = Visibility.Visible
    End Sub

#End Region

#Region "Settings"
    Private Sub SS_IndexFolder_Click(sender As Object, e As RoutedEventArgs) Handles SS_IndexFolder.Click
        DoNotDeactivate = True
        Dim Folderdlg As New FolderBrowserDialog
        If Folderdlg.ShowDialog() = Forms.DialogResult.OK Then
            SS_IndexedFolders.Items.Add(Folderdlg.SelectedPath)
            If SS_IndexedFolders.Items.Count = 0 Then
            Else
                Dim AllFolders As String = "*"
                Dim x As Integer = 0
                For Each item In SS_IndexedFolders.Items
                    AllFolders &= SS_IndexedFolders.Items(x) & "*"
                    x += 1
                Next
                My.Computer.FileSystem.WriteAllText("FoldersCatalog.txt", AllFolders, False)
            End If
        End If
        DoNotDeactivate = False
    End Sub

    Private Sub SS_RebuildCatalog_Click(sender As Object, e As RoutedEventArgs) Handles SS_RebuildCatalog.Click
        CLib.NewThread(AddressOf Rebuild)
        CLib.NewThread(AddressOf RebuildTimer)
    End Sub

    Private Async Sub RebuildTimer()
        Do
            Await Task.Delay(5000)
            RebuildTime = 1
        Loop
    End Sub

    Private Sub Rebuild()
        Dim Count As Integer = 0
        Dim BulkWrite As String
        My.Computer.FileSystem.WriteAllText("SearchCatalog.txt", "*", False)
        Try
            For i = 0 To SS_IndexedFolders.Items.Count - 1
                CLib.OnDiffThread(Sub() SS_Status.Content = "Status: Computing Files (Found: " & Count & " Already)", Me)



                For Each foundFile As String In My.Computer.FileSystem.GetFiles(SS_IndexedFolders.Items.Item(i), Microsoft.VisualBasic.FileIO.SearchOption.SearchAllSubDirectories)
                    If RebuildTime = 1 Then
                        RebuildTime = 0
                        My.Computer.FileSystem.WriteAllText("SearchCatalog.txt", BulkWrite & "*", True)
                        BulkWrite = Nothing
                    Else
                        BulkWrite &= foundFile & "*"
                    End If
                    Count += 1
                    CLib.OnDiffThread(Sub() SS_Status.Content = "Status: Found " & Count & " Files", Me)
                Next

            Next
            CLib.OnDiffThread(Sub() SS_Status.Content = "Status: Finished With " & Count & " Files", Me)
            UpdateSearch()
        Catch ex As Exception
            CLib.OnDiffThread(Sub() SS_Status.Content = "Error: " & ex.Message, Me)
        End Try
    End Sub

    Private Sub TGeneral_MouseUp(sender As Object, e As MouseButtonEventArgs) Handles TGeneral.MouseUp
        If TGeneral.IsSelected = True Then
            TGeneral.Foreground = Brushes.Black
            TLayout.Foreground = Brushes.White
            TSearch.Foreground = Brushes.White
            TExtras.Foreground = Brushes.White
            TCredits.Foreground = Brushes.White
        End If
    End Sub

    Private Sub TLayout_MouseUp(sender As Object, e As MouseButtonEventArgs) Handles TLayout.MouseUp
        If TLayout.IsSelected = True Then
            TLayout.Foreground = Brushes.Black
            TGeneral.Foreground = Brushes.White
            TSearch.Foreground = Brushes.White
            TExtras.Foreground = Brushes.White
            TCredits.Foreground = Brushes.White
        End If
    End Sub

    Private Sub TSearch_MouseUp(sender As Object, e As MouseButtonEventArgs) Handles TSearch.MouseUp
        If TSearch.IsSelected = True Then
            TSearch.Foreground = Brushes.Black
            TGeneral.Foreground = Brushes.White
            TLayout.Foreground = Brushes.White
            TExtras.Foreground = Brushes.White
            TCredits.Foreground = Brushes.White
        End If
    End Sub

    Private Sub TExtras_MouseUp(sender As Object, e As MouseButtonEventArgs) Handles TExtras.MouseUp
        If TExtras.IsSelected = True Then
            TExtras.Foreground = Brushes.Black
            TGeneral.Foreground = Brushes.White
            TLayout.Foreground = Brushes.White
            TSearch.Foreground = Brushes.White
            TCredits.Foreground = Brushes.White
        End If
    End Sub

    Private Sub TCredits_MouseUp(sender As Object, e As MouseButtonEventArgs) Handles TCredits.MouseUp
        If TCredits.IsSelected = True Then
            TCredits.Foreground = Brushes.Black
            TGeneral.Foreground = Brushes.White
            TLayout.Foreground = Brushes.White
            TSearch.Foreground = Brushes.White
            TExtras.Foreground = Brushes.White
        End If
    End Sub

    Private Sub SL_covertaskbar_Click(sender As Object, e As RoutedEventArgs) Handles SL_CoverTaskBar.Click
        My.Settings.SL_CoverTaskBar = SL_CoverTaskBar.IsChecked
        My.Settings.Save()
        If SL_CoverTaskBar.IsChecked = True Then Height = Sy Else Height = My.Computer.Screen.WorkingArea.Height
    End Sub

    Private Sub SC_Image_Coder_MouseDown(sender As Object, e As MouseButtonEventArgs) Handles SC_Image_Coder.MouseDown
        Process.Start("https://hackforums.net/member.php?action=profile&uid=3339627")
    End Sub

    Private Sub SC_Image_VTCode_MouseDown(sender As Object, e As MouseButtonEventArgs) Handles SC_Image_VTCode.MouseDown
        Process.Start("https://github.com/omegatechware/VirusTotal.VB.NET")
    End Sub

    Private Sub SC_Image_name_MouseDown(sender As Object, e As MouseButtonEventArgs) Handles SC_Image_Name.MouseDown
        Process.Start("https://hackforums.net/member.php?action=profile&uid=1828119")
    End Sub

    Private Sub SG_Small_Checked(sender As Object, e As RoutedEventArgs) Handles SG_Small.Checked
        My.Settings.SG_Size = 1
        My.Settings.Save()
        ChangeWidth()
    End Sub

    Private Sub SG_Medium_Checked(sender As Object, e As RoutedEventArgs) Handles SG_Medium.Checked
        My.Settings.SG_Size = 2
        My.Settings.Save()
        ChangeWidth()
    End Sub

    Private Sub SG_Large_Checked(sender As Object, e As RoutedEventArgs) Handles SG_Large.Checked
        My.Settings.SG_Size = 3
        My.Settings.Save()
        ChangeWidth()
    End Sub

    Private Sub SG_XLarge_Checked(sender As Object, e As RoutedEventArgs) Handles SG_XLarge.Checked
        My.Settings.SG_Size = 4
        My.Settings.Save()
        ChangeWidth()
    End Sub

    Private Sub ChangeWidth()
        'when adding more buttons to the main menu: you need to work out where it will be using this in each different window size
        'the same goes for witdget buttons

        If My.Settings.SG_Size = 1 Then
            Width = 350
            Left = Sx - 350
            WidthSetting = 350
            btn_networktools.Margin = New Thickness(10, 115, 0, 0)
            btn_widgets.Margin = New Thickness(115, 115, 0, 0)
            btn_settings.Margin = New Thickness(220, 115, 0, 0)
            SG_Small.IsChecked = True
        ElseIf My.Settings.SG_Size = 2 Then
            Width = 457
            Left = Sx - 457
            WidthSetting = 457
            btn_networktools.Margin = New Thickness(325, 10, 0, 0)
            btn_widgets.Margin = New Thickness(10, 115, 0, 0)
            btn_settings.Margin = New Thickness(115, 115, 0, 0)
            SG_Medium.IsChecked = True
        ElseIf My.Settings.SG_Size = 3 Then
            Width = 564
            Left = Sx - 564
            WidthSetting = 564
            btn_networktools.Margin = New Thickness(325, 10, 0, 0)
            btn_widgets.Margin = New Thickness(430, 10, 0, 0)
            btn_settings.Margin = New Thickness(10, 115, 0, 0)
            SG_Large.IsChecked = True
        ElseIf My.Settings.SG_Size = 4 Then
            Width = 671
            Left = Sx - 671
            WidthSetting = 671
            btn_networktools.Margin = New Thickness(325, 10, 0, 0)
            btn_widgets.Margin = New Thickness(430, 10, 0, 0)
            btn_settings.Margin = New Thickness(535, 10, 0, 0)
            SG_XLarge.IsChecked = True
        End If
    End Sub

    Private Sub SS_MaxResults_TextChanged(sender As Object, e As TextChangedEventArgs) Handles SS_MaxResults.TextChanged
        If Initialised = True Then
            Try
                MaxResultsInt = SS_MaxResults.Text.Replace(" ", "")
                My.Settings.SS_MaxResult = MaxResultsInt
                My.Settings.Save()
            Catch
                SS_MaxResults.Text = MaxResultsInt
            End Try
        End If
    End Sub

    Private Sub SS_ClearSearchOnDeactivation_Click(sender As Object, e As RoutedEventArgs) Handles SS_ClearSearchOnDeactivation.Click
        If Initialised = True Then
            My.Settings.SS_ClearSearchOnDeactivate = SS_ClearSearchOnDeactivation.IsChecked
            My.Settings.Save()
        End If
    End Sub

    Private Sub SE_ResetToMainOnDeactivate_Click(sender As Object, e As RoutedEventArgs) Handles SE_ResetToMainOnDeactivate.Click
        If Initialised = True Then
            My.Settings.SE_ResetToMainOnDeactivate = SE_ResetToMainOnDeactivate.IsChecked
            My.Settings.Save()
        End If
    End Sub

    Private Sub SE_ysize_TextChanged(sender As Object, e As TextChangedEventArgs) Handles SE_ysize.TextChanged
        If Initialised = True Then
            Try
                ysizeint = SE_ysize.Text.Replace(" ", "")
                My.Settings.OPENZONE_ysize = ysizeint
                My.Settings.Save()
            Catch
                SE_ysize.Text = ysizeint
            End Try
        End If
    End Sub

    Private Sub SE_yoffset_TextChanged(sender As Object, e As TextChangedEventArgs) Handles SE_yoffset.TextChanged
        If Initialised = True Then
            Try
                yoffsetint = SE_yoffset.Text.Replace(" ", "")
                My.Settings.OPENZONE_yoffset = yoffsetint
                My.Settings.Save()
            Catch
                SE_yoffset.Text = ysizeint
            End Try
        End If
    End Sub

    Private Sub SE_xwide_TextChanged(sender As Object, e As TextChangedEventArgs) Handles SE_xwide.TextChanged
        If Initialised = True Then
            Try
                xwideint = SE_xwide.Text.Replace(" ", "")
                My.Settings.OPENZONE_xwide = xwideint
                My.Settings.Save()
            Catch
                SE_xwide.Text = xwideint
            End Try
        End If
    End Sub

    Private Sub SE_DragOpen_Click(sender As Object, e As RoutedEventArgs) Handles SE_DragOpen.Click
        My.Settings.OpenMethod = 2
        My.Settings.Save()
    End Sub

    Private Sub SE_SlideMouseDown_Click(sender As Object, e As RoutedEventArgs) Handles SE_SlideMouseDown.Click
        My.Settings.OpenMethod = 1
        My.Settings.Save()
    End Sub

    Private Sub SE_VTWaitTime_TextChanged(sender As Object, e As TextChangedEventArgs) Handles SE_VTWaitTime.TextChanged
        If Initialised = True Then
            Try
                VTWaitTime = SE_VTWaitTime.Text.Replace(" ", "")
                My.Settings.VT_WaitTime = VTWaitTime
                My.Settings.Save()
            Catch
                SE_VTWaitTime.Text = VTWaitTime
            End Try
        End If
    End Sub
#End Region

End Class