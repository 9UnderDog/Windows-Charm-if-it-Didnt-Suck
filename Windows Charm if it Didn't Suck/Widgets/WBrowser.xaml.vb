Imports System
Imports System.Reflection

Public Class WBrowser
    Private Sub a()
    End Sub

    Private Sub WB_UrlBox_KeyDown(sender As Object, e As KeyEventArgs) Handles WB_UrlBox.KeyDown
        If e.Key.ToString = "Enter" Or e.Key.ToString = "Return" Then
            Nav()
        End If
    End Sub

    Public Sub HideScriptErrors(ByVal wb As WebBrowser, ByVal Hide As Boolean)
        Dim fiComWebBrowser As FieldInfo = GetType(WebBrowser).GetField("_axIWebBrowser2", BindingFlags.Instance Or BindingFlags.NonPublic)
        If fiComWebBrowser Is Nothing Then Return
        Dim objComWebBrowser As Object = fiComWebBrowser.GetValue(wb)
        If objComWebBrowser Is Nothing Then Return
        objComWebBrowser.[GetType]().InvokeMember("Silent", BindingFlags.SetProperty, Nothing, objComWebBrowser, New Object() {Hide})
    End Sub

    Private Sub Nav()
        Try
            WB_Status.Content = "Status: Loading.."
            WB_Browser.Navigate(WB_UrlBox.Text)
        Catch ex As Exception
            Try
                WB_Browser.Navigate("https://" & WB_UrlBox.Text)
            Catch
                WB_Status.Content = "Status: Error - " & ex.Message
            End Try
        End Try
    End Sub

    Private Sub WB_Refresh_Click(sender As Object, e As RoutedEventArgs) Handles WB_Refresh.Click
        WB_Browser.Refresh()
    End Sub

    Private Sub WB_Forward_Click(sender As Object, e As RoutedEventArgs) Handles WB_Forward.Click
        WB_Browser.GoForward()
    End Sub

    Private Sub WB_Back_Click(sender As Object, e As RoutedEventArgs) Handles WB_Back.Click
        WB_Browser.GoBack()
    End Sub

    Private Sub WB_Browser_LoadCompleted(sender As Object, e As NavigationEventArgs) Handles WB_Browser.LoadCompleted
        WB_Status.Content = "Status: Loaded"
    End Sub

    Private Sub WB_Browser_Navigated(sender As Object, e As NavigationEventArgs) Handles WB_Browser.Navigated
        HideScriptErrors(WB_Browser, 1)
    End Sub

    Private Sub WB_TopMost_Click(sender As Object, e As RoutedEventArgs) Handles WB_TopMost.Click
        Topmost = WB_TopMost.IsChecked
    End Sub
End Class
