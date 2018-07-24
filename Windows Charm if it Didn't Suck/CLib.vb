Imports System, System.Security.Cryptography, System.Text, System.Threading, System.Windows.Forms, System.Windows.Threading

Public Class CLib

    'Code Library (CLib)
    '- Any code that can be used throughout the whole project to make things easier is placed here

    Public Shared SlideIsInProgress As Boolean = False 'to avoid sliding in and out do not overlap


    Public Shared Sub NewThread(ByRef T As ThreadStart) 'starts a sub in a new thread
        Dim NT As Thread
        NT = New Thread(T)
        NT.SetApartmentState(ApartmentState.STA)
        NT.Start()
    End Sub

    Public Shared Sub OnDiffThread(ByRef ActionToDo As Action, ByVal _Window As Window) 'this saves so much time and space in code when things are on all different threads
        Dim Act As Action = ActionToDo
        Dim Limbda = Sub() Act()
        _Window.Dispatcher.Invoke(DispatcherPriority.Normal, New Action(Sub() Limbda()))
    End Sub

    Public Shared Sub SlideIn(ByVal _Window As Window, _Size As Int16, Optional _Start As Integer = 0) 'just slides in the window
        If SlideIsInProgress = True Then
            Exit Sub
        End If
        MainWindow.WindowVisible = True
        SlideIsInProgress = True
        Dim Sx As Integer = Screen.PrimaryScreen.Bounds.Width
        For i = _Start To _Size
            OnDiffThread(Sub() _Window.Left = Sx - i, _Window)
            i += 1
        Next
        OnDiffThread(Sub() _Window.Activate(), _Window)
        OnDiffThread(Sub() _Window.Focus(), _Window)
        SlideIsInProgress = False
    End Sub

    Public Shared Sub SlideOut(ByVal _Window As Window, Optional ByVal _Wait As Integer = 0)
        If SlideIsInProgress = True Then
            Exit Sub
        End If
        SlideIsInProgress = True
        Dim Sx As Integer = Screen.PrimaryScreen.Bounds.Width
        Dim _Start
        OnDiffThread(Sub() _Start = _Window.Left, _Window)
        For i = _Start To Sx
            OnDiffThread(Sub() _Window.Left = i, _Window)
            i += 1
        Next
        MainWindow.WindowVisible = False
        SlideIsInProgress = False
    End Sub


    Public Shared Function AES_Encrypt(ByVal input As String, ByVal Optional pass As String = "ijw/8VQ9D4UysRWm7iEZnK2oKL+ruqVIWl5v4XAo+RLVdA4Y3jhVKImRGZEGIgrAsaqGPSVp79PtdxOlrpdFiA==") As String 'encryption for memo, idk why - it was too simple to leave as plain text
        Dim AES As New RijndaelManaged
        Dim Hash_AES As New MD5CryptoServiceProvider
        Dim encrypted As String = ""
        Try
            Dim hash(31) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESEncrypter As ICryptoTransform = AES.CreateEncryptor
            Dim Buffer As Byte() = Encoding.ASCII.GetBytes(input)
            encrypted = Convert.ToBase64String(DESEncrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return encrypted
        Catch ex As Exception
        End Try
    End Function

    Public Shared Function AES_Decrypt(ByVal input As String, ByVal Optional pass As String = "ijw/8VQ9D4UysRWm7iEZnK2oKL+ruqVIWl5v4XAo+RLVdA4Y3jhVKImRGZEGIgrAsaqGPSVp79PtdxOlrpdFiA==") As String
        Dim AES As New RijndaelManaged
        Dim Hash_AES As New MD5CryptoServiceProvider
        Dim decrypted As String = ""
        Try
            Dim hash(31) As Byte
            Dim temp As Byte() = Hash_AES.ComputeHash(Encoding.ASCII.GetBytes(pass))
            Array.Copy(temp, 0, hash, 0, 16)
            Array.Copy(temp, 0, hash, 15, 16)
            AES.Key = hash
            AES.Mode = CipherMode.ECB
            Dim DESDecrypter As ICryptoTransform = AES.CreateDecryptor
            Dim Buffer As Byte() = Convert.FromBase64String(input)
            decrypted = Encoding.ASCII.GetString(DESDecrypter.TransformFinalBlock(Buffer, 0, Buffer.Length))
            Return decrypted
        Catch ex As Exception
        End Try
    End Function

    Public Shared Function FindString(ByVal Input As String, First As String, Last As String) 'if you want to find something using the fist and last characters (but also removes the first and last characters from the final result (that you used to search for the string) - easy to change though)
        Dim Index As Integer = Input.IndexOf(First)
        Dim Output As String = Input.Substring(Index + First.Length, Input.IndexOf(Last, Index + 1) - Index - Last.Length + (Last.Length - First.Length))
        Return Output
    End Function
End Class
