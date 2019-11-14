object DM: TDM
  OldCreateOrder = False
  Height = 150
  Width = 215
  object ss: TServerSocket
    Active = True
    Port = 7621
    ServerType = stNonBlocking
    OnClientConnect = ssClientConnect
    OnClientDisconnect = ssClientDisconnect
    OnClientRead = ssClientRead
    OnClientError = ssClientError
    Left = 152
    Top = 16
  end
  object Timer1: TTimer
    OnTimer = Timer1Timer
    Left = 16
    Top = 16
  end
end
