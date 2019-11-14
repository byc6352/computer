object fVideo: TfVideo
  Left = 211
  Top = 145
  Width = 113
  Height = 132
  AutoSize = True
  Caption = #35270#39057#30417#35270
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  FormStyle = fsStayOnTop
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object imgVideo: TImage
    Left = 0
    Top = 0
    Width = 105
    Height = 105
    AutoSize = True
  end
  object IdUDPServer1: TIdUDPServer
    Bindings = <>
    DefaultPort = 7618
    OnUDPRead = IdUDPServer1UDPRead
    Left = 96
    Top = 80
  end
end
