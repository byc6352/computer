unit uConfigSvrGuid;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Buttons, ExtCtrls, ComCtrls,shellapi,shlobj, CheckLst;
type
  TOS=(Owin98,Owin2k);
  TFileType=(FEXE,FDLL);
  pSvcInfo=^stSvcInfo;
  stSvcInfo=record
    bShare:bool;
    name:array[0..255] of char;
    show:array[0..255] of char;
    note:array[0..255] of char;
  end;
  pConfigSvrInfo=^stConfigSvrInfo;
  stConfigSvrInfo=record
    OS:TOS;
    fileType:TFileType;
    bSvc:bool;
    svcInfo:stSvcInfo;
    
  end;
type
  TFConfigSvrGuid = class(TForm)
    btnCancel: TBitBtn;
    btnOK: TBitBtn;
    StatusBar1: TStatusBar;
    PFile: TPanel;
    edtFileName: TEdit;
    ScrollBox1: TScrollBox;
    rgpPath: TRadioGroup;
    PSvc: TPanel;
    CheckBox2: TCheckBox;
    Edit1: TEdit;
    Edit4: TEdit;
    Edit3: TEdit;
    Label4: TLabel;
    Label1: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    RadioButton1: TRadioButton;
    RadioButton2: TRadioButton;
    PSetup: TPanel;
    cbxSetup: TCheckListBox;
    PInject: TPanel;
    cbxInject: TCheckListBox;
    POnLine: TPanel;
    Edit5: TEdit;
    Label7: TLabel;
    Edit6: TEdit;
    Label8: TLabel;
    rbnNoShell: TRadioButton;
    RadioButton3: TRadioButton;
    RadioButton4: TRadioButton;
    Label2: TLabel;
    cbxFileType: TComboBox;
    procedure FormShow(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
    SvrConfig:stConfigSvrInfo;
  end;

var
  FConfigSvrGuid: TFConfigSvrGuid;

implementation

{$R *.dfm}

procedure TFConfigSvrGuid.FormShow(Sender: TObject);
begin
  PFile.BringToFront;
end;

end.
