unit configSvr;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ComCtrls, StdCtrls, ExtCtrls, Buttons;
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
  TFConfigSvr = class(TForm)
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    CheckBox1: TCheckBox;
    GroupBox2: TGroupBox;
    RadioButton4: TRadioButton;
    RadioButton3: TRadioButton;
    Edit2: TEdit;
    Label2: TLabel;
    TabSheet5: TTabSheet;
    CheckBox2: TCheckBox;
    Edit1: TEdit;
    Label1: TLabel;
    Label4: TLabel;
    Edit4: TEdit;
    Edit3: TEdit;
    Label3: TLabel;
    CheckBox3: TCheckBox;
    CheckBox4: TCheckBox;
    CheckBox5: TCheckBox;
    CheckBox6: TCheckBox;
    CheckBox7: TCheckBox;
    CheckBox8: TCheckBox;
    CheckBox9: TCheckBox;
    CheckBox10: TCheckBox;
    StatusBar1: TStatusBar;
    Label5: TLabel;
    Label6: TLabel;
    Edit5: TEdit;
    Edit6: TEdit;
    RadioButton1: TRadioButton;
    RadioButton2: TRadioButton;
    RadioButton5: TRadioButton;
    btnOK: TBitBtn;
    btnCancel: TBitBtn;
  private
    { Private declarations }
  public
    { Public declarations }
    SvrConfig:stConfigSvrInfo;
  end;

var
  FConfigSvr: TFConfigSvr;

implementation

{$R *.dfm}

end.
