unit ufScr;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ExtCtrls;

type
  TfScr = class(TForm)
    imgScreen: TImage;
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  fScr: TfScr;

implementation
uses main;
{$R *.dfm}

procedure TfScr.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  FMain.menuFloatPic.Checked:=false;
end;

end.
