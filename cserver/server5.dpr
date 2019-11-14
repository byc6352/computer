program server5;

uses
  Forms,
  main in 'main.pas' {FMain},
  uTransDataSrv in 'uTransDataSrv.pas',
  func in 'func.pas',
  Zip in 'Zip.pas',
  data in 'data.pas' {DM: TDataModule},
  uRegEdit in 'uRegEdit.pas' {FRegEdit},
  uHelper in 'uHelper.pas' {FHelper},
  uStr in 'uStr.pas',
  uSocket in 'uSocket.pas',
  ufVideo in 'ufVideo.pas' {fVideo},
  udlgCMD in 'udlgCMD.pas' {fdlgCMD},
  ufScr in 'ufScr.pas' {fScr};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFMain, FMain);
  Application.CreateForm(TDM, DM);
  Application.CreateForm(TFRegEdit, FRegEdit);
  Application.CreateForm(TFHelper, FHelper);
  Application.CreateForm(TfVideo, fVideo);
  Application.CreateForm(TfdlgCMD, fdlgCMD);
  Application.CreateForm(TfScr, fScr);
  Application.Run;
end.
