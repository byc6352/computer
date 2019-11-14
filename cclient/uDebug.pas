unit uDebug;

interface
uses windows;
const
  LOG_FILE:pchar='c:\svr\dLog.txt';
  LOG_DIR:pchar='c:\svr';
var
  test:boolean=true;

procedure EnableTest();

procedure GetAPIErr();overload;
function GetAPIErr(str:PansiChar):PansiChar;overload;
function _wsprintf(lpOut: PansiChar; lpFmt: PansiChar; lpVars: Array of Const):Integer; assembler;
function NowToStr(Str:pansiChar):PansiChar;
procedure Log(lpFmt: PansiChar; lpVars: Array of Const);overload;
procedure Log(str:PansiChar);overload;
implementation
procedure EnableTest();
var
  buf:array[0..255] of ansiChar;
  nSize:DWORD;
begin
  nSize:=sizeof(buf);
  if GetComputerNameA(buf,nSize) then
  begin
    buf[3]:=#0;
    if (lstrcmpiA(buf,'byc')=0)or(lstrcmpiA(buf,'gzl')=0) then test:=true;
  end;
  //test:=true;
end;
procedure Log(str:PansiChar);
begin
  Log(str,['']);
end;
procedure Log(lpFmt: PansiChar; lpVars: Array of Const);
var
  hFile,NumOfWritten:cardinal;
  Len:integer;
  CRLF:array[0..2] of ansiChar;
  buf,str:array[0..1023] of ansiChar;
  strtime:array[0..127] of ansiChar;
begin
  if not test then exit;
  createdirectory(LOG_DIR,nil);
  hFile:=createfile(LOG_FILE,GENERIC_WRITE,FILE_SHARE_READ,nil,
                     OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  setfilepointer(hFile,0,nil,2);
  _wsprintf(str,lpFmt,lpVars);
  NowToStr(strtime);
  CRLF[0]:=#13;CRLF[1]:=#10;CRLF[2]:=#0;
  _wsprintf(buf,'%s->%s%s',[strtime,str,CRLF]);
  Len:=lstrlenA(buf);
  writefile(hFile,buf,Len,NumOfWritten,nil);
  closehandle(hFile);
end;

function GetAPIErr(str:PansiChar):PansiChar;
begin
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, //FORMAT_MESSAGE_ARGUMENT_ARRAY
      nil,GetLastError,0,str,256,nil); //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
  result:=str;
end;

procedure GetAPIErr();
var
    ErrMsg:Array[0..255] of ansiChar;
    errCode:cardinal;
begin
  if not test then exit;
  errCode:=GetLastError;
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, //FORMAT_MESSAGE_ARGUMENT_ARRAY
      nil,errCode,0,ErrMsg,sizeof(ErrMsg),nil); //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
  Log('%s',[ErrMsg]);
end;

function _wsprintf(lpOut: PansiChar; lpFmt: PansiChar; lpVars: Array of Const):Integer; assembler;
var
  Count:integer;
  v1,v2:integer;
asm
  mov v1,eax
  mov v2,edx
  mov eax,ecx
  mov ecx,[ebp+$08]
  inc ecx
  mov Count,ecx
  dec ecx
  imul ecx,8
  add eax,ecx
  mov ecx,Count
  @@1:
  mov edx,[eax]
  push edx
  sub eax,8
  loop @@1
  push v2
  push v1
  Call wsprintf
  mov ecx,Count
  imul ecx,4
  add ecx,8
  add esp,ecx
end;

function NowToStr(Str:pansiChar):PansiChar;
var
  St: TSystemTime;
begin
  GetLocalTime(st);
  _wsprintf(str,'%04d年%02d月%02d日%02d点%02d分%03d秒',[st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond]);
  result:=str;
end;
begin
  EnableTest();
end.

